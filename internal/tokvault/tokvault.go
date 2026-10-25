// Package tokvault is the tokenization vault (ticket 24, spec FR-DLP-3, §5.3): format-preserving tokens (NIST
// SP 800-38G FF1, radix 10) for numeric identifiers, so a model can work with a NIK, account or card number without
// seeing it, and the gateway can put the real value back for a caller entitled to it.
//
// No plaintext is stored. A token decrypts with the tenant's FF1 key; the vault keeps only an HMAC of each issued
// token with its expiry, so a token is honoured only while it is registered (TTL), and every detokenisation is
// written to the audit log before the value leaves. The FF1 key is wrapped under the vault KEK.
package tokvault

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/capitalone/fpe/ff1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/seal"
	"wantimpres26/internal/tenantdb"
)

//go:embed schema.sql
var schemaSQL string

// Classes are the tokenizable detector classes and how many leading digits stay as they are (a phone keeps "08", or
// "628" in the +62 form, so it still reads as an Indonesian mobile number). Everything else is redacted instead.
var Classes = map[string]int{"PII_ID.NIK": 0, "PII_ID.KK": 0, "PII_ID.NPWP": 0, "PII_ID.PHONE": 2, "FIN.ACCOUNT": 0, "PCI.PAN": 0}

// minDigits: FF1 needs a domain of at least a million values (radix^len ≥ 10^6).
const minDigits = 6

var (
	ErrClass = errors.New("class is not tokenizable")
	ErrShort = errors.New("value has too few digits to tokenize")
)

type Vault struct {
	db     *pgxpool.Pool
	audit  *audit.Store
	tenant string
	key    []byte // FF1 (AES-256) key
	macKey []byte
	Now    func() time.Time
}

// Item is one value (to tokenize) or token (to detokenize) of a class.
type Item struct {
	Class string `json:"class"`
	Value string `json:"value"`
}

// Open applies the schema and loads the tenant's FF1 key, creating it on first use. kek is 32 bytes.
// ponytail: KEK from a file mounted from Vault/HSM, as for incident evidence; a KMS unwrap call when §10.1's KMS lands.
func Open(ctx context.Context, db *pgxpool.Pool, auditLog *audit.Store, tenant string, kek []byte) (*Vault, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("vault KEK must be 32 bytes, got %d", len(kek))
	}
	if _, err := db.Exec(ctx, schemaSQL); err != nil {
		return nil, fmt.Errorf("apply tokvault schema: %w", err)
	}
	if err := tenantdb.Isolate(ctx, db, "tokvault.keys", "tokvault.tokens"); err != nil {
		return nil, err
	}
	aad := []byte("tokvault:" + tenant)
	fresh := make([]byte, 32)
	if _, err := rand.Read(fresh); err != nil {
		return nil, err
	}
	w, err := seal.Seal(kek, fresh, aad)
	if err != nil {
		return nil, err
	}
	// Replicas starting together: the first insert wins, everyone reads the same row.
	if _, err := db.Exec(ctx, "INSERT INTO tokvault.keys (tenant_id, wrapped) VALUES ($1, $2) ON CONFLICT DO NOTHING", tenant, w); err != nil {
		return nil, err
	}
	if err := db.QueryRow(ctx, "SELECT wrapped FROM tokvault.keys WHERE tenant_id = $1", tenant).Scan(&w); err != nil {
		return nil, err
	}
	key, err := seal.Open(kek, w, aad)
	if err != nil {
		return nil, fmt.Errorf("unwrap tenant FF1 key (wrong KEK?): %w", err)
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("token-mac"))
	return &Vault{db: db, audit: auditLog, tenant: tenant, key: key, macKey: m.Sum(nil), Now: time.Now}, nil
}

// cipher: a new one per call, the library's Cipher keeps CBC state and is not safe to share between goroutines.
func (v *Vault) cipher(class string) (ff1.Cipher, error) {
	return ff1.NewCipher(10, len(class), v.key, []byte(class)) // the class is the tweak: one domain per class
}

// transform runs FF1 over the digits of s, keeping separators and the class's leading digits in place.
func (v *Vault) transform(class, s string, decrypt bool) (string, error) {
	keep, ok := Classes[class]
	if !ok {
		return "", ErrClass
	}
	var digits []byte
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			digits = append(digits, s[i])
		}
	}
	if class == "PII_ID.PHONE" && strings.HasPrefix(string(digits), "62") {
		keep = 3
	}
	if len(digits)-keep < minDigits {
		return "", ErrShort
	}
	c, err := v.cipher(class)
	if err != nil {
		return "", err
	}
	tail := string(digits[keep:])
	if decrypt {
		tail, err = c.Decrypt(tail)
	} else {
		tail, err = c.Encrypt(tail)
	}
	if err != nil {
		return "", err
	}
	out, next := []byte(s), string(digits[:keep])+tail
	j := 0
	for i := range out {
		if out[i] >= '0' && out[i] <= '9' {
			out[i] = next[j]
			j++
		}
	}
	return string(out), nil
}

func (v *Vault) mac(class, token string) string {
	m := hmac.New(sha256.New, v.macKey)
	m.Write([]byte(class + "\x00" + digitsOf(token)))
	return hex.EncodeToString(m.Sum(nil))
}

func digitsOf(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
}

// Tokenize returns a token per value and registers it until now+ttl (an earlier registration is extended, never
// shortened). The same value gives the same token, so a conversation stays consistent.
func (v *Vault) Tokenize(ctx context.Context, items []Item, ttl time.Duration) ([]string, error) {
	tokens := make([]string, len(items))
	exp := v.Now().Add(ttl)
	b := &pgx.Batch{}
	for i, it := range items {
		t, err := v.transform(it.Class, it.Value, false)
		if err != nil {
			return nil, fmt.Errorf("item %d (%s): %w", i, it.Class, err)
		}
		tokens[i] = t
		b.Queue(`INSERT INTO tokvault.tokens (tenant_id, class, token_mac, expires_at) VALUES ($1, $2, $3, $4)
			ON CONFLICT (tenant_id, class, token_mac) DO UPDATE SET expires_at = greatest(tokvault.tokens.expires_at, excluded.expires_at)`,
			v.tenant, it.Class, v.mac(it.Class, t), exp)
	}
	if err := v.db.SendBatch(ctx, b).Close(); err != nil {
		return nil, err
	}
	return tokens, nil
}

// DetokenizeRequest says who asks: the calling app, the principal it acts for (HMAC), and the trace.
type DetokenizeRequest struct {
	App       string `json:"app"`
	Principal string `json:"principal"`
	TraceID   string `json:"trace_id"`
	Items     []Item `json:"items"`
}

// Detokenize returns the value of each registered, unexpired token (nil for any other), after writing the access
// to the audit log: no audit record, no value. Entitlement is the caller's decision (the gateway asks only for
// apps allowed to see values).
func (v *Vault) Detokenize(ctx context.Context, req DetokenizeRequest) ([]*string, error) {
	out := make([]*string, len(req.Items))
	now := v.Now()
	var macs []string
	classes := map[string]int{}
	for i, it := range req.Items {
		if _, ok := Classes[it.Class]; !ok {
			continue
		}
		mac := v.mac(it.Class, it.Value)
		var exp time.Time
		err := v.db.QueryRow(ctx, "SELECT expires_at FROM tokvault.tokens WHERE tenant_id = $1 AND class = $2 AND token_mac = $3",
			v.tenant, it.Class, mac).Scan(&exp)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !exp.After(now) {
			continue // never issued, or expired: the token stays a token
		} else if err != nil {
			return nil, err
		}
		val, err := v.transform(it.Class, it.Value, true)
		if err != nil {
			continue
		}
		out[i] = &val
		macs = append(macs, mac[:16])
		classes[it.Class]++
	}
	if len(macs) == 0 {
		return out, nil
	}
	if _, err := v.audit.Append(ctx, v.tenant, "app:"+req.App, "token.detokenize", map[string]any{
		"principal": req.Principal, "trace_id": req.TraceID, "classes": classes, "tokens": macs, "requested": len(req.Items)}); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	return out, nil
}

// Purge deletes expired registrations.
func (v *Vault) Purge(ctx context.Context) (int64, error) {
	tag, err := v.db.Exec(ctx, "DELETE FROM tokvault.tokens WHERE tenant_id = $1 AND expires_at <= $2", v.tenant, v.Now())
	return tag.RowsAffected(), err
}
