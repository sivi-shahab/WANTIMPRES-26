package tokvault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/capitalone/fpe/ff1"
	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/audit"
)

const tenant = "6f1c1d1e-2a7b-4c3d-9e8f-0a1b2c3d4e5f"

var kek = []byte("0123456789abcdef0123456789abcdef")

// TestFF1Vector pins the library to NIST SP 800-38G sample 1 (AES-128, radix 10, empty tweak).
func TestFF1Vector(t *testing.T) {
	key, _ := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	c, err := ff1.NewCipher(10, 8, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ct, err := c.Encrypt("0123456789"); err != nil || ct != "2433477484" {
		t.Fatalf("FF1 sample 1: %s %v", ct, err)
	}
}

func setup(t *testing.T) (*Vault, string, *pgxpool.Pool) {
	t.Helper()
	dbURL := os.Getenv("AUDIT_TEST_DATABASE_URL")
	if dbURL == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("AUDIT_TEST_DATABASE_URL must be set in CI")
		}
		t.Skip("no test Postgres")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("tokvault_test_%d", time.Now().UnixNano()%1e9)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)"); admin.Close() })
	u, _ := neturl.Parse(dbURL)
	u.Path = "/" + name
	db, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	al, err := audit.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	v, err := Open(ctx, db, al, tenant, kek)
	if err != nil {
		t.Fatal(err)
	}
	return v, u.String(), db
}

// TestRoundTrip (ticket 24 AC): NIK, account numbers and card numbers come back as tokens of the same shape (length,
// separators, kept prefix) that turn back into the value; the same value always gives the same token.
func TestRoundTrip(t *testing.T) {
	v, _, db := setup(t)
	ctx := context.Background()
	items := []Item{
		{"PII_ID.NIK", "3171012310900001"},
		{"PII_ID.NIK", "3171 0123 1090 0001"},
		{"FIN.ACCOUNT", "1234567890"},      // BCA
		{"FIN.ACCOUNT", "1230004567891"},   // Mandiri
		{"FIN.ACCOUNT", "001201000123456"}, // BRI
		{"PCI.PAN", "4111 1111 1111 1111"},
		{"PCI.PAN", "378282246310005"},
		{"PII_ID.PHONE", "+62 812-3456-7890"},
		{"PII_ID.PHONE", "0812 3456 7890"},
		{"PII_ID.NPWP", "01.234.567.8-901.234"},
	}
	toks, err := v.Tokenize(ctx, items, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for i, it := range items {
		tok := toks[i]
		shape := func(s string) string {
			return strings.Map(func(r rune) rune {
				if r >= '0' && r <= '9' {
					return '9'
				}
				return r
			}, s)
		}
		if tok == it.Value || shape(tok) != shape(it.Value) {
			t.Errorf("%s %q → %q: not format-preserving", it.Class, it.Value, tok)
		}
		if it.Class == "PII_ID.PHONE" && !strings.HasPrefix(tok, "+62 8") && !strings.HasPrefix(tok, "08") {
			t.Errorf("phone prefix not kept: %s", tok)
		}
	}
	if digitsOf(toks[0]) != digitsOf(toks[1]) {
		t.Error("same NIK, different tokens")
	}
	again, _ := v.Tokenize(ctx, items[:1], time.Hour)
	other, _ := v.Tokenize(ctx, []Item{{"PII_ID.KK", items[0].Value}}, time.Hour)
	if again[0] != toks[0] || other[0] == toks[0] {
		t.Errorf("determinism / class separation: %s %s %s", toks[0], again[0], other[0])
	}

	var back []Item
	for i, it := range items {
		back = append(back, Item{it.Class, toks[i]})
	}
	back = append(back, Item{"PII_ID.NIK", digitsOf(toks[1])}, Item{"PII_ID.NIK", "3171012310900002"}) // reformatted; never issued
	vals, err := v.Detokenize(ctx, DetokenizeRequest{App: "cs-assistant", Principal: strings.Repeat("a", 64), TraceID: strings.Repeat("b", 32), Items: back})
	if err != nil {
		t.Fatal(err)
	}
	for i, it := range items {
		if vals[i] == nil || *vals[i] != it.Value {
			t.Errorf("%s: %v, want %s", it.Class, vals[i], it.Value)
		}
	}
	if vals[len(items)] == nil || *vals[len(items)] != "3171012310900001" || vals[len(items)+1] != nil {
		t.Errorf("digits-only form / unknown token: %v %v", vals[len(items)], vals[len(items)+1])
	}

	// Audited, without values; the key survives a restart; a wrong KEK cannot open it.
	var target string
	if err := db.QueryRow(ctx, "SELECT actor || ' ' || action || ' ' || target::text FROM audit.audit_log ORDER BY seq DESC LIMIT 1").Scan(&target); err != nil ||
		!strings.HasPrefix(target, "app:cs-assistant token.detokenize") || strings.Contains(target, "3171") || strings.Contains(target, "4111") {
		t.Errorf("audit: %s %v", target, err)
	}
	v2, err := Open(ctx, db, v.audit, tenant, kek)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := v2.Tokenize(ctx, items[:1], time.Hour); again[0] != toks[0] {
		t.Error("key changed on reopen")
	}
	if _, err := Open(ctx, db, v.audit, tenant, []byte(strings.Repeat("x", 32))); err == nil {
		t.Error("wrong KEK opened the key")
	}
	if _, err := v.Tokenize(ctx, []Item{{"SECRET.AWS_KEY", "AKIA"}}, time.Hour); err == nil {
		t.Error("tokenized a non-numeric class")
	}
}

// TestTTL: an expired token stays a token, unaudited, and is purged.
func TestTTL(t *testing.T) {
	v, _, db := setup(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	v.Now = func() time.Time { return now }
	toks, _ := v.Tokenize(ctx, []Item{{"PCI.PAN", "4111111111111111"}}, 10*time.Minute)
	now = now.Add(11 * time.Minute)
	vals, err := v.Detokenize(ctx, DetokenizeRequest{App: "a", Items: []Item{{"PCI.PAN", toks[0]}}})
	if err != nil || vals[0] != nil {
		t.Fatalf("expired token: %v %v", vals, err)
	}
	var n int
	_ = db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_log WHERE action = 'token.detokenize'").Scan(&n)
	if purged, _ := v.Purge(ctx); purged != 1 || n != 0 {
		t.Errorf("purged %d, audit entries %d", purged, n)
	}
}

// TestFailover (ticket 24 AC): two replicas, one active. The client is served by the active one; when it dies the
// passive one takes the lock and the same tokens still detokenize.
func TestFailover(t *testing.T) {
	v, dbURL, _ := setup(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	token := "gateway-secret"
	sum := sha256.Sum256([]byte(token))
	type replica struct {
		leader *Leader
		stop   context.CancelFunc
		srv    *httptest.Server
	}
	start := func() replica {
		l := &Leader{}
		rctx, stop := context.WithCancel(ctx)
		go l.Run(rctx, dbURL, 50*time.Millisecond, log)
		mux := http.NewServeMux()
		v.Routes(mux, l, hex.EncodeToString(sum[:]))
		return replica{l, stop, httptest.NewServer(mux)}
	}
	a := start()
	waitFor(t, a.leader.Active)
	b := start()
	defer b.srv.Close()
	defer b.stop()
	time.Sleep(200 * time.Millisecond)
	if b.leader.Active() {
		t.Fatal("two active replicas")
	}
	if r, _ := http.Get(b.srv.URL + "/ready"); r.StatusCode != 503 {
		t.Errorf("passive ready: %d", r.StatusCode)
	}
	c := &Client{URLs: []string{a.srv.URL, b.srv.URL}, Token: token, HTTP: http.DefaultClient}
	toks, err := c.Tokenize(ctx, []Item{{"PII_ID.NIK", "3171012310900001"}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&Client{URLs: []string{a.srv.URL}, Token: "wrong", HTTP: http.DefaultClient}).Tokenize(ctx, []Item{{"PII_ID.NIK", "3171012310900001"}}, time.Hour); err == nil {
		t.Error("wrong client token accepted")
	}

	a.stop() // the active replica dies: its lock connection closes
	a.srv.Close()
	waitFor(t, b.leader.Active)
	vals, err := c.Detokenize(ctx, DetokenizeRequest{App: "cs", Items: []Item{{"PII_ID.NIK", toks[0]}}})
	if err != nil || vals[0] == nil || *vals[0] != "3171012310900001" {
		t.Fatalf("after failover: %v %v", vals, err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for range 100 {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out")
}
