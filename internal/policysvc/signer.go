package policysvc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/bundle"
)

// Ticket 40 (threat model G1): the bundle key lives in a KMS/HSM and signs through a crypto.Signer; the pod never
// holds the private key as a file. Sidecars trust two key slots, so a new key goes into the idle slot, sidecars
// pick it up, then the control-plane switches: rotation without downtime (docs/runbooks/rotasi-kunci-bundle.md).

// KeyIDs are the slots every sidecar trusts (deploy/base/opa/opa.yaml, --set-file keys.<slot>.key). KeyID is the
// default slot.
var KeyIDs = []string{"wantimpres26-policy-a", "wantimpres26-policy-b"}

// Signer signs bundles with an EC P-256 key it may never hand out, under KeyID (a slot of KeyIDs).
type Signer struct {
	KeyID string
	Key   crypto.Signer
}

// FileSigner is a PEM EC P-256 private key (development and tests only).
func FileSigner(keyID string, pemKey []byte) (Signer, error) {
	blk, _ := pem.Decode(pemKey)
	if blk == nil {
		return Signer{}, errors.New("bundle signing key: no PEM block")
	}
	k, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		if pk, err2 := x509.ParsePKCS8PrivateKey(blk.Bytes); err2 == nil {
			k, _ = pk.(*ecdsa.PrivateKey)
			err = nil
		}
	}
	if err != nil || k == nil {
		return Signer{}, fmt.Errorf("bundle signing key: not an EC private key: %v", err)
	}
	return Signer{KeyID: keyID, Key: k}, nil
}

// Check refuses an unknown slot or a key that is not P-256, and signs a probe to catch a KMS that is unreachable or
// a public key that does not match it before the first bundle.
func (s Signer) Check() error {
	if !slices.Contains(KeyIDs, s.KeyID) {
		return fmt.Errorf("bundle key id %q: want one of %v", s.KeyID, KeyIDs)
	}
	pub, ok := s.Key.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve.Params().Name != "P-256" {
		return errors.New("bundle signing key: want EC P-256")
	}
	d := sha256.Sum256([]byte("wantimpres26 bundle signer check"))
	sig, err := s.Key.Sign(rand.Reader, d[:], crypto.SHA256)
	if err != nil {
		return fmt.Errorf("bundle signing key: %w", err)
	}
	if !ecdsa.VerifyASN1(pub, d[:], sig) {
		return errors.New("bundle signing key: signature does not verify with the configured public key")
	}
	return nil
}

// signers holds the crypto.Signer of each Build in flight, by the SigningConfig.Key handed to OPA's signer plugin.
var signers sync.Map

const signerPlugin = "wantimpres26-crypto-signer"

func init() {
	_ = bundle.RegisterSigner(signerPlugin, cryptoSigner{})
}

// cryptoSigner is OPA's bundle.Signer over a crypto.Signer: a compact ES256 JWS with the files claim (as OPA's
// default signer writes it) and kid = the slot, which the sidecar uses to pick the public key.
type cryptoSigner struct{}

func (cryptoSigner) GenerateSignedToken(files []bundle.FileInfo, sc *bundle.SigningConfig, keyID string) (string, error) {
	v, ok := signers.Load(sc.Key)
	if !ok {
		return "", errors.New("no signer for this build")
	}
	hdr, _ := json.Marshal(map[string]string{"alg": Alg, "kid": keyID, "typ": "JWT"})
	payload, err := json.Marshal(map[string]any{"files": files, "keyid": keyID})
	if err != nil {
		return "", err
	}
	b64 := base64.RawURLEncoding.EncodeToString
	input := b64(hdr) + "." + b64(payload)
	d := sha256.Sum256([]byte(input))
	der, err := v.(crypto.Signer).Sign(rand.Reader, d[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	raw, err := jwsES256(der)
	if err != nil {
		return "", err
	}
	return input + "." + b64(raw), nil
}

// jwsES256 turns an ASN.1 ECDSA signature into JWS's fixed 64-byte r||s.
func jwsES256(der []byte) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &sig); err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("signature is not ASN.1 ECDSA: %v", err)
	}
	out := make([]byte, 64)
	sig.R.FillBytes(out[:32])
	sig.S.FillBytes(out[32:])
	return out, nil
}

func (s Signer) sign(b *bundle.Bundle) error {
	handle := fmt.Sprintf("%p", s.Key)
	signers.Store(handle, s.Key)
	defer signers.Delete(handle)
	if err := b.GenerateSignature(&bundle.SigningConfig{Plugin: signerPlugin, Key: handle, Algorithm: Alg}, s.KeyID, false); err != nil {
		return err
	}
	b.Signatures.Plugin = "" // a standard JWS: sidecars verify it with OPA's default verifier
	return nil
}

// TransitSigner signs through HashiCorp Vault's transit engine (HSM-backed in production: Vault managed keys or
// the bank's KMS behind a transit-compatible API). The private key never leaves it; Public is the configured PEM.
type TransitSigner struct {
	SignURL   string // https://vault:8200/v1/transit/sign/<key>/sha2-256
	TokenFile string // Vault token, re-read on every call (rotated by the Vault agent)
	Pub       *ecdsa.PublicKey
	Client    *http.Client
}

func (t *TransitSigner) Public() crypto.PublicKey { return t.Pub }

func (t *TransitSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	tok, err := os.ReadFile(t.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("vault token: %w", err)
	}
	body, _ := json.Marshal(map[string]any{"input": base64.StdEncoding.EncodeToString(digest), "prehashed": true, "marshaling_algorithm": "asn1"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.SignURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", strings.TrimSpace(string(tok)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("vault transit sign: HTTP %d: %s", resp.StatusCode, msg)
	}
	var out struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return nil, err
	}
	// "vault:v<N>:<base64 DER>"
	parts := strings.SplitN(out.Data.Signature, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" {
		return nil, fmt.Errorf("vault transit sign: unexpected signature %q", out.Data.Signature)
	}
	return base64.StdEncoding.DecodeString(parts[2])
}

// ParsePublicKey reads a PEM EC public key (the public half of the KMS key, from a ConfigMap).
func ParsePublicKey(pemKey []byte) (*ecdsa.PublicKey, error) {
	blk, _ := pem.Decode(pemKey)
	if blk == nil {
		return nil, errors.New("public key: no PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key: not EC")
	}
	return ec, nil
}
