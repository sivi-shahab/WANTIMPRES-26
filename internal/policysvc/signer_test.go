package policysvc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/bundle"

	"wantimpres26/policy"
)

// fakeTransit is Vault's transit sign endpoint over an in-memory key.
func fakeTransit(t *testing.T, key *ecdsa.PrivateKey, token string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Input     string `json:"input"`
			Prehashed bool   `json:"prehashed"`
			Marshal   string `json:"marshaling_algorithm"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		digest, _ := base64.StdEncoding.DecodeString(req.Input)
		if r.Header.Get("X-Vault-Token") != token || r.URL.Path != "/v1/transit/sign/wantimpres26-bundle/sha2-256" || !req.Prehashed || req.Marshal != "asn1" || len(digest) != 32 {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			return
		}
		sig, _ := ecdsa.SignASN1(crand.Reader, key, digest)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig)}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func pubPEM(k *ecdsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// verify reads a bundle as a sidecar configured like deploy/base/opa/opa.yaml: both slots trusted, no keyid, so
// the bundle's kid picks the key.
func verify(tarball []byte, trusted map[string]string) error {
	keys := map[string]*bundle.KeyConfig{}
	for id, pub := range trusted {
		keys[id] = &bundle.KeyConfig{Key: pub, Algorithm: Alg}
	}
	_, err := bundle.NewReader(bytes.NewReader(tarball)).WithBundleVerificationConfig(bundle.NewVerificationConfig(keys, "", "", nil)).Read()
	return err
}

// Ticket 40: the key signs through Vault transit (the private key never in the pod), and rotation from slot a to
// slot b works while sidecars trust both.
func TestTransitSignerAndRotation(t *testing.T) {
	ctx := context.Background()
	kmsKey, _ := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	tokenFile := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tokenFile, []byte("s.bundle-signer\n"), 0o600)
	vault := fakeTransit(t, kmsKey, "s.bundle-signer")
	transit := &TransitSigner{SignURL: vault.URL + "/v1/transit/sign/wantimpres26-bundle/sha2-256", TokenFile: tokenFile, Pub: &kmsKey.PublicKey, Client: vault.Client()}
	b := Signer{KeyID: "wantimpres26-policy-b", Key: transit}
	if err := b.Check(); err != nil {
		t.Fatal(err)
	}
	fileKey, _ := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	der, _ := x509.MarshalECPrivateKey(fileKey)
	a, err := FileSigner("wantimpres26-policy-a", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	both := map[string]string{"wantimpres26-policy-a": pubPEM(&fileKey.PublicKey), "wantimpres26-policy-b": pubPEM(&kmsKey.PublicKey)}

	signedA, _, err := Build(ctx, policy.Files, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	signedB, _, err := Build(ctx, policy.Files, b, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(signedA, both); err != nil {
		t.Errorf("slot a with both trusted: %v", err)
	}
	if err := verify(signedB, both); err != nil {
		t.Errorf("slot b (Vault transit) with both trusted: %v", err)
	}
	// Before the sidecars learned slot b, its bundles are refused: the order in the runbook matters.
	if err := verify(signedB, map[string]string{"wantimpres26-policy-a": both["wantimpres26-policy-a"]}); err == nil {
		t.Error("bundle of an untrusted slot verified")
	}
	// A key claiming a trusted slot it does not own is refused.
	rogue, _ := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	forged, _, _ := Build(ctx, policy.Files, Signer{KeyID: "wantimpres26-policy-a", Key: rogue}, nil)
	if err := verify(forged, both); err == nil {
		t.Error("forged bundle verified")
	}

	// Misconfiguration is caught at startup, not at the first release.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err := (Signer{KeyID: "wantimpres26-policy-a", Key: &TransitSigner{SignURL: transit.SignURL, TokenFile: tokenFile, Pub: &other.PublicKey, Client: vault.Client()}}).Check(); err == nil {
		t.Error("public key not matching the KMS key accepted")
	}
	_ = os.WriteFile(tokenFile, []byte("s.revoked"), 0o600)
	if err := b.Check(); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("revoked token: %v", err)
	}
	if err := (Signer{KeyID: "wantimpres26-policy", Key: fileKey}).Check(); err == nil {
		t.Error("unknown slot accepted")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), crand.Reader)
	if err := (Signer{KeyID: KeyID, Key: p384}).Check(); err == nil {
		t.Error("P-384 key accepted for ES256")
	}
}
