package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/sdk"
	"sigs.k8s.io/yaml"

	"wantimpres26/internal/policysvc"
	"wantimpres26/internal/server/mtlstest"
	"wantimpres26/policy"
)

// Ticket 40 AC: the bundle reaches an OPA sidecar configured exactly as deploy/base/opa/opa.yaml (mTLS with the
// pod's SVID, both key slots trusted, kid picks the key), not a pod without an allowed identity; and the key
// rotates from slot a to slot b without the sidecar missing a release.
func TestBundleOnlyForSidecarsAndKeyRotation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca := mtlstest.NewCA(t)
	bundles := &policysvc.Server{}
	srv := mtlstest.Serve(t, workloadRoutes(bundles), ca.Issue(t, "", "control-plane"), "ai-gateway", "mcp-gateway")

	keys := map[string]any{}
	signers := map[string]policysvc.Signer{}
	for _, slot := range policysvc.KeyIDs {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		keys[slot] = map[string]any{"algorithm": policysvc.Alg, "key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
		signers[slot] = policysvc.Signer{KeyID: slot, Key: k}
	}
	publish := func(s policysvc.Signer, version string) {
		t.Helper()
		tarball, rev, err := policysvc.Build(ctx, policy.Files, s, policysvc.Overrides{"wantimpres26.rules": map[string]any{"version": version, "items": []any{}}})
		if err != nil {
			t.Fatal(err)
		}
		bundles.Publish(tarball, rev)
	}
	publish(signers["wantimpres26-policy-a"], "signed-a")

	// The deployed sidecar config, with this test's paths, server and key material.
	raw, err := os.ReadFile("../../deploy/base/opa/opa.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	sidecar := func(sa string) map[string]any {
		dir := ca.Issue(t, "", sa)
		c := map[string]any{}
		b, _ := json.Marshal(cfg)
		_ = json.Unmarshal(b, &c)
		svc := c["services"].(map[string]any)["policy"].(map[string]any)
		svc["url"] = srv.URL + "/bundles"
		svc["tls"].(map[string]any)["ca_cert"] = filepath.Join(dir, "ca.crt")
		tlsAuth := svc["credentials"].(map[string]any)["client_tls"].(map[string]any)
		tlsAuth["cert"], tlsAuth["private_key"] = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
		c["bundles"].(map[string]any)["wantimpres26"].(map[string]any)["polling"] = map[string]any{"long_polling_timeout_seconds": 5}
		for slot := range c["keys"].(map[string]any) {
			c["keys"].(map[string]any)[slot] = keys[slot]
		}
		c["persistence_directory"] = t.TempDir()
		delete(c, "decision_logs")
		return c
	}
	if len(cfg["keys"].(map[string]any)) != len(policysvc.KeyIDs) {
		t.Fatalf("opa.yaml trusts %v, want the slots %v", cfg["keys"], policysvc.KeyIDs)
	}
	// sdk.New returns once the sidecar has activated a verified bundle (its readiness).
	start := func(sa string, within time.Duration) (*sdk.OPA, error) {
		b, _ := json.Marshal(sidecar(sa))
		sctx, scancel := context.WithTimeout(ctx, within)
		defer scancel()
		opa, err := sdk.New(sctx, sdk.Options{ID: sa, Config: bytes.NewReader(b)})
		if err == nil {
			t.Cleanup(func() { opa.Stop(context.Background()) })
		}
		return opa, err
	}
	version := func(opa *sdk.OPA) string {
		res, err := opa.Decision(ctx, sdk.DecisionOptions{Path: "/wantimpres26/rules/version"})
		if err != nil {
			return ""
		}
		v, _ := res.Result.(string)
		return v
	}
	wait := func(opa *sdk.OPA, want string, d time.Duration) bool {
		for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if version(opa) == want {
				return true
			}
		}
		return false
	}

	gw, err := start("ai-gateway", 60*time.Second)
	if err != nil || version(gw) != "signed-a" {
		t.Fatalf("sidecar with an allowed identity has no bundle: %v", err)
	}
	if _, err := start("siem-export", 5*time.Second); err == nil {
		t.Error("pod without an allowed identity got the bundle")
	}

	// Rotation: sidecars already trust slot b; the control-plane switches to it and the next release activates.
	publish(signers["wantimpres26-policy-b"], "signed-b")
	if !wait(gw, "signed-b", 30*time.Second) {
		t.Errorf("release signed with slot b not activated: %q", version(gw))
	}
	// A key outside the trusted slots is never activated, even under a trusted kid.
	rogue, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publish(policysvc.Signer{KeyID: "wantimpres26-policy-a", Key: rogue}, "rogue")
	time.Sleep(2 * time.Second)
	if v := version(gw); v != "signed-b" {
		t.Errorf("after a rogue bundle the sidecar runs %q, want the last verified signed-b", v)
	}
}
