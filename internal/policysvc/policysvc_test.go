package policysvc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"math"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/tester"

	"wantimpres26/policy"
)

// Runs every policy/**/*_test.rego (precedence, templates, residency matrix, log masking) under go test.
func TestRegoPolicies(t *testing.T) {
	modules, store, err := tester.Load([]string{"../../policy"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The 80-combination residency matrix outlives the default 5s per test under -race.
	ch, err := tester.NewRunner().SetStore(store).SetModules(modules).SetTimeout(time.Minute).RunTests(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var results []*tester.Result
	for r := range ch {
		results = append(results, r)
	}
	t.Logf("%d rego tests", len(results))
	if len(results) == 0 {
		t.Fatal("no rego tests found")
	}
	for _, r := range results {
		if r.Fail || r.Error != nil {
			t.Errorf("%s.%s: fail=%v err=%v\n%s", r.Package, r.Name, r.Fail, r.Error, r.Output)
		}
	}
}

func keyPair(t *testing.T) (priv Signer, pub string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDer, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return Signer{KeyID: KeyID, Key: k}, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}))
}

func read(tarball []byte, pub string) (bundle.Bundle, error) {
	vc := bundle.NewVerificationConfig(map[string]*bundle.KeyConfig{KeyID: {Key: pub, Algorithm: Alg}}, KeyID, "", nil)
	return bundle.NewReader(bytes.NewReader(tarball)).WithBundleVerificationConfig(vc).Read()
}

func TestBuildSignsVerifiableBundle(t *testing.T) {
	priv, pub := keyPair(t)
	tarball, rev, err := Build(context.Background(), policy.Files, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := read(tarball, pub)
	if err != nil {
		t.Fatalf("verify with the signing key's public half: %v", err)
	}
	if b.Manifest.Revision != rev {
		t.Errorf("revision %q, want %q", b.Manifest.Revision, rev)
	}
	for _, m := range b.Modules {
		if strings.HasSuffix(m.Path, "_test.rego") {
			t.Errorf("test module shipped: %s", m.Path)
		}
	}
	forbidden, _ := b.Data["system"].(map[string]any)["log"].(map[string]any)["forbidden"].([]any)
	if !slices.Contains(forbidden, any("prompt")) {
		t.Errorf("data.system.log.forbidden = %v, want the privacy field list", forbidden)
	}

	_, otherPub := keyPair(t)
	if _, err := read(tarball, otherPub); err == nil {
		t.Error("bundle verified with an unrelated key")
	}
}

func TestBuildRefusesInvalidRules(t *testing.T) {
	priv, _ := keyPair(t)
	fsys := fstest.MapFS{}
	_ = fs.WalkDir(policy.Files, ".", func(p string, d fs.DirEntry, _ error) error {
		if !d.IsDir() {
			raw, _ := fs.ReadFile(policy.Files, p)
			fsys[p] = &fstest.MapFile{Data: raw}
		}
		return nil
	})
	fsys["wantimpres26/rules/data.json"] = &fstest.MapFile{Data: []byte(
		`{"version": "bad", "items": [{"id": "x", "when": [{"field": "channel", "op": "regex", "value": "."}], "action": "block", "reason": "X"}]}`)}
	if _, _, err := Build(context.Background(), fsys, priv, nil); err == nil || !strings.Contains(err.Error(), "unknown op regex") {
		t.Fatalf("err = %v, want rule_errors refusal", err)
	}

	fsys["wantimpres26/rules/data.json"] = &fstest.MapFile{Data: []byte(`{"version": "ok", "items": []}`)}
	cfg, _ := fs.ReadFile(policy.Files, "wantimpres26/risk/config/data.json")
	fsys["wantimpres26/risk/config/data.json"] = &fstest.MapFile{Data: bytes.Replace(cfg, []byte(`"sens": 0.30`), []byte(`"sens": 0.90`), 1)}
	if _, _, err := Build(context.Background(), fsys, priv, nil); err == nil || !strings.Contains(err.Error(), "weights sum to") {
		t.Fatalf("err = %v, want risk config refusal", err)
	}
}

func get(t *testing.T, url string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestServerETagAndLongPoll(t *testing.T) {
	s := &Server{}
	ts := httptest.NewServer(s)
	defer ts.Close()

	if resp, _ := get(t, ts.URL, nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("before publish: %d", resp.StatusCode)
	}
	s.Publish([]byte("v1"), "r1")
	resp, body := get(t, ts.URL, nil)
	if resp.StatusCode != 200 || body != "v1" || resp.Header.Get("ETag") != `"r1"` || resp.Header.Get("Content-Type") != ContentType {
		t.Fatalf("first fetch: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	if resp, _ := get(t, ts.URL, map[string]string{"If-None-Match": `"r1"`}); resp.StatusCode != http.StatusNotModified {
		t.Fatalf("unchanged without wait: %d", resp.StatusCode)
	}

	done := make(chan string)
	go func() {
		_, body := get(t, ts.URL, map[string]string{"If-None-Match": `"r1"`, "Prefer": "modes=snapshot,delta;wait=30"}) // exactly what OPA 1.21 sends
		done <- body
	}()
	time.Sleep(100 * time.Millisecond)
	s.Publish([]byte("v2"), "r2")
	select {
	case body := <-done:
		if body != "v2" {
			t.Fatalf("long-poll got %q, want v2", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("long-poll not woken by Publish")
	}
}

func pick[T any](r *rand.Rand, xs ...T) T { return xs[r.IntN(len(xs))] }

// unit returns a value in [0,1], biased toward the edges where rounding and caps bite.
func unit(r *rand.Rand) float64 { return pick(r, 0, 1, 0.5, 0.79999, 0.8, r.Float64()) }

func randomInput(r *rand.Rand) map[string]any {
	classes := []any{}
	for range r.IntN(4) {
		classes = append(classes, map[string]any{
			"type":       pick(r, "PII_ID.NIK", "PCI.PAN", "SECRET.AWS_KEY", "FIN.ACCOUNT", "PHI.DIAGNOSIS"),
			"count":      pick(r, 1, 9, 10, 1+r.IntN(1000)),
			"confidence": unit(r),
		})
	}
	in := map[string]any{
		"channel":   pick(r, "ai_gateway", "web_proxy", "browser_ext", "endpoint", "mcp_gateway", "connector"),
		"direction": pick(r, "request", "response", "tool_call", "tool_result", "at_rest"),
		"principal": map[string]any{
			"type": pick(r, "user", "agent", "service"), "id": "p", "risk": unit(r),
			"device": pick(r, "managed", "unmanaged", "unknown"), "account_context": pick(r, "corporate", "personal", "unknown"),
		},
		"destination": map[string]any{
			"app_id": "a", "sanction": pick(r, "sanctioned", "tolerated", "unsanctioned", "blocked", "under_review"),
			"region": pick(r, "ID", "US", "unknown"),
		},
		"content": map[string]any{
			"sensitivity": pick(r, "public", "internal", "confidential", "restricted"), "classes": classes,
			"injection_score": unit(r), "jailbreak_score": unit(r), "exfil_score": unit(r),
			"volume_ratio": pick(r, 0, 1.99, 2, 16, r.Float64()*1e9),
		},
	}
	if r.IntN(4) == 0 { // quiet event: every factor near 0, where a negative level or weight would show
		in["principal"] = map[string]any{"type": "user", "id": "p", "device": "managed", "account_context": "corporate"}
		in["content"] = map[string]any{"sensitivity": pick(r, "public", "internal"), "classes": []any{}}
		return in
	}
	if r.IntN(2) == 0 {
		agent := map[string]any{"agent_id": "g", "tool_risk": pick(r, "low", "medium", "high"), "session_injection_max": unit(r)}
		if r.IntN(2) == 0 {
			agent["action"] = pick(r, "read", "write", "external_send", "financial")
		}
		if r.IntN(2) == 0 {
			agent["registered"] = r.IntN(2) == 0
		}
		in["agent"] = agent
	}
	return in
}

// FR-RISK-1 property: for every valid input the score is an integer in [0, 100] and carries the weights version.
func TestRiskScoreAlwaysInRange(t *testing.T) {
	ctx := context.Background()
	modules, store, err := tester.Load([]string{"../../policy"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	opts := []func(*rego.Rego){rego.Query("data.wantimpres26.decision.result"), rego.Store(store)}
	for _, m := range modules {
		opts = append(opts, rego.ParsedModule(m))
	}
	pq, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewPCG(17, 17))
	seen := map[float64]bool{}
	for i := range 500 { // ~15s under -race
		in := randomInput(r)
		rs, err := pq.Eval(ctx, rego.EvalInput(in))
		if err != nil || len(rs) != 1 {
			t.Fatalf("eval %v: %v", in, err)
		}
		out := rs[0].Expressions[0].Value.(map[string]any)
		if slices.Contains(out["reason_codes"].([]any), any("INPUT_SCHEMA_INVALID")) {
			t.Fatalf("generator produced invalid input %d: %v", i, in)
		}
		score, err := out["risk_score"].(json.Number).Float64()
		if err != nil || score < 0 || score > 100 || score != math.Trunc(score) {
			t.Fatalf("risk_score %v for %v", out["risk_score"], in)
		}
		if out["risk_version"] == "" {
			t.Fatalf("no risk_version for %v", in)
		}
		seen[score] = true
	}
	if !seen[0] || !seen[100] || len(seen) < 40 {
		t.Errorf("generator too narrow: %d distinct scores, 0 seen %v, 100 seen %v", len(seen), seen[0], seen[100])
	}
}

// A release replaces the rules and exceptions documents; the revision follows the content, and the evaluator
// runs exactly what the bundle carries.
func TestOverridesAndEvaluator(t *testing.T) {
	ctx := context.Background()
	priv, pub := keyPair(t)
	rules := map[string]any{"version": "release-7", "items": []any{map[string]any{
		"id": "block-chatgpt", "when": []any{map[string]any{"field": "destination.app_id", "op": "eq", "value": "chatgpt"}},
		"action": "block", "reason": "NO_CHATGPT"}}}
	ov := Overrides{"wantimpres26.rules": rules, "wantimpres26.exceptions": map[string]any{"items": []any{}}}
	tarball, rev, err := Build(ctx, policy.Files, priv, ov)
	if err != nil {
		t.Fatal(err)
	}
	_, rev0, _ := Build(ctx, policy.Files, priv, nil)
	_, rev2, _ := Build(ctx, policy.Files, priv, ov)
	if rev == rev0 || rev != rev2 {
		t.Errorf("revision must follow content: %s %s %s", rev0, rev, rev2)
	}
	b, err := read(tarball, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.Data["wantimpres26"].(map[string]any)["rules"].(map[string]any)["version"]; got != "release-7" {
		t.Errorf("bundle rules version %v", got)
	}

	ev, err := NewEvaluator(ctx, policy.Files, ov)
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]any{"channel": "ai_gateway", "direction": "request", "principal": map[string]any{"type": "user", "id": "u"},
		"destination": map[string]any{"app_id": "chatgpt", "sanction": "sanctioned", "region": "ID"},
		"content":     map[string]any{"sensitivity": "public", "classes": []any{}}}
	d, err := ev.Eval(ctx, in)
	if err != nil || d.Action != "block" || !slices.Equal(d.MatchedRules, []string{"block-chatgpt"}) {
		t.Errorf("eval: %+v %v", d, err)
	}
	bad := Overrides{"wantimpres26.rules": map[string]any{"version": "x", "items": []any{map[string]any{"id": "a", "when": []any{}, "action": "block", "reason": "R"}}}}
	if _, err := NewEvaluator(ctx, policy.Files, bad); !errors.Is(err, ErrInvalidRules) {
		t.Errorf("invalid rules: %v", err)
	}
}
