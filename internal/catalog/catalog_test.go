package catalog

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-policy-agent/opa/v1/sdk"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/events"
	"wantimpres26/internal/lifecycle"
	"wantimpres26/internal/policysvc"
	"wantimpres26/policy"
)

func TestConfidenceFormula(t *testing.T) {
	for _, c := range []struct {
		in   []float64
		want float64
	}{{nil, 0}, {[]float64{0.9}, 0.9}, {[]float64{0.9, 0.8}, 0.98}, {[]float64{0.6, 0.5}, 0.8}, {[]float64{0.5, 0.5, 0.5}, 0.875}} {
		if got := Confidence(c.in...); math.Abs(got-c.want) > 1e-9 {
			t.Errorf("Confidence(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestMatch(t *testing.T) {
	seed, err := ParseFeed(seedFeed)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		s       Signals
		app     string
		review  bool
		signals []string
	}{
		{"domain", Signals{Host: "claude.ai"}, "claude", false, []string{"domain"}},
		{"subdomain", Signals{Host: "eu.api.anthropic.com"}, "claude", false, []string{"domain"}},
		{"look-alike domain does not match", Signals{Host: "notclaude.ai"}, "", false, nil},
		{"domain + API + header + SDK", Signals{Host: "api.anthropic.com", Method: "POST", Path: "/v1/messages", Headers: []string{"Anthropic-Version"},
			UserAgent: "Anthropic/Python 0.40", PayloadKeys: []string{"model", "messages", "max_tokens"}}, "claude", false,
			[]string{"domain", "api_signature", "header", "payload_shape", "user_agent"}},
		{"gemini path suffix", Signals{Method: "POST", Path: "/v1beta/models/gemini-2.0:generateContent"}, "gemini", false, []string{"api_signature"}},
		{"payload shape alone sits at the threshold", Signals{PayloadKeys: []string{"contents"}}, "gemini", false, []string{"payload_shape"}},
		{"SDK user agent alone needs review", Signals{UserAgent: "Cursor/0.42"}, "cursor", true, []string{"user_agent"}},
	}
	for _, c := range cases {
		d, ok := Match(seed.Apps, c.s)
		if c.app == "" {
			if ok {
				t.Errorf("%s: matched %+v", c.name, d)
			}
			continue
		}
		if !ok || d.AppID != c.app || d.NeedsReview != c.review || !slices.Equal(d.Signals, c.signals) {
			t.Errorf("%s: %+v", c.name, d)
		}
	}
	// payload shape alone is 0.6: exactly the review threshold, not below it.
	if d, _ := Match(seed.Apps, Signals{PayloadKeys: []string{"contents"}}); d.Confidence != WeightPayload {
		t.Errorf("payload confidence %v", d.Confidence)
	}
	// An OpenAI-compatible endpoint alone is shared by several vendors: ambiguous, to review.
	d, _ := Match(seed.Apps, Signals{Method: "POST", Path: "/v1/chat/completions"})
	if d.AppID != "" || !d.NeedsReview || !slices.Contains(d.Candidates, "deepseek") || !slices.Contains(d.Candidates, "chatgpt") {
		t.Errorf("ambiguous endpoint: %+v", d)
	}
	// …and the domain settles it.
	if d, _ := Match(seed.Apps, Signals{Host: "api.deepseek.com", Method: "POST", Path: "/v1/chat/completions"}); d.AppID != "deepseek" || d.NeedsReview {
		t.Errorf("domain + endpoint: %+v", d)
	}
}

func keys(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return k, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func sign(k *ecdsa.PrivateKey, raw []byte) string {
	sum := sha256.Sum256(raw)
	sig, _ := ecdsa.SignASN1(rand.Reader, k, sum[:])
	return base64.StdEncoding.EncodeToString(sig) + "\n" // as a .sig file usually ends
}

func feed(version int64, apps ...App) []byte {
	b, _ := json.Marshal(Feed{Version: version, Apps: apps})
	return b
}

func app(id, region string) App {
	return App{ID: id, Vendor: "V", Name: id, Category: "chat", Domains: []string{id + ".example"}, HostingRegion: region}
}

// Ticket AC: a feed without a valid signature is refused.
func TestVerifyFeed(t *testing.T) {
	k, pub := keys(t)
	other, _ := keys(t)
	raw := feed(2, app("x", "US"))
	if f, err := VerifyFeed(raw, sign(k, raw), pub); err != nil || f.Version != 2 {
		t.Fatalf("valid feed: %v", err)
	}
	tampered := bytes.Replace(raw, []byte(`"US"`), []byte(`"ID"`), 1)
	for name, c := range map[string]struct {
		raw []byte
		sig string
	}{
		"tampered":  {tampered, sign(k, raw)},
		"other key": {raw, sign(other, raw)},
		"no sig":    {raw, ""},
		"garbage":   {raw, "not base64!"},
	} {
		if _, err := VerifyFeed(c.raw, c.sig, pub); !errors.Is(err, ErrSignature) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := VerifyFeed(raw, sign(k, raw), nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("no key configured: %v", err)
	}
	bad := feed(3, app("Bad ID", "US"))
	if _, err := VerifyFeed(bad, sign(k, bad), pub); !errors.Is(err, ErrInvalid) {
		t.Errorf("signed but invalid app: %v", err)
	}
}

func setup(t *testing.T) (*Store, *lifecycle.Store, *pgxpool.Pool) {
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
	name := fmt.Sprintf("catalog_test_%d", time.Now().UnixNano()%1e9)
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
	t.Cleanup(al.Close)
	const tenant = "00000000-0000-0000-0000-000000000001"
	ls, err := lifecycle.Open(ctx, db, tenant, policy.Files)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, db, tenant, ls)
	if err != nil {
		t.Fatal(err)
	}
	return s, ls, db
}

func auditActions(t *testing.T, db *pgxpool.Pool) string {
	rows, _ := db.Query(context.Background(), "SELECT actor || ':' || action || ':' || target::text FROM audit.audit_log ORDER BY seq")
	var out []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		out = append(out, s)
	}
	return strings.Join(out, "\n")
}

func TestCatalogStore(t *testing.T) {
	s, ls, db := setup(t)
	ctx := context.Background()
	now := time.Now()
	if _, err := Open(ctx, db, "00000000-0000-0000-0000-000000000001", ls); err != nil { // second replica
		t.Fatal(err)
	}
	rel, _ := ls.Latest(ctx)
	cat := rel.Data["wantimpres26.catalog"].(map[string]any)
	seed, _ := ParseFeed(seedFeed)
	if cat["version"] != float64(seed.Version) || cat["apps"].(map[string]any)["deepseek"].(map[string]any)["region"] != "CN" {
		t.Fatalf("seed release catalog: %v", cat)
	}
	if rs, _ := ls.Releases(ctx, 10); len(rs) != 2 { // lifecycle seed + catalog seed, once
		t.Errorf("%d releases after two opens", len(rs))
	}

	// Ticket AC: status changes are audited (and published).
	blocked, why := "blocked", "trains on prompts; no DPA"
	if _, err := s.Update(ctx, "secadmin", "deepseek", Patch{Sanction: &blocked}); !errors.Is(err, ErrInvalid) {
		t.Errorf("sanction change without reason: %v", err)
	}
	if _, err := s.Update(ctx, "secadmin", "no-such-app", Patch{Sanction: &blocked, Reason: &why}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown app: %v", err)
	}
	v, err := s.Update(ctx, "secadmin", "deepseek", Patch{Sanction: &blocked, Reason: &why})
	if err != nil || v.Sanction != "blocked" {
		t.Fatalf("update: %+v %v", v, err)
	}
	rel, _ = ls.Latest(ctx)
	if rel.Data["wantimpres26.catalog"].(map[string]any)["apps"].(map[string]any)["deepseek"].(map[string]any)["sanction"] != "blocked" {
		t.Error("release does not carry the new status")
	}
	log := auditActions(t, db)
	if !strings.Contains(log, `secadmin:catalog.app.update:`) || !strings.Contains(log, `"before": {"owner": null, "sanction": "unsanctioned"`) ||
		!strings.Contains(log, `"after": {"owner": null, "sanction": "blocked"`) {
		t.Errorf("audit lacks before/after:\n%s", log)
	}

	// Ticket AC: feeds without a valid signature are refused (and recorded); stale ones too.
	k, pub := keys(t)
	raw := feed(seed.Version+1, append(seedApps(t), app("newai", "SG"))...)
	if _, err := s.ImportSigned(ctx, "secadmin", raw, sign(k, raw[:len(raw)-1]), pub); !errors.Is(err, ErrSignature) {
		t.Errorf("bad signature: %v", err)
	}
	if v, err := s.ImportSigned(ctx, "secadmin", raw, sign(k, raw), pub); err != nil || v != seed.Version+1 {
		t.Fatalf("import: %d %v", v, err)
	}
	if _, err := s.ImportSigned(ctx, "secadmin", raw, sign(k, raw), pub); !errors.Is(err, ErrStale) {
		t.Errorf("replayed feed: %v", err)
	}
	if !strings.Contains(auditActions(t, db), "secadmin:catalog.feed.rejected") {
		t.Error("rejected feed not audited")
	}
	all, _, _ := s.List(ctx, ListOptions{}, now)
	if i := slices.IndexFunc(all, func(v View) bool { return v.ID == "deepseek" }); all[i].Sanction != "blocked" {
		t.Error("override lost on feed update")
	}

	// Local app, usage (with redelivery and shadow AI), sorting.
	if err := s.AddLocal(ctx, "secadmin", app("bank-llm", "ID")); err != nil {
		t.Fatal(err)
	}
	ev := func(id int, appID, action string, classes int) events.Event {
		e := events.Event{EventID: fmt.Sprintf("00000000-0000-4000-8000-%012d", id), TS: now.UTC().Format(time.RFC3339Nano),
			AppID: appID, Action: action, PrincipalID: fmt.Sprintf("p%d", id%2)}
		for range classes {
			e.Classes = append(e.Classes, events.Class{Type: "PII_ID.NIK", Count: 1})
		}
		return e
	}
	for _, e := range []events.Event{ev(1, "deepseek", "block", 1), ev(2, "deepseek", "block", 1), ev(3, "deepseek", "allow", 0),
		ev(1, "deepseek", "block", 1), ev(4, "unknown-ai.io", "allow", 1), ev(5, "chatgpt", "allow", 0)} {
		if err := s.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	items, total, _ := s.List(ctx, ListOptions{Sort: "-sensitive_events", Limit: 2}, now)
	if total < 18 || len(items) != 2 || items[0].ID != "deepseek" || *items[0].Usage != (Usage{Events: 3, SensitiveEvents: 2, Blocked: 2, Users: 2}) {
		t.Errorf("top apps: total %d %+v", total, items)
	}
	if items[1].ID != "unknown-ai.io" || items[1].Source != "observed" {
		t.Errorf("shadow AI app: %+v", items[1])
	}

	// Ticket AC: offshore apps without an OJK approval reference are flagged; adding one clears it.
	flagged, _, _ := s.List(ctx, ListOptions{Flag: FlagOffshoreNoOJK}, now)
	ids := func(vs []View) []string {
		var out []string
		for _, v := range vs {
			out = append(out, v.ID)
		}
		return out
	}
	if got := ids(flagged); !slices.Contains(got, "deepseek") || !slices.Contains(got, "newai") || slices.Contains(got, "bank-llm") || !slices.Contains(got, "unknown-ai.io") {
		t.Errorf("residency report: %v", got)
	}
	ref := "OJK/S-123/2026"
	if _, err := s.Update(ctx, "secadmin", "newai", Patch{OJKApprovalRef: &ref}); err != nil {
		t.Fatal(err)
	}
	flagged, _, _ = s.List(ctx, ListOptions{Flag: FlagOffshoreNoOJK}, now)
	if slices.Contains(ids(flagged), "newai") {
		t.Error("app with an OJK approval reference still flagged")
	}
}

func seedApps(t *testing.T) []App {
	f, err := ParseFeed(seedFeed)
	if err != nil {
		t.Fatal(err)
	}
	return f.Apps
}

// Ticket AC: a status change reaches OPA decisions within 60 s. One replica's releaser serves the bundle; a real
// OPA (the sidecar's bundle plugin via the SDK) long-polls it.
func TestStatusChangeReachesOPA(t *testing.T) {
	s, ls, _ := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDer, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	srv := &policysvc.Server{}
	r := &lifecycle.Releaser{Store: ls, Server: srv, FS: policy.Files, Signer: policysvc.Signer{KeyID: policysvc.KeyID, Key: k},
		Log: slog.New(slog.DiscardHandler), Poll: 15 * time.Second}
	if err := r.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	go r.Run(ctx)
	hs := httptest.NewServer(srv)
	defer hs.Close()
	cfg, _ := json.Marshal(map[string]any{
		"services": map[string]any{"policy": map[string]any{"url": hs.URL}},
		"bundles": map[string]any{"wantimpres26": map[string]any{"service": "policy", "resource": "/", "signing": map[string]any{"keyid": policysvc.KeyID},
			"polling": map[string]any{"long_polling_timeout_seconds": 30}}},
		"keys": map[string]any{policysvc.KeyID: map[string]any{"algorithm": policysvc.Alg, "key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}))}},
	})
	opa, err := sdk.New(ctx, sdk.Options{ID: "pep", Config: bytes.NewReader(cfg)})
	if err != nil {
		t.Fatal(err)
	}
	defer opa.Stop(ctx)
	// The PEP believes copilot is sanctioned and onshore; the catalog decides.
	in := map[string]any{"channel": "ai_gateway", "direction": "request", "principal": map[string]any{"type": "user", "id": "u"},
		"destination": map[string]any{"app_id": "microsoft-copilot", "sanction": "sanctioned", "region": "ID"},
		"content":     map[string]any{"sensitivity": "internal", "classes": []any{}}}
	action := func() string {
		res, err := opa.Decision(ctx, sdk.DecisionOptions{Path: "/wantimpres26/decision/result", Input: in})
		if err != nil {
			return ""
		}
		return res.Result.(map[string]any)["action"].(string)
	}
	// Seed: copilot is unsanctioned with an unknown (= offshore) region, so it is blocked until the bank decides.
	for deadline := time.Now().Add(30 * time.Second); action() != "block"; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("seed decision is %q, want block", action())
		}
	}
	var lat []time.Duration
	for i, st := range []struct{ sanction, region, want string }{{"sanctioned", "ID", "allow"}, {"blocked", "ID", "block"}, {"sanctioned", "ID", "allow"}} {
		start := time.Now()
		sanction, region, reason := st.sanction, st.region, fmt.Sprintf("change %d", i)
		if _, err := s.Update(ctx, "secadmin", "microsoft-copilot", Patch{Sanction: &sanction, Reason: &reason, HostingRegion: &region}); err != nil {
			t.Fatal(err)
		}
		for action() != st.want {
			if time.Since(start) > 60*time.Second {
				t.Fatalf("decision still not %s after 60 s", st.want)
			}
			time.Sleep(10 * time.Millisecond)
		}
		lat = append(lat, time.Since(start))
	}
	t.Logf("catalog change → OPA decision: %v", lat)
}
