package lifecycle

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
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
	"wantimpres26/internal/policysvc"
	"wantimpres26/policy"
)

const tenant = "00000000-0000-0000-0000-000000000001"

func setup(t *testing.T) (*Store, *pgxpool.Pool, string) {
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
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name := fmt.Sprintf("lifecycle_test_%x", b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		admin.Close()
	})
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
	s, err := Open(ctx, db, tenant, policy.Files)
	if err != nil {
		t.Fatal(err)
	}
	return s, db, u.String()
}

func rule(id, app, action string) any {
	return map[string]any{"id": id, "when": []any{map[string]any{"field": "destination.app_id", "op": "eq", "value": app}},
		"action": action, "reason": strings.ToUpper(strings.ReplaceAll(id, "-", "_"))}
}

func auditActions(t *testing.T, db *pgxpool.Pool) []string {
	t.Helper()
	rows, err := db.Query(context.Background(), "SELECT actor || ':' || action FROM audit.audit_log ORDER BY seq")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		out = append(out, a)
	}
	return out
}

func f(v float64) *float64 { return &v }

func storedEvent(i int, app string) events.Event {
	return events.Event{EventID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i), TenantID: tenant, TS: time.Now().UTC().Format(time.RFC3339Nano),
		TraceID: strings.Repeat("a", 32), Channel: "ai_gateway", Direction: "request", PrincipalID: strings.Repeat("b", 64), AppID: app,
		Action: "allow", ReasonCodes: []string{}, PolicyVersion: "release-1", RiskVersion: "risk-1", Classes: []events.Class{},
		ContentHash: strings.Repeat("c", 64), Sensitivity: "internal", Sanction: "sanctioned", Region: "ID", InjectionScore: f(0)}
}

func waitSimulation(t *testing.T, s *Store, id string) Simulation {
	t.Helper()
	for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		sim, err := s.Simulation(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if sim.State != "running" {
			return sim
		}
	}
	t.Fatal("simulation did not finish")
	return Simulation{}
}

// FR-POL-5/6: draft → simulated → pending_approval → active, 4-eyes, simulation diff, rollback, and every step
// in the audit log.
func TestLifecycle(t *testing.T) {
	s, db, _ := setup(t)
	ctx := context.Background()
	if _, err := Open(ctx, s.db, tenant, policy.Files); err != nil { // second replica starting
		t.Fatal(err)
	}
	if rs, _ := s.Releases(ctx, 10); len(rs) != 1 || rs[0].Rules["version"] != "release-1" {
		t.Fatalf("seed: %d releases", len(rs))
	}

	corpus, err := LoadCorpus(policy.Files)
	if err != nil || len(corpus) < 5 {
		t.Fatalf("corpus: %d %v", len(corpus), err)
	}
	stored := []events.Event{storedEvent(1, "deepseek"), storedEvent(2, "deepseek"), storedEvent(3, "chatgpt")}
	noMeta := storedEvent(4, "deepseek")
	noMeta.Sensitivity = ""
	stored = append(stored, noMeta)
	sim := &Simulator{Store: s, Corpus: corpus, MaxEvents: 1000, Log: slog.New(slog.DiscardHandler),
		Source: func(context.Context, time.Time, time.Time, int) ([]events.Event, error) { return stored, nil }}

	pid, err := s.CreatePolicy(ctx, "alice", "block-deepseek", []any{rule("no-deepseek", "deepseek", "block")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePolicy(ctx, "alice", "bad", []any{map[string]any{"id": "x", "when": []any{}, "action": "block", "reason": "X"}}); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid rules accepted: %v", err)
	}
	if err := s.Submit(ctx, "alice", pid, 1); !errors.Is(err, ErrState) {
		t.Errorf("submit without simulation: %v", err)
	}
	if _, err := sim.Start(ctx, "alice", pid, 1, time.Now().Add(-31*24*time.Hour), time.Now(), false); !errors.Is(err, ErrInvalid) {
		t.Errorf("31-day window accepted: %v", err)
	}
	simID, err := sim.Start(ctx, "alice", pid, 1, time.Time{}, time.Time{}, true)
	if err != nil {
		t.Fatal(err)
	}
	res := waitSimulation(t, s, simID)
	if res.State != "done" || res.Result.Total != 4 || res.Result.Replayable != 3 || res.Result.Changed != 2 ||
		res.Result.Diff["allow→block"] != 2 || len(res.Result.Corpus.Regressions) != 0 {
		t.Fatalf("simulation: %+v %+v", res, res.Result)
	}
	if vs, _ := s.Versions(ctx, pid); vs[0].State != Simulated {
		t.Fatalf("version state after simulation: %s", vs[0].State)
	}

	// Editing after simulation voids it.
	if err := s.UpdateDraft(ctx, "alice", pid, 1, []any{rule("no-deepseek", "deepseek", "block"), rule("warn-chatgpt", "chatgpt", "warn")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Submit(ctx, "alice", pid, 1); !errors.Is(err, ErrState) {
		t.Errorf("submit after edit without re-simulation: %v", err)
	}
	simID, _ = sim.Start(ctx, "alice", pid, 1, time.Time{}, time.Time{}, true)
	if res = waitSimulation(t, s, simID); res.Result.Diff["allow→warn"] != 1 {
		t.Errorf("re-simulation diff %v", res.Result.Diff)
	}
	if err := s.Submit(ctx, "alice", pid, 1); err != nil {
		t.Fatal(err)
	}

	// Ticket AC: publish without a second approver is refused.
	if _, err := s.Approve(ctx, "alice", pid, 1); !errors.Is(err, ErrFourEyes) {
		t.Fatalf("self-approval: %v", err)
	}
	if _, err := s.Approve(ctx, "ALICE", pid, 1); !errors.Is(err, ErrFourEyes) {
		t.Fatalf("self-approval, other case: %v", err)
	}
	n, err := s.Approve(ctx, "bob", pid, 1)
	if err != nil || n != 2 {
		t.Fatalf("approve: release %d %v", n, err)
	}
	latest, _ := s.Latest(ctx)
	if latest.Rules["version"] != "release-2" || !strings.Contains(fmt.Sprint(latest.Rules["items"]), "no-deepseek") ||
		!strings.Contains(fmt.Sprint(latest.Rules["items"]), "tpl.pii-id-to-unsanctioned") {
		t.Errorf("release 2 must hold builtin + new policy: %v", latest.Rules)
	}

	// A version that would clash with an active rule id is refused at publish, atomically.
	v2, err := s.NewVersion(ctx, "alice", pid, []any{rule("tpl.secret-to-any-ai", "x", "block")})
	if err != nil {
		t.Fatal(err)
	}
	if simID, err = sim.Start(ctx, "alice", pid, v2, time.Time{}, time.Time{}, false); err != nil {
		t.Fatal(err)
	}
	if res = waitSimulation(t, s, simID); res.State != "failed" {
		t.Errorf("simulation of a clashing version: %s", res.State)
	}
	_ = s.UpdateDraft(ctx, "alice", pid, v2, []any{rule("no-deepseek", "deepseek", "warn")})
	simID, _ = sim.Start(ctx, "alice", pid, v2, time.Time{}, time.Time{}, true)
	waitSimulation(t, s, simID)
	_ = s.Submit(ctx, "alice", pid, v2)
	if err := s.Reject(ctx, "bob", pid, v2, "warn is too weak"); err != nil {
		t.Fatal(err)
	}
	simID, _ = sim.Start(ctx, "alice", pid, v2, time.Time{}, time.Time{}, true)
	waitSimulation(t, s, simID)
	_ = s.Submit(ctx, "alice", pid, v2)
	if _, err := s.Approve(ctx, "bob", pid, v2); err != nil {
		t.Fatal(err)
	}

	// Rollback: one action back to v1.
	if _, err := s.Rollback(ctx, "carol", pid); err != nil {
		t.Fatal(err)
	}
	vs, _ := s.Versions(ctx, pid)
	if vs[0].State != Active || vs[1].State != Retired {
		t.Errorf("after rollback: v1 %s, v2 %s", vs[0].State, vs[1].State)
	}
	latest, _ = s.Latest(ctx)
	for _, it := range latest.Rules["items"].([]any) {
		if r := it.(map[string]any); r["id"] == "no-deepseek" && r["action"] != "block" {
			t.Errorf("rollback release has no-deepseek = %v, want v1's block", r["action"])
		}
	}

	want := []string{"system:policy.seed", "alice:policy.create", "alice:policy.simulate", "system:policy.simulate.done",
		"alice:policy.version.edit", "alice:policy.simulate", "system:policy.simulate.done", "alice:policy.version.submit",
		"bob:policy.version.approve", "alice:policy.version.create", "alice:policy.simulate", "alice:policy.version.edit",
		"alice:policy.simulate", "system:policy.simulate.done", "alice:policy.version.submit", "bob:policy.version.reject",
		"alice:policy.simulate", "system:policy.simulate.done", "alice:policy.version.submit", "bob:policy.version.approve",
		"carol:policy.rollback"}
	got := auditActions(t, db)
	if len(got) < len(want) || !slices.Equal(got[:len(want)], want) {
		t.Errorf("audit log:\n got %v\nwant %v", got, want)
	}
}

// FR-POL-7: exceptions must expire, need a second person, ride in the bundle, and warn before they lapse.
func TestExceptions(t *testing.T) {
	s, db, _ := setup(t)
	ctx := context.Background()
	now := time.Now()
	ok := Exception{Rules: []string{"tpl.pii-id-to-unsanctioned"}, Scope: map[string]string{"group": "SG-RESEARCH"},
		Reason: "research pilot with DeepSeek on synthetic NIK", ExpiresAt: now.Add(30 * 24 * time.Hour)}
	for name, mutate := range map[string]func(*Exception){
		"no expires_at":     func(e *Exception) { e.ExpiresAt = time.Time{} },
		"past expires_at":   func(e *Exception) { e.ExpiresAt = now.Add(-time.Hour) },
		"over 90 days":      func(e *Exception) { e.ExpiresAt = now.Add(91 * 24 * time.Hour) },
		"empty scope":       func(e *Exception) { e.Scope = map[string]string{} },
		"unknown scope key": func(e *Exception) { e.Scope = map[string]string{"department": "x"} },
		"unknown rule":      func(e *Exception) { e.Rules = []string{"no-such-rule"} },
		"no reason":         func(e *Exception) { e.Reason = " " },
	} {
		bad := ok
		mutate(&bad)
		if _, err := s.RequestException(ctx, "dina", bad, now); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	id, err := s.RequestException(ctx, "dina", ok, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveException(ctx, "dina", id, now); !errors.Is(err, ErrFourEyes) {
		t.Errorf("self-approved exception: %v", err)
	}
	if _, err := s.ApproveException(ctx, "bob", id, now); err != nil {
		t.Fatal(err)
	}
	latest, _ := s.Latest(ctx)
	if !strings.Contains(fmt.Sprint(latest.Exceptions), "SG-RESEARCH") {
		t.Errorf("approved exception not in release: %v", latest.Exceptions)
	}

	soon := ok
	soon.ExpiresAt = now.Add(3 * 24 * time.Hour)
	sid, _ := s.RequestException(ctx, "dina", soon, now)
	_, _ = s.ApproveException(ctx, "bob", sid, now)
	if _, notified, err := s.Sweep(ctx, now); err != nil || notified != 1 {
		t.Errorf("expiry notice: %d %v", notified, err)
	}
	if _, notified, _ := s.Sweep(ctx, now); notified != 0 {
		t.Error("expiry notice sent twice")
	}
	if n, _ := s.ExpiringSoon(ctx, now); n != 1 {
		t.Errorf("expiring gauge %d", n)
	}
	if expired, _, err := s.Sweep(ctx, now.Add(4*24*time.Hour)); err != nil || expired != 1 {
		t.Errorf("expire: %d %v", expired, err)
	}
	if _, err := s.RevokeException(ctx, "bob", id); err != nil {
		t.Fatal(err)
	}
	latest, _ = s.Latest(ctx)
	if items := latest.Exceptions["items"].([]any); len(items) != 0 {
		t.Errorf("revoked/expired exceptions still in release: %v", items)
	}
	got := strings.Join(auditActions(t, db), " ")
	for _, a := range []string{"dina:policy.exception.request", "bob:policy.exception.approve", "system:policy.exception.expiring",
		"system:policy.exception.expire", "bob:policy.exception.revoke"} {
		if !strings.Contains(got, a) {
			t.Errorf("audit lacks %s", a)
		}
	}
}

// Ticket AC: publish/rollback reaches every PEP within 60 s p99. Two replicas (releasers) share Postgres; a real
// OPA instance (the sidecar's bundle plugin, via the SDK) long-polls replica B while changes are cut through the
// store. Measured from the change committing until OPA's decision flips.
func TestPropagation(t *testing.T) {
	s, _, _ := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDer, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}))

	var servers []*httptest.Server
	for range 2 {
		srv := &policysvc.Server{}
		r := &Releaser{Store: s, Server: srv, FS: policy.Files, Signer: policysvc.Signer{KeyID: policysvc.KeyID, Key: k}, Log: slog.New(slog.DiscardHandler), Poll: 15 * time.Second}
		if err := r.Sync(ctx); err != nil {
			t.Fatal(err)
		}
		go r.Run(ctx)
		hs := httptest.NewServer(srv)
		defer hs.Close()
		servers = append(servers, hs)
	}
	cfg, _ := json.Marshal(map[string]any{
		"services": map[string]any{"policy": map[string]any{"url": servers[1].URL}},
		"bundles": map[string]any{"wantimpres26": map[string]any{"service": "policy", "resource": "/", "signing": map[string]any{"keyid": policysvc.KeyID},
			"polling": map[string]any{"long_polling_timeout_seconds": 30}}},
		"keys": map[string]any{policysvc.KeyID: map[string]any{"algorithm": policysvc.Alg, "key": pub}},
	})
	opa, err := sdk.New(ctx, sdk.Options{ID: "pep", Config: bytes.NewReader(cfg), Logger: nil})
	if err != nil {
		t.Fatal(err)
	}
	defer opa.Stop(ctx)

	in := map[string]any{"channel": "ai_gateway", "direction": "request", "principal": map[string]any{"type": "user", "id": "u", "groups": []any{"SG-X"}},
		"destination": map[string]any{"app_id": "deepseek", "sanction": "sanctioned", "region": "ID"},
		"content":     map[string]any{"sensitivity": "internal", "classes": []any{}}}
	action := func() string {
		res, err := opa.Decision(ctx, sdk.DecisionOptions{Path: "/wantimpres26/decision/result", Input: in})
		if err != nil {
			return ""
		}
		return res.Result.(map[string]any)["action"].(string)
	}
	for deadline := time.Now().Add(30 * time.Second); action() == "" && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
	}

	// Publish a blocking rule, then toggle an exception for the PEP's group on and off: each is a release.
	pid, _ := s.CreatePolicy(ctx, "alice", "block-deepseek", []any{rule("no-deepseek", "deepseek", "block")})
	sim := &Simulator{Store: s, MaxEvents: 1, Log: slog.New(slog.DiscardHandler),
		Source: func(context.Context, time.Time, time.Time, int) ([]events.Event, error) { return nil, nil }}
	simID, _ := sim.Start(ctx, "alice", pid, 1, time.Time{}, time.Time{}, false)
	waitSimulation(t, s, simID)
	_ = s.Submit(ctx, "alice", pid, 1)

	var lat []time.Duration
	measure := func(want string, change func() error) {
		t.Helper()
		start := time.Now()
		if err := change(); err != nil {
			t.Fatal(err)
		}
		for action() != want {
			if time.Since(start) > 90*time.Second {
				t.Fatalf("OPA still not %s after 90 s", want)
			}
			time.Sleep(10 * time.Millisecond)
		}
		lat = append(lat, time.Since(start))
	}
	measure("block", func() error { _, err := s.Approve(ctx, "bob", pid, 1); return err })
	for i := range 10 {
		var id string
		measure("allow", func() error {
			var err error
			e := Exception{Rules: []string{"no-deepseek"}, Scope: map[string]string{"group": "SG-X"}, Reason: fmt.Sprintf("toggle %d", i), ExpiresAt: time.Now().Add(time.Hour)}
			if id, err = s.RequestException(ctx, "dina", e, time.Now()); err != nil {
				return err
			}
			_, err = s.ApproveException(ctx, "bob", id, time.Now())
			return err
		})
		measure("block", func() error { _, err := s.RevokeException(ctx, "bob", id); return err })
	}
	measure("allow", func() error { _, err := s.Retire(ctx, "bob", pid, 1); return err })
	slices.Sort(lat)
	p99 := lat[len(lat)*99/100]
	t.Logf("publish→PEP over %d releases: p50 %v, p99 %v, max %v", len(lat), lat[len(lat)/2], p99, lat[len(lat)-1])
	if p99 > 60*time.Second {
		t.Errorf("p99 %v > 60 s", p99)
	}
}
