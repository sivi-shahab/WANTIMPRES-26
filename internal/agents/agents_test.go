package agents

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/authz"
	"wantimpres26/internal/authz/authztest"
	"wantimpres26/internal/events"
	"wantimpres26/internal/identity"
	"wantimpres26/internal/lifecycle"
	"wantimpres26/internal/policysvc"
	"wantimpres26/policy"
)

const tenant = "00000000-0000-0000-0000-000000000001"

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
	name := fmt.Sprintf("agents_test_%d", time.Now().UnixNano()%1e9)
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
	al, _ := audit.Open(ctx, u.String())
	t.Cleanup(al.Close)
	if _, err := identity.Open(ctx, db, tenant); err != nil {
		t.Fatal(err)
	}
	for _, u := range []struct {
		name   string
		active bool
	}{{"budi@bankmega.com", true}, {"ani@bankmega.com", true}, {"svc-shared", true}} {
		if _, err := db.Exec(ctx, "INSERT INTO identity.users (user_name, active, doc) VALUES ($1, $2, '{}')", u.name, u.active); err != nil {
			t.Fatal(err)
		}
	}
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

func agent(id, owner, unit, ref string) Agent {
	a := Agent{ID: id, Name: id, BusinessUnit: unit, Purpose: "reconcile invoices", Environment: "prod", RiskTier: "high",
		Identity: Identity{Type: "spiffe", Ref: ref}, Tools: []Tool{{Name: "erp.read", Risk: "low"}, {Name: "payments.transfer", Risk: "high",
			Scopes: map[string]any{"amount": map[string]any{"max": 25000000.0}}}}, DataScopes: []string{"finance:invoices"}}
	if owner != "" {
		a.Owner = &owner
	}
	return a
}

func decide(t *testing.T, ls *lifecycle.Store, agentID string) policysvc.Decision {
	t.Helper()
	rel, err := ls.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ev, err := policysvc.NewEvaluator(context.Background(), policy.Files, rel.Overrides())
	if err != nil {
		t.Fatal(err)
	}
	d, err := ev.Eval(context.Background(), map[string]any{"channel": "mcp_gateway", "direction": "tool_call",
		"principal": map[string]any{"type": "agent", "id": agentID}, "destination": map[string]any{"app_id": "erp", "sanction": "sanctioned", "region": "ID"},
		"content": map[string]any{"sensitivity": "internal", "classes": []any{}}, "agent": map[string]any{"agent_id": agentID, "tool": "erp.read", "tool_risk": "low", "registered": true}})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestRegistry(t *testing.T) {
	s, ls, db := setup(t)
	ctx := context.Background()

	a, err := s.Register(ctx, "budi@bankmega.com", agent("invoice-bot", "budi@bankmega.com", "finance", "spiffe://bank.local/ns/finance/sa/invoice-bot"))
	if err != nil || a.Status != "active" {
		t.Fatalf("register with owner: %+v %v", a, err)
	}
	if d := decide(t, ls, "invoice-bot"); d.Action != "allow" {
		t.Errorf("active agent: %+v", d)
	}

	// No owner: quarantined at once, and the PDP blocks it even though the PEP claims registration.
	orphan, err := s.Register(ctx, "budi@bankmega.com", agent("orphan-bot", "", "finance", "spiffe://bank.local/ns/finance/sa/orphan"))
	if err != nil || orphan.Status != "quarantined" || *orphan.StatusReason != NoOwner {
		t.Fatalf("owner-less agent: %+v %v", orphan, err)
	}
	if d := decide(t, ls, "orphan-bot"); d.Action != "block" || !slices.Contains(d.ReasonCodes, "AGENT_NOT_ACTIVE") {
		t.Errorf("quarantined agent: %+v", d)
	}
	if _, err := s.SetStatus(ctx, "budi@bankmega.com", "orphan-bot", "active", "please"); !errors.Is(err, ErrInvalid) {
		t.Errorf("activated without owner: %v", err)
	}
	o := agent("orphan-bot", "ani@bankmega.com", "finance", "spiffe://bank.local/ns/finance/sa/orphan")
	if a, err := s.Update(ctx, "budi@bankmega.com", o); err != nil || a.Status != "active" {
		t.Errorf("owner added: %+v %v", a, err)
	}

	// FR-AGT-2: workload identities only, never shared, never a user account.
	for name, bad := range map[string]Agent{
		"email as client": func() Agent {
			x := agent("x1", "budi@bankmega.com", "finance", "")
			x.Identity = Identity{"oidc_client", "budi@bankmega.com"}
			return x
		}(),
		"user name as client": func() Agent {
			x := agent("x2", "budi@bankmega.com", "finance", "")
			x.Identity = Identity{"oidc_client", "svc-shared"}
			return x
		}(),
		"user credential": func() Agent {
			x := agent("x3", "budi@bankmega.com", "finance", "")
			x.Identity = Identity{"user", "budi"}
			return x
		}(),
		"reused identity": agent("x4", "budi@bankmega.com", "finance", "spiffe://bank.local/ns/finance/sa/invoice-bot"),
		"bad spiffe":      agent("x5", "budi@bankmega.com", "finance", "https://bank.local/x"),
		"bad managed": func() Agent {
			x := agent("x6", "budi@bankmega.com", "finance", "")
			x.Identity = Identity{"managed_identity", "my-laptop"}
			return x
		}(),
		"duplicate tool": func() Agent {
			x := agent("x7", "budi@bankmega.com", "finance", "spiffe://bank.local/x7")
			x.Tools = append(x.Tools, x.Tools[0])
			return x
		}(),
	} {
		if _, err := s.Register(ctx, "budi@bankmega.com", bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	ok := agent("gcp-bot", "ani@bankmega.com", "retail", "")
	ok.Identity = Identity{"managed_identity", "summarizer@bank-prod.iam.gserviceaccount.com"}
	if _, err := s.Register(ctx, "ani@bankmega.com", ok); err != nil {
		t.Errorf("GCP service account: %v", err)
	}

	// Owner deactivated in the IdP (SCIM): the next reconcile quarantines the agent.
	if _, err := db.Exec(ctx, "UPDATE identity.users SET active = false WHERE user_name = 'budi@bankmega.com'"); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Reconcile(ctx); err != nil || n != 1 {
		t.Errorf("reconcile: %d %v", n, err)
	}
	if a, _ := s.Get(ctx, "invoice-bot"); a.Status != "quarantined" {
		t.Errorf("agent of a deactivated owner: %s", a.Status)
	}
	if n, _ := s.Reconcile(ctx); n != 0 {
		t.Error("reconcile not idempotent")
	}

	// Shadow agents from traffic.
	ev := func(agentID string) events.Event {
		return events.Event{EventID: "x", TS: time.Now().UTC().Format(time.RFC3339Nano), AgentID: agentID}
	}
	for _, id := range []string{"shadow-bot", "shadow-bot", "invoice-bot", "test-bot"} {
		if err := s.Handle(ctx, ev(id), nil); err != nil {
			t.Fatal(err)
		}
	}
	pending, _ := s.Discovered(ctx, "pending")
	if len(pending) != 2 || pending[0].AgentID == "invoice-bot" {
		t.Errorf("review queue: %+v", pending)
	}
	if err := s.Dismiss(ctx, "ani@bankmega.com", "test-bot", "load test harness"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(ctx, "ani@bankmega.com", agent("shadow-bot", "ani@bankmega.com", "retail", "spiffe://bank.local/ns/retail/sa/shadow")); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Discovered(ctx, "pending"); len(p) != 0 {
		t.Errorf("queue after register/dismiss: %+v", p)
	}

	// Ticket AC: "agents without owner & policy" is measurable.
	noTools := agent("chat-helper", "ani@bankmega.com", "retail", "spiffe://bank.local/ns/retail/sa/chat")
	noTools.Tools = nil
	if _, err := s.Register(ctx, "ani@bankmega.com", noTools); err != nil {
		t.Fatal(err)
	}
	sum, err := s.Summarize(ctx)
	if err != nil || !slices.Equal(sum.WithoutOwnerOrPolicy, []string{"chat-helper"}) || sum.ByStatus["quarantined"] != 1 || sum.PendingReview != 0 {
		t.Errorf("summary: %+v %v", sum, err)
	}

	// Ticket AC: every registry change is in the audit log.
	rows, _ := db.Query(ctx, "SELECT actor || ':' || action FROM audit.audit_log WHERE action LIKE 'agent.%' ORDER BY seq")
	var got []string
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		got = append(got, a)
	}
	want := []string{"budi@bankmega.com:agent.register", "budi@bankmega.com:agent.register", "budi@bankmega.com:agent.update",
		"ani@bankmega.com:agent.register", "system:agent.quarantine", "ani@bankmega.com:agent.discovered.dismiss",
		"ani@bankmega.com:agent.register", "ani@bankmega.com:agent.register"}
	if !slices.Equal(got, want) {
		t.Errorf("audit:\n got %v\nwant %v", got, want)
	}
}

// ABAC: agent owners write only within the business units of their binding.
func TestBusinessUnitScope(t *testing.T) {
	s, _, _ := setup(t)
	now := func() time.Time { return time.Now() }
	auth, _ := authztest.New(map[string]authztest.User{
		"ani@bankmega.com": {Bindings: []authz.Binding{{Role: "agent_owner", Attrs: authz.Attrs{BusinessUnits: []string{"retail"}}}}},
	}, now, nil)
	rt := authz.NewRouter(auth)
	Routes(rt, s, now)
	srv := httptest.NewServer(rt)
	defer srv.Close()
	do := func(method, path, body string) int {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer ani@bankmega.com")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	body := func(unit, ref string) string {
		return fmt.Sprintf(`{"agent_id": "retail-bot", "name": "Retail bot", "owner": "ani@bankmega.com", "business_unit": %q, "purpose": "FAQ",
			"environment": "prod", "identity": {"type": "spiffe", "ref": %q}, "tools": [{"name": "kb.search", "risk": "low"}], "risk_tier": "low"}`, unit, ref)
	}
	if code := do("POST", "/agents", body("treasury", "spiffe://bank.local/t")); code != 403 {
		t.Errorf("register in another unit: %d", code)
	}
	if code := do("POST", "/agents", body("retail", "spiffe://bank.local/r")); code != 201 {
		t.Fatalf("register in own unit: %d", code)
	}
	if code := do("PUT", "/agents/retail-bot", body("treasury", "spiffe://bank.local/r")); code != 403 {
		t.Errorf("move to another unit: %d", code)
	}
	if code := do("POST", "/agents/retail-bot/status", `{"status": "suspended", "reason": "incident INC-9"}`); code != 200 {
		t.Errorf("suspend own agent: %d", code)
	}
}
