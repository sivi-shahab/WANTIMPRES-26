package agents

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
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/sdk"

	"wantimpres26/internal/authz"
	"wantimpres26/internal/authz/authztest"
	"wantimpres26/internal/lifecycle"
	"wantimpres26/internal/policysvc"
	"wantimpres26/policy"
)

var digestA = strings.Repeat("a", 64)

func approvalReq(digest string) Approval {
	return Approval{AgentID: "invoice-bot", Server: "erp", Tool: "payments.transfer", ArgsDigest: digest,
		Preview: map[string]any{"recipient": "1234500001", "amount": 850000.0}, ReasonCodes: []string{"INJECTION_THEN_HIGH_TOOL"}}
}

func TestApprovals(t *testing.T) {
	s, _, db := setup(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	if _, err := s.Register(ctx, "budi@bankmega.com", agent("invoice-bot", "budi@bankmega.com", "finance", "spiffe://bank.local/ns/fin/sa/invoice")); err != nil {
		t.Fatal(err)
	}
	notified := make(chan string, 10)
	s.Notify = func(a Approval) { notified <- a.ID }
	allowAll := func(Agent) error { return nil }

	a, err := s.RequestApproval(ctx, approvalReq(digestA), now)
	if err != nil || a.State != "pending" || !a.ExpiresAt.Equal(now.Add(DefaultApprovalTTL)) {
		t.Fatalf("request: %+v %v", a, err)
	}
	// The same call asking again gets the same request, and approvers hear about it once.
	if again, _ := s.RequestApproval(ctx, approvalReq(digestA), now.Add(time.Minute)); again.ID != a.ID {
		t.Errorf("duplicate request %s", again.ID)
	}
	if id := <-notified; id != a.ID || len(notified) != 0 { // Notify runs after commit, once per new request
		t.Errorf("notices: %s +%d", id, len(notified))
	}
	if _, ok, _ := s.ClaimApproval(ctx, "invoice-bot", "erp", "payments.transfer", digestA, now); ok {
		t.Error("pending approval claimed")
	}

	// AC: approvers cannot approve their own agent's actions.
	if _, err := s.DecideApproval(ctx, "budi@bankmega.com", a.ID, true, "", now, allowAll); !errors.Is(err, errSelf) {
		t.Errorf("owner approved: %v", err)
	}
	ok, err := s.DecideApproval(ctx, "sari@bankmega.com", a.ID, true, "verified payee", now.Add(2*time.Minute), allowAll)
	if err != nil || ok.State != "approved" || *ok.DecidedBy != "sari@bankmega.com" {
		t.Fatalf("approve: %+v %v", ok, err)
	}
	if _, err := s.DecideApproval(ctx, "sari@bankmega.com", a.ID, false, "", now, allowAll); !errors.Is(err, ErrConflict) {
		t.Errorf("decided twice: %v", err)
	}
	// Single use, for exactly this call.
	if _, ok, _ := s.ClaimApproval(ctx, "invoice-bot", "erp", "payments.transfer", strings.Repeat("b", 64), now); ok {
		t.Error("claimed for other arguments")
	}
	if id, ok, err := s.ClaimApproval(ctx, "invoice-bot", "erp", "payments.transfer", digestA, now.Add(3*time.Minute)); !ok || id != a.ID || err != nil {
		t.Fatalf("claim: %s %v %v", id, ok, err)
	}
	if _, ok, _ := s.ClaimApproval(ctx, "invoice-bot", "erp", "payments.transfer", digestA, now.Add(3*time.Minute)); ok {
		t.Error("claimed twice")
	}

	// AC: approval expired → the action is refused. Approved but unused past the deadline: no claim.
	b, _ := s.RequestApproval(ctx, approvalReq(digestA), now.Add(4*time.Minute))
	if b.ID == a.ID {
		t.Fatal("used approval reopened")
	}
	_, _ = s.DecideApproval(ctx, "sari@bankmega.com", b.ID, true, "", now.Add(5*time.Minute), allowAll)
	if _, ok, _ := s.ClaimApproval(ctx, "invoice-bot", "erp", "payments.transfer", digestA, b.ExpiresAt); ok {
		t.Error("claimed at the deadline")
	}
	// Pending past the deadline: approving is refused (the timeout was a deny) and the request is expired.
	c, _ := s.RequestApproval(ctx, approvalReq(strings.Repeat("c", 64)), now)
	if _, err := s.DecideApproval(ctx, "sari@bankmega.com", c.ID, true, "", c.ExpiresAt.Add(time.Second), allowAll); !errors.Is(err, ErrExpired) {
		t.Errorf("late approval: %v", err)
	}
	if got, _ := s.GetApproval(ctx, c.ID); got.State != "expired" {
		t.Errorf("late request state %s", got.State)
	}
	// Retrying after the timeout opens a fresh request.
	if d, _ := s.RequestApproval(ctx, approvalReq(digestA), b.ExpiresAt.Add(time.Minute)); d.ID == b.ID || d.State != "pending" {
		t.Errorf("after expiry: %+v", d)
	}

	rows, _ := db.Query(ctx, "SELECT actor || ':' || action FROM audit.audit_log WHERE action LIKE 'approval.%' ORDER BY seq")
	var got []string
	for rows.Next() {
		var x string
		_ = rows.Scan(&x)
		got = append(got, x)
	}
	want := []string{"mcp-gateway:approval.request", "sari@bankmega.com:approval.approve", "mcp-gateway:approval.used",
		"mcp-gateway:approval.request", "sari@bankmega.com:approval.approve", "mcp-gateway:approval.request", "mcp-gateway:approval.request"}
	if !slices.Equal(got, want) {
		t.Errorf("audit:\n got %v\nwant %v", got, want)
	}
}

// The approval and kill APIs: who may do what.
func TestHITLAndKillAPI(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	now := func() time.Time { return time.Now() }
	for _, a := range []Agent{agent("invoice-bot", "budi@bankmega.com", "finance", "spiffe://bank.local/f"), agent("retail-bot", "ani@bankmega.com", "retail", "spiffe://bank.local/r")} {
		if _, err := s.Register(ctx, "budi@bankmega.com", a); err != nil {
			t.Fatal(err)
		}
	}
	fin := []authz.Binding{{Role: "agent_approver", Attrs: authz.Attrs{BusinessUnits: []string{"finance"}}}}
	auth, _ := authztest.New(map[string]authztest.User{
		"sari@bankmega.com": {Bindings: fin},
		"budi@bankmega.com": {Bindings: append(fin, authz.Binding{Role: "agent_owner", Attrs: authz.Attrs{BusinessUnits: []string{"finance"}}})},
		"soc":               authztest.Role("soc_analyst"),
		"ciso":              authztest.Role("ciso"),
		"bg":                {BreakGlass: true, Bindings: []authz.Binding{{Role: "break_glass"}}},
	}, now, nil)
	rt := authz.NewRouter(auth)
	Routes(rt, s, now)
	srv := httptest.NewServer(rt)
	defer srv.Close()
	do := func(user, method, path, body string) (int, map[string]any) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+user)
		req.Header.Set("X-Justification", "incident INC-42 containment")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	fa, _ := s.RequestApproval(ctx, approvalReq(digestA), time.Now())
	ra := approvalReq(digestA)
	ra.AgentID = "retail-bot"
	rb, _ := s.RequestApproval(ctx, ra, time.Now())
	for _, c := range []struct {
		user, id string
		want     int
	}{
		{"budi@bankmega.com", fa.ID, 403}, // owns invoice-bot
		{"sari@bankmega.com", rb.ID, 403}, // retail is outside her binding
		{"soc", fa.ID, 403},               // no agent.approve
		{"sari@bankmega.com", fa.ID, 200},
		{"sari@bankmega.com", fa.ID, 409},
		{"sari@bankmega.com", "apr-nope", 404},
	} {
		if code, _ := do(c.user, "POST", "/approvals/"+c.id+"/approve", `{"note": "ok"}`); code != c.want {
			t.Errorf("%s approves %s: %d, want %d", c.user, c.id, code, c.want)
		}
	}

	// Kills: owner kills own agent; SOC kills tools/apps; global needs agent.kill.global.
	if code, _ := do("budi@bankmega.com", "POST", "/agents/retail-bot/kill", `{"reason": "x"}`); code != 403 {
		t.Errorf("owner kills another unit's agent: %d", code)
	}
	code, k := do("budi@bankmega.com", "POST", "/agents/invoice-bot/kill", `{"reason": "suspicious transfers"}`)
	if code != 201 || k["scope"] != "agent" {
		t.Errorf("owner kill: %d %v", code, k)
	}
	if code, _ := do("soc", "POST", "/kills", `{"scope": "tool", "target": "payments.transfer", "reason": "fraud wave"}`); code != 201 {
		t.Errorf("SOC tool kill: %d", code)
	}
	if code, _ := do("soc", "POST", "/kills", `{"scope": "global", "reason": "x"}`); code != 403 {
		t.Errorf("SOC global via /kills: %d", code)
	}
	if code, _ := do("soc", "POST", "/kills/global", `{"reason": "x"}`); code != 403 {
		t.Errorf("SOC global: %d", code)
	}
	code, g := do("bg", "POST", "/kills/global", `{"reason": "AI incident, all agents stop"}`)
	if code != 201 {
		t.Fatalf("break-glass global kill: %d", code)
	}
	gid := fmt.Sprint(int64(g["id"].(float64)))
	if code, _ := do("soc", "POST", "/kills/"+gid+"/lift", `{}`); code != 403 {
		t.Errorf("SOC lifts global: %d", code)
	}
	if code, _ := do("bg", "POST", "/kills/global/"+gid+"/lift", `{}`); code != 200 {
		t.Errorf("lift global: %d", code)
	}
	ks, _ := s.Kills(ctx, true)
	if len(ks) != 2 {
		t.Errorf("active kills: %+v", ks)
	}
}

// AC (ticket 30): kill switch effective ≤ 10 s, measured end to end on the control-plane side: from the kill
// committing in the registry until a real OPA (the sidecar's bundle plugin, long-polling the bundle server)
// blocks the agent. The gateway then cuts live sessions within one poll (1 s, mcpgw.TestKillSwitch).
func TestKillSwitchPropagation(t *testing.T) {
	s, ls, _ := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := s.Register(ctx, "budi@bankmega.com", agent("invoice-bot", "budi@bankmega.com", "finance", "spiffe://bank.local/f")); err != nil {
		t.Fatal(err)
	}
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
		"keys": map[string]any{policysvc.KeyID: map[string]any{"algorithm": policysvc.Alg,
			"key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}))}},
	})
	opa, err := sdk.New(ctx, sdk.Options{ID: "mcp-gateway", Config: bytes.NewReader(cfg)})
	if err != nil {
		t.Fatal(err)
	}
	defer opa.Stop(ctx)
	in := map[string]any{"channel": "mcp_gateway", "direction": "tool_call", "principal": map[string]any{"type": "agent", "id": "invoice-bot"},
		"destination": map[string]any{"app_id": "erp", "sanction": "sanctioned", "region": "ID"},
		"content":     map[string]any{"sensitivity": "internal", "classes": []any{}}, "agent": map[string]any{"agent_id": "invoice-bot", "tool": "erp.read", "tool_risk": "low"}}
	action := func() string {
		res, err := opa.Decision(ctx, sdk.DecisionOptions{Path: "/wantimpres26/decision/result", Input: in})
		if err != nil {
			return ""
		}
		return res.Result.(map[string]any)["action"].(string)
	}
	for deadline := time.Now().Add(30 * time.Second); action() != "allow" && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
	}

	var lat []time.Duration
	for i := range 10 {
		start := time.Now()
		kill, err := s.SetKill(ctx, "soc", []string{"agent", "global"}[i%2], []string{"invoice-bot", ""}[i%2], "drill")
		if err != nil {
			t.Fatal(err)
		}
		for action() != "block" {
			if time.Since(start) > 30*time.Second {
				t.Fatal("OPA still allowing 30 s after the kill")
			}
			time.Sleep(10 * time.Millisecond)
		}
		lat = append(lat, time.Since(start))
		if _, err := s.LiftKill(ctx, "soc", kill.ID, kill.Scope == "global"); err != nil {
			t.Fatal(err)
		}
		for action() != "allow" {
			time.Sleep(10 * time.Millisecond)
		}
	}
	slices.Sort(lat)
	worst := lat[len(lat)-1]
	t.Logf("kill → OPA blocks over %d kills: p50 %v, max %v; with the gateway's 1 s poll, worst end to end %v", len(lat), lat[len(lat)/2], worst, worst+time.Second)
	if worst+time.Second > 10*time.Second {
		t.Errorf("kill switch took %v (+1 s poll) > 10 s", worst)
	}
}
