package incident

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/authz"
	"wantimpres26/internal/authz/authztest"
	"wantimpres26/internal/events"
)

const tenant = "00000000-0000-0000-0000-000000000001"

func uuid() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func event(principal string, at time.Time, risk int, classes ...string) (events.Event, []byte) {
	e := events.Event{EventID: uuid(), TenantID: tenant, TS: at.UTC().Format(time.RFC3339Nano), TraceID: strings.ReplaceAll(uuid(), "-", ""),
		Channel: "ai_gateway", Direction: "request", PrincipalID: principal, AppID: "chatgpt", Action: "block",
		ReasonCodes: []string{"R"}, MatchedRules: []string{"tpl.x"}, PolicyVersion: "builtin-1", RiskScore: risk, RiskVersion: "risk-1",
		ContentHash: strings.Repeat("b", 64)}
	for _, c := range classes {
		e.Classes = append(e.Classes, events.Class{Type: c, Count: 1})
	}
	raw, _ := json.Marshal(e)
	return e, raw
}

func setup(t *testing.T) (*Store, *audit.Store, *pgxpool.Pool) {
	t.Helper()
	dbURL := os.Getenv("AUDIT_TEST_DATABASE_URL")
	if dbURL == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("AUDIT_TEST_DATABASE_URL must be set in CI")
		}
		t.Skip("no test Postgres")
	}
	ctx := context.Background()
	// A database of its own: go test runs packages in parallel, and internal/audit resets the audit schema.
	admin, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	name := "incident_test_" + strings.ReplaceAll(uuid()[:8], "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	// Registered first, so it runs after the pools below are closed.
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		admin.Close()
	})
	u, err := neturl.Parse(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	dbURL = u.String()
	db, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	al, err := audit.Open(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(al.Close)
	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	s, err := Open(ctx, db, al, kek)
	if err != nil {
		t.Fatal(err)
	}
	return s, al, db
}

// FR-INC-1: same key within 30 minutes of the incident's events joins it; later, another key, or a resolved
// incident opens a new one.
func TestDedupWindow(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	ingest := func(principal string, at time.Time, risk int, classes ...string) (string, bool) {
		t.Helper()
		e, raw := event(principal, at, risk, classes...)
		id, created, err := s.Ingest(ctx, e, raw, at)
		if err != nil {
			t.Fatal(err)
		}
		return id, created
	}

	a, created := ingest("p1", t0, 50, "PCI.PAN")
	if !created {
		t.Fatal("first event did not open an incident")
	}
	if id, created := ingest("p1", t0.Add(29*time.Minute), 50, "PCI.PAN"); id != a || created {
		t.Error("event 29 min later did not join")
	}
	// Sliding: 30 min after the *last* event still joins.
	if id, _ := ingest("p1", t0.Add(59*time.Minute), 50, "PCI.PAN"); id != a {
		t.Error("event within 30 min of the last event did not join")
	}
	if id, created := ingest("p1", t0.Add(90*time.Minute), 50, "PCI.PAN"); id == a || !created {
		t.Error("event 31 min after the last one joined the old incident")
	}
	if id, _ := ingest("p2", t0.Add(time.Minute), 50, "PCI.PAN"); id == a {
		t.Error("other principal joined")
	}
	if id, _ := ingest("p1", t0.Add(time.Minute), 50, "PII_ID.NIK"); id == a {
		t.Error("other class joined")
	}
	if id, _ := ingest("p1", t0.Add(time.Minute), 39, "PCI.PAN"); id != "" {
		t.Error("low-risk event opened or joined an incident")
	}

	// Redelivery of the same event is a no-op.
	e, raw := event("p3", t0, 60, "PCI.PAN")
	id1, _, _ := s.Ingest(ctx, e, raw, t0)
	id2, created2, _ := s.Ingest(ctx, e, raw, t0)
	inc, _ := s.Get(ctx, id1)
	if id1 != id2 || created2 || inc.EventCount != 1 {
		t.Errorf("redelivery: ids %s/%s created %v count %d", id1, id2, created2, inc.EventCount)
	}

	got, _ := s.Get(ctx, a)
	if got.EventCount != 3 || !got.FirstEventAt.Equal(t0) || !got.LastEventAt.Equal(t0.Add(59*time.Minute)) {
		t.Errorf("incident a: count %d first %v last %v", got.EventCount, got.FirstEventAt, got.LastEventAt)
	}

	// A resolved incident does not collect new events.
	r, _ := ingest("p4", t0, 50, "PCI.PAN")
	for _, to := range []State{Triaged, Investigating, Contained, Resolved} {
		if _, err := s.Transition(ctx, r, to, "", "analyst", t0); err != nil {
			t.Fatal(err)
		}
	}
	if id, created := ingest("p4", t0.Add(time.Minute), 50, "PCI.PAN"); id == r || !created {
		t.Error("event joined a resolved incident")
	}
}

// FR-INC-2/7: severity follows the riskiest event, never drops, and a critical escalation tightens the ack SLA.
func TestSeverityAndSLA(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	e, raw := event("p1", t0, 75, "PCI.PAN")
	id, _, _ := s.Ingest(ctx, e, raw, t0)
	inc, _ := s.Get(ctx, id)
	if inc.Severity != "high" || inc.AckDeadline == nil || !inc.AckDeadline.Equal(t0.Add(time.Hour)) {
		t.Fatalf("high: severity %s deadline %v", inc.Severity, inc.AckDeadline)
	}
	e, raw = event("p1", t0.Add(10*time.Minute), 95, "PCI.PAN")
	_, _, _ = s.Ingest(ctx, e, raw, t0.Add(10*time.Minute))
	inc, _ = s.Get(ctx, id)
	if inc.Severity != "critical" || !inc.AckDeadline.Equal(t0.Add(25*time.Minute)) {
		t.Errorf("escalated: severity %s deadline %v, want critical by %v", inc.Severity, inc.AckDeadline, t0.Add(25*time.Minute))
	}
	e, raw = event("p1", t0.Add(11*time.Minute), 45, "PCI.PAN")
	_, _, _ = s.Ingest(ctx, e, raw, t0.Add(11*time.Minute))
	if inc, _ = s.Get(ctx, id); inc.Severity != "critical" {
		t.Errorf("severity dropped to %s", inc.Severity)
	}
	if n, _ := s.Overdue(ctx, t0.Add(26*time.Minute)); n != 1 {
		t.Errorf("overdue = %d, want 1", n)
	}
	if _, err := s.Transition(ctx, id, Triaged, "", "analyst", t0.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	inc, _ = s.Get(ctx, id)
	if n, _ := s.Overdue(ctx, t0.Add(time.Hour)); n != 0 || inc.AcknowledgedAt == nil || !inc.AcknowledgedAt.Equal(t0.Add(30*time.Minute)) {
		t.Errorf("after ack: overdue %d acknowledged_at %v", n, inc.AcknowledgedAt)
	}
	medium, raw := event("p9", t0, 50, "PCI.PAN")
	mid, _, _ := s.Ingest(ctx, medium, raw, t0)
	if m, _ := s.Get(ctx, mid); m.AckDeadline != nil {
		t.Errorf("medium has an ack deadline %v; FR-INC-7 sets none", m.AckDeadline)
	}
	if _, err := s.RaiseSeverity(ctx, id, "high", "x", "analyst", t0); err == nil {
		t.Error("severity lowered")
	}
}

type api struct {
	t   *testing.T
	srv *httptest.Server
}

// do calls the API as user (a token for authztest; "" = no token).
func (a api) do(method, path, user, body string) (int, string) {
	a.t.Helper()
	req, _ := http.NewRequest(method, a.srv.URL+path, strings.NewReader(body))
	if user != "" {
		req.Header.Set("Authorization", "Bearer "+user)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAPITransitionsAndUnmask(t *testing.T) {
	s, al, db := setup(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	auth, _ := authztest.New(map[string]authztest.User{
		"soc1":   authztest.Role("soc_analyst"), // incidents read/write, no unmask
		"ciso1":  authztest.Role("ciso"),        // incidents read only
		"dpo1":   authztest.Role("dpo"),         // unmask
		"nobody": {},
	}, time.Now, func(ctx context.Context, actor, action string, target map[string]any) error {
		_, err := al.Append(ctx, tenant, actor, action, target)
		return err
	})
	rt := authz.NewRouter(auth)
	Routes(rt, s, time.Now)
	a := api{t, httptest.NewServer(rt)}
	defer a.srv.Close()

	e, raw := event("p1", t0, 92, "PII_ID.NIK")
	id, _, _ := s.Ingest(ctx, e, raw, t0)
	eid, err := s.AddRawEvidence(ctx, id, "prompt", []byte("NIK saya 3171234567890001"), t0)
	if err != nil {
		t.Fatal(err)
	}

	if code, _ := a.do("GET", "/incidents", "", ""); code != 401 {
		t.Errorf("no token: %d", code)
	}
	if code, _ := a.do("GET", "/incidents", "nobody", ""); code != 403 {
		t.Errorf("no permission: %d", code)
	}
	if code, body := a.do("GET", "/incidents?severity=critical&state=New", "ciso1", ""); code != 200 || !strings.Contains(body, id) {
		t.Errorf("list: %d %s", code, body)
	}
	if code, body := a.do("GET", "/incidents/"+id, "soc1", ""); code != 200 || strings.Contains(body, "3171234567890001") || !strings.Contains(body, eid) {
		t.Errorf("detail must list evidence without revealing it: %d %s", code, body)
	}

	// Transitions: valid, invalid, labelled-without-note, without write permission.
	steps := []struct {
		to, note, user string
		want           int
	}{
		{"Investigating", "", "soc1", 409}, // New -> Investigating skips Triaged
		{"Triaged", "", "ciso1", 403},      // read-only role
		{"Triaged", "", "soc1", 200},
		{"Closed", "", "soc1", 409}, // duplicate needs a note
		{"Investigating", "", "soc1", 200},
		{"Resolved", "benign", "soc1", 200},
		{"Contained", "", "soc1", 409},
		{"Investigating", "reopen: new evidence", "soc1", 200},
		{"Contained", "", "soc1", 200},
		{"Resolved", "", "soc1", 200},
		{"Closed", "", "soc1", 200},
		{"Triaged", "", "soc1", 409}, // Closed is final
	}
	for i, st := range steps {
		code, body := a.do("POST", "/incidents/"+id+"/transition", st.user, fmt.Sprintf(`{"to": %q, "note": %q}`, st.to, st.note))
		if code != st.want {
			t.Errorf("step %d -> %s: %d %s, want %d", i, st.to, code, body, st.want)
		}
	}
	inc, _ := s.Get(ctx, id)
	if inc.State != Closed || inc.AcknowledgedAt == nil || inc.ClosedAt == nil {
		t.Errorf("final: %+v", inc)
	}

	// Unmask: denied without permission or justification (and recorded), granted with both (and recorded).
	path := "/incidents/" + id + "/evidence/" + eid + "/raw?justification="
	if code, _ := a.do("GET", path+neturl.QueryEscape("investigating incident"), "soc1", ""); code != 403 {
		t.Errorf("unmask without permission: %d", code)
	}
	if code, _ := a.do("GET", path+"x", "dpo1", ""); code != 403 {
		t.Errorf("unmask without justification: %d", code)
	}
	if code, body := a.do("GET", path+neturl.QueryEscape("UU PDP breach assessment INC-7"), "dpo1", ""); code != 200 || body != "NIK saya 3171234567890001" {
		t.Errorf("unmask granted: %d %q", code, body)
	}
	if code, body := a.do("GET", "/incidents/"+id+"/evidence/"+eid, "soc1", ""); code != 200 || strings.Contains(body, "3171") {
		t.Errorf("metadata view: %d %s", code, body)
	}

	var actions []string
	rows, _ := db.Query(ctx, "SELECT actor || ':' || action FROM audit.audit_log ORDER BY seq")
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		actions = append(actions, s)
	}
	// The router records every attempt; the store adds the grant naming the evidence before decrypting.
	want := []string{"soc1:access.sensitive.denied", "dpo1:access.sensitive.denied", "dpo1:access.sensitive", "dpo1:evidence.unmask"}
	got := []string{}
	for _, a := range actions {
		if strings.Contains(a, "unmask") || strings.Contains(a, "access.sensitive") {
			got = append(got, a)
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("unmask audit = %v, want %v", got, want)
	}
	if n := strings.Count(strings.Join(actions, " "), "incident.transition"); n != 7 {
		t.Errorf("%d transitions audited, want 7 (only the successful ones)", n)
	}
	prevSeq, prevHash, entries, err := al.Range(ctx, t0.Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil || audit.Verify(prevSeq, prevHash, entries) != nil {
		t.Errorf("audit chain after incident work: %v %v", err, audit.Verify(prevSeq, prevHash, entries))
	}

	// Raw evidence past its TTL is purged.
	if n, err := s.PurgeExpired(ctx, t0.Add(RawTTL+time.Second)); err != nil || n != 1 {
		t.Errorf("purge: %d %v", n, err)
	}
}
