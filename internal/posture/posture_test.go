package posture

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/agents"
	"wantimpres26/internal/audit"
	"wantimpres26/internal/catalog"
	"wantimpres26/internal/events"
	"wantimpres26/internal/incident"
	"wantimpres26/internal/ingest"
	"wantimpres26/internal/lifecycle"
	"wantimpres26/policy"
)

const tenant = "00000000-0000-0000-0000-000000000001"

func f(v float64) *float64 { return &v }
func b(v bool) *bool       { return &v }

// direct runs a hand-written query DSL body against the test index: the reconciliation side, independent of
// eventAggs.
func direct(t *testing.T, osURL, index, body string) map[string]any {
	t.Helper()
	resp, err := http.Post(osURL+"/"+index+"/_search", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil || resp.StatusCode != 200 {
		t.Fatalf("direct query: %d %s", resp.StatusCode, raw)
	}
	return out
}

func directCount(t *testing.T, osURL, index, from, to, query string) int64 {
	t.Helper()
	body := fmt.Sprintf(`{"size": 0, "track_total_hits": true, "query": {"bool": {"filter": [
		{"range": {"ts": {"gte": %q, "lt": %q}}}, %s]}}}`, from, to, query)
	res := direct(t, osURL, index, body)
	return int64(res["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64))
}

func sqlInt(t *testing.T, db *pgxpool.Pool, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Ticket 20 AC: every dashboard number matches a direct query to the store it comes from.
func TestReconciliation(t *testing.T) {
	dbURL, osURL := os.Getenv("AUDIT_TEST_DATABASE_URL"), os.Getenv("IT_OPENSEARCH_URL")
	if dbURL == "" || osURL == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("AUDIT_TEST_DATABASE_URL / IT_OPENSEARCH_URL must be set in CI")
		}
		t.Skip("no Postgres/OpenSearch")
	}
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	// Postgres: own database.
	admin, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("posture_test_%d", now.UnixNano()%1e9)
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
	ls, err := lifecycle.Open(ctx, db, tenant, policy.Files)
	if err != nil {
		t.Fatal(err)
	}
	apps, err := catalog.Open(ctx, db, tenant, ls)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := agents.Open(ctx, db, tenant, ls)
	if err != nil {
		t.Fatal(err)
	}
	kek := bytes.Repeat([]byte{7}, 32)
	incidents, err := incident.Open(ctx, db, al, kek)
	if err != nil {
		t.Fatal(err)
	}

	// OpenSearch: own index under the event template, queried only by this test.
	search := &ingest.OpenSearch{URL: osURL, HTTP: &http.Client{Timeout: 30 * time.Second}}
	if err := search.Setup(ctx); err != nil {
		t.Fatal(err)
	}
	index := fmt.Sprintf("%sposturetest%d", ingest.IndexPrefix, now.UnixNano()%1e9)
	t.Cleanup(func() {
		req, _ := http.NewRequest(http.MethodDelete, osURL+"/"+index, nil)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	})

	// The bank has decided on deepseek (blocked) and copilot; chatgpt and an unknown app are undecided.
	reason, blocked, sanctioned := "decided in the AI committee", "blocked", "sanctioned"
	if _, err := apps.Update(ctx, "secadmin", "deepseek", catalog.Patch{Sanction: &blocked, Reason: &reason}); err != nil {
		t.Fatal(err)
	}
	past := now.AddDate(0, 0, -2).Format(time.DateOnly)
	if _, err := apps.Update(ctx, "secadmin", "microsoft-copilot", catalog.Patch{Sanction: &sanctioned, Reason: &reason, ReviewAt: &past}); err != nil {
		t.Fatal(err)
	}

	n := 0
	ev := func(age time.Duration, app, action, sens string, risk int, mut func(*events.Event)) events.Event {
		n++
		e := events.Event{EventID: fmt.Sprintf("00000000-0000-4000-8000-%012d", n), TenantID: tenant, TS: now.Add(-age).Format(time.RFC3339Nano),
			TraceID: strings.Repeat("a", 32), Channel: "ai_gateway", Direction: "request", PrincipalID: fmt.Sprintf("%064d", n%3), AppID: app,
			Action: action, ReasonCodes: []string{}, PolicyVersion: "release-1", RiskScore: risk, RiskVersion: "risk-1", Classes: []events.Class{},
			ContentHash: strings.Repeat("c", 64), Sensitivity: sens, Sanction: "unsanctioned", Region: "US"}
		if mut != nil {
			mut(&e)
		}
		return e
	}
	nik := func(e *events.Event) { e.Classes = []events.Class{{Type: "PII_ID.NIK", Count: 2}} }
	all := []events.Event{
		ev(time.Hour, "deepseek", "block", "confidential", 95, nik),      // decided, sensitive protected
		ev(2*time.Hour, "chatgpt", "allow", "confidential", 45, nil),     // sensitive unprotected
		ev(3*time.Hour, "chatgpt", "redact", "internal", 50, nik),        // sensitive protected
		ev(4*time.Hour, "chatgpt", "allow", "internal", 10, nil),         // plain
		ev(26*time.Hour, "microsoft-copilot", "allow", "public", 5, nil), // decided
		ev(27*time.Hour, "chatgpt", "block", "public", 92, func(e *events.Event) { e.InjectionScore = f(0.9) }),
		ev(28*time.Hour, "chatgpt", "allow", "public", 30, func(e *events.Event) { e.JailbreakScore = f(0.85) }),
		ev(50*time.Hour, "unknown-ai.io", "allow", "internal", 20, func(e *events.Event) { e.AgentID, e.AgentRegistered = "agent-1", b(true) }),
		ev(51*time.Hour, "unknown-ai.io", "allow", "internal", 20, func(e *events.Event) { e.AgentID = "agent-2" }), // registration unknown
		ev(40*24*time.Hour, "chatgpt", "allow", "restricted", 60, nil),                                              // outside 30 d, inside the trend
	}
	var docs []ingest.Doc
	for _, e := range all {
		body, _ := json.Marshal(e)
		docs = append(docs, ingest.Doc{Index: index, ID: e.EventID, Body: body})
		if err := apps.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
		if _, _, err := incidents.Ingest(ctx, e, body, now); err != nil {
			t.Fatal(err)
		}
	}
	if failed, err := search.Bulk(ctx, docs); err != nil || failed != 0 {
		t.Fatalf("bulk: %d %v", failed, err)
	}
	if resp, err := http.Post(osURL+"/"+index+"/_refresh", "application/json", nil); err == nil {
		_ = resp.Body.Close()
	}

	// Exceptions: one expiring within the notice window, one later.
	for i, days := range []int{3, 30} {
		id, err := ls.RequestException(ctx, "dina", lifecycle.Exception{Rules: []string{"tpl.pii-id-to-unsanctioned"},
			Scope: map[string]string{"group": fmt.Sprintf("SG-%d", i)}, Reason: "pilot", ExpiresAt: now.AddDate(0, 0, days)}, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ls.ApproveException(ctx, "bob", id, now); err != nil {
			t.Fatal(err)
		}
	}

	src := Sources{Search: func(ctx context.Context, body []byte) ([]byte, error) {
		resp, err := http.Post(osURL+"/"+index+"/_search", "application/json", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		return io.ReadAll(resp.Body)
	}, Apps: apps, Incidents: incidents, Policies: ls, Agents: reg}
	// Ticket 43: a server seen reaching a provider without the gateway is a finding.
	if _, err := apps.ReportBypass(ctx, "secadmin", []catalog.Bypass{{Server: "10.20.3.7", Domain: "api.openai.com", AppID: "chatgpt",
		Requests: 3, FirstSeen: now.Add(-2 * time.Hour), LastSeen: now.Add(-time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	rep, err := src.Compute(ctx, now)
	if err != nil {
		t.Fatal(err)
	}

	// --- reconcile event domains against hand-written queries ------------------------------------------
	from, to := now.Add(-Window).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)
	match := `{"match_all": {}}`
	sensitive := `{"bool": {"should": [{"exists": {"field": "classes.type"}}, {"terms": {"sensitivity": ["confidential", "restricted"]}}], "minimum_should_match": 1}}`
	attack := `{"bool": {"should": [{"range": {"injection_score": {"gte": 0.8}}}, {"range": {"jailbreak_score": {"gte": 0.8}}}], "minimum_should_match": 1}}`
	and := func(a, b string) string { return fmt.Sprintf(`{"bool": {"filter": [%s, %s]}}`, a, b) }
	want := map[string][2]int64{
		"discovery": {directCount(t, osURL, index, from, to, `{"terms": {"app_id": ["deepseek", "microsoft-copilot"]}}`), directCount(t, osURL, index, from, to, match)},
		"data":      {directCount(t, osURL, index, from, to, and(sensitive, `{"terms": {"action": ["block", "redact", "tokenize", "quarantine", "require_approval"]}}`)), directCount(t, osURL, index, from, to, sensitive)},
		"prompt":    {directCount(t, osURL, index, from, to, and(attack, `{"terms": {"action": ["block", "quarantine", "require_approval"]}}`)), directCount(t, osURL, index, from, to, attack)},
		"agent":     {directCount(t, osURL, index, from, to, `{"term": {"agent_registered": true}}`), directCount(t, osURL, index, from, to, `{"exists": {"field": "agent_id"}}`)},
	}
	// And the known truth of the fixture, so a query bug on both sides cannot hide.
	truth := map[string][2]int64{"discovery": {2, 9}, "data": {2, 3}, "prompt": {1, 2}, "agent": {1, 2}}
	for k, w := range want {
		got := rep.Domains[k]
		if got.Numerator != w[0] || got.Denominator != w[1] || w != truth[k] {
			t.Errorf("%s: dashboard %d/%d, direct %d/%d, fixture %d/%d", k, got.Numerator, got.Denominator, w[0], w[1], truth[k][0], truth[k][1])
		}
	}
	if d := rep.Domains["data"]; d.Score == nil || fmt.Sprintf("%.1f", *d.Score) != "66.7" {
		t.Errorf("data score %v", d.Score)
	}
	var trendEvents int64
	for _, d := range rep.Trend {
		trendEvents += d.Events
	}
	if all90 := directCount(t, osURL, index, now.Add(-TrendWindow).Format(time.RFC3339Nano), to, match); trendEvents != all90 || all90 != 10 || len(rep.Trend) < 90 {
		t.Errorf("trend: %d events over %d days, direct %d", trendEvents, len(rep.Trend), all90)
	}

	// --- reconcile Postgres figures against SQL -----------------------------------------------------------
	open := sqlInt(t, db, "SELECT count(*) FROM incident.incidents WHERE state IN ('New','Triaged','Investigating','Contained')")
	crit := sqlInt(t, db, "SELECT count(*) FROM incident.incidents WHERE severity = 'critical' AND opened_at >= $1", now.Add(-Window))
	if int64(rep.Incidents.Open) != open || int64(rep.Incidents.CriticalOpened) != crit || open == 0 {
		t.Errorf("incidents: dashboard open %d critical %d, SQL %d %d", rep.Incidents.Open, rep.Incidents.CriticalOpened, open, crit)
	}
	var mttd float64
	_ = db.QueryRow(ctx, "SELECT avg(extract(epoch FROM opened_at - first_event_at))::float8 FROM incident.incidents WHERE severity = 'critical' AND opened_at >= $1", now.Add(-Window)).Scan(&mttd)
	if rep.Incidents.MTTDCriticalSec == nil || *rep.Incidents.MTTDCriticalSec != mttd {
		t.Errorf("MTTD: dashboard %v, SQL %v", rep.Incidents.MTTDCriticalSec, mttd)
	}
	activeExc := sqlInt(t, db, "SELECT count(*) FROM policy.exceptions WHERE state = 'active' AND expires_at > $1", now)
	expiring := sqlInt(t, db, "SELECT count(*) FROM policy.exceptions WHERE state = 'active' AND expires_at > $1 AND expires_at <= $2", now, now.Add(lifecycle.ExpiryNotice))
	reviewed := sqlInt(t, db, "SELECT count(*) FROM catalog.overrides WHERE review_at IS NOT NULL")
	overdue := sqlInt(t, db, "SELECT count(*) FROM catalog.overrides WHERE review_at < $1", now.Format(time.DateOnly))
	ackSLA := sqlInt(t, db, "SELECT count(*) FROM incident.incidents WHERE state = 'New' AND ack_deadline IS NOT NULL")
	ackOver := sqlInt(t, db, "SELECT count(*) FROM incident.incidents WHERE state = 'New' AND ack_deadline < $1", now)
	h := rep.Domains["policy_hygiene"]
	if items := activeExc + reviewed + ackSLA; h.Denominator != items || h.Numerator != items-(expiring+overdue+ackOver) || len(rep.ExpiringExceptions) != int(expiring) {
		t.Errorf("hygiene: dashboard %d/%d, SQL items %d bad %d+%d+%d", h.Numerator, h.Denominator, items, expiring, overdue, ackOver)
	}
	usage := sqlInt(t, db, "SELECT coalesce(sum(events), 0) FROM catalog.usage_daily WHERE app_id = 'chatgpt' AND day >= $1", now.AddDate(0, 0, -30))
	if len(rep.ShadowAI) == 0 || rep.ShadowAI[0].ID != "chatgpt" || rep.ShadowAI[0].Usage.Events != usage {
		t.Errorf("shadow AI top: %+v, SQL chatgpt events %d", rep.ShadowAI, usage)
	}
	for _, a := range rep.ShadowAI {
		if a.Decided {
			t.Errorf("decided app %s listed as shadow AI", a.ID)
		}
	}
	if rep.Inventory.NotInCatalog != 1 || rep.Inventory.BySanction["blocked"] != 1 || rep.Inventory.ReviewOverdue != int(overdue) {
		t.Errorf("inventory: %+v", rep.Inventory)
	}
	if last := rep.Metrics[len(rep.Metrics)-1]; len(rep.GatewayBypass) != 1 || last.Value == nil || *last.Value != 1 || last.Target != "0" {
		t.Errorf("gateway bypass: %+v, metric %+v", rep.GatewayBypass, last)
	}
	if rep.Overall == nil || len(rep.Metrics) < 10 || rep.Metrics[0].Value == nil {
		t.Errorf("overall/metrics: %v %+v", rep.Overall, rep.Metrics)
	}
	out, _ := json.Marshal(rep)
	for _, leak := range []string{"3171", "snippet"} {
		if strings.Contains(string(out), leak) {
			t.Errorf("report contains %q", leak)
		}
	}
}
