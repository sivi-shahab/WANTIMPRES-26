package riskcal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	neturl "net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-policy-agent/opa/v1/rego"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/events"
	"wantimpres26/internal/incident"
	"wantimpres26/internal/lifecycle"
	"wantimpres26/internal/policysvc"
	"wantimpres26/internal/tuning"
	"wantimpres26/policy"
)

const tenant = "6f1c1d1e-2a7b-4c3d-9e8f-0a1b2c3d4e5f"

func setup(t *testing.T) (*Store, *pgxpool.Pool) {
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
	name := fmt.Sprintf("riskcal_test_%d", time.Now().UnixNano()%1e9)
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
	ls, err := lifecycle.Open(ctx, db, tenant, policy.Files)
	if err != nil {
		t.Fatal(err)
	}
	s := &Store{DB: db, Tenant: tenant, Policies: ls, FS: policy.Files}
	if err := Open(ctx, s); err != nil {
		t.Fatal(err)
	}
	if _, err := incident.Open(ctx, db, al, []byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	if err := tuning.Open(ctx, db); err != nil {
		t.Fatal(err)
	}
	return s, db
}

// resolved stores an incident with one event and the path the SOC took to resolve it.
func resolved(t *testing.T, db *pgxpool.Pool, e events.Event, tp bool, at time.Time) {
	t.Helper()
	ctx := context.Background()
	id := uuid.NewString()
	raw, _ := json.Marshal(e)
	_, err := db.Exec(ctx, `INSERT INTO incident.incidents (id, tenant_id, dedup_key, title, state, severity, max_risk, event_count, first_event_at,
		last_event_at, resolved_at, dek_wrapped) VALUES ($1, $2, $3, 't', 'Resolved', 'medium', 50, 1, $4, $4, $4, '\x00')`, id, tenant, id, at)
	if err == nil {
		_, err = db.Exec(ctx, "INSERT INTO incident.incident_events (incident_id, event_id, ts, risk_score, event) VALUES ($1, $2, $3, 50, $4)", id, e.EventID, at, raw)
	}
	path := [][2]string{{"New", "Triaged"}, {"Triaged", "Investigating"}, {"Investigating", "Resolved"}}
	if tp {
		path = [][2]string{{"New", "Triaged"}, {"Triaged", "Investigating"}, {"Investigating", "Contained"}, {"Contained", "Resolved"}}
	}
	for _, p := range path {
		if err == nil {
			_, err = db.Exec(ctx, "INSERT INTO incident.transitions (incident_id, at, actor, from_state, to_state, note) VALUES ($1, $2, 'soc1', $3, $4, 'n')", id, at, p[0], p[1])
		}
	}
	if err != nil {
		t.Fatal(err)
	}
}

func event(sanction, sensitivity string, injection float64) events.Event {
	return events.Event{EventID: uuid.NewString(), TenantID: tenant, TS: "2026-09-01T00:00:00Z", TraceID: "0123456789abcdef0123456789abcdef",
		Channel: "ai_gateway", Direction: "request", PrincipalID: "p", PrincipalType: "user", AppID: "some-ai", Action: "allow",
		ReasonCodes: []string{}, PolicyVersion: "x", RiskVersion: "risk-1", Classes: []events.Class{}, ContentHash: "h",
		Sanction: sanction, Region: "ID", Sensitivity: sensitivity, InjectionScore: &injection}
}

// TestCalibration (ticket 25 AC): verdicts of resolved incidents propose new weights; a version goes live only after
// it was simulated, submitted and approved by someone else, and then ships in the policy release.
func TestCalibration(t *testing.T) {
	s, db := setup(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	if _, err := s.Propose(ctx, "analyst", now); !errors.Is(err, ErrTooFew) {
		t.Fatalf("no verdicts: %v", err)
	}
	// What the SOC confirmed: data going to unsanctioned AI. What it dismissed: injection-looking text to the
	// sanctioned assistant, which the initial weights score about as high.
	sens := []string{"internal", "confidential", "restricted"}
	for i := range 50 {
		resolved(t, db, event("unsanctioned", sens[i%3], 0.1*float64(i%3)), true, now.AddDate(0, 0, -10-i%30))
	}
	for i := range 40 {
		resolved(t, db, event("sanctioned", sens[i%2], 0.6+0.1*float64(i%4)), false, now.AddDate(0, 0, -10-i%30))
	}
	// An analyst's class label overrides the incident verdict for its event.
	flip := event("unsanctioned", "restricted", 0)
	resolved(t, db, flip, true, now.AddDate(0, 0, -3))
	if _, err := db.Exec(ctx, "INSERT INTO tuning.labels (tenant_id, event_id, class, tp, labeled_by, labeled_at) VALUES ($1, $2, 'PII_ID.NIK', false, 'soc2', now())", tenant, flip.EventID); err != nil {
		t.Fatal(err)
	}
	labels, err := s.Labels(ctx, now.AddDate(0, -3, 0), now)
	if err != nil || len(labels) != 91 || labels[len(labels)-1].TP {
		t.Fatalf("labels: %d %v", len(labels), err)
	}

	v, err := s.Propose(ctx, "analyst", now)
	if err != nil {
		t.Fatal(err)
	}
	w := weightsOf(v.Config)
	sum := 0.0
	for _, x := range w {
		sum += x
	}
	// dest and attack vary in the verdicts: dest up, attack down; agency and volume never vary: unchanged.
	if v.State != "draft" || v.Config["version"] != "risk-cal-1" || w[1] <= 0.20 || w[2] >= 0.15 || w[3] != 0.15 || w[4] != 0.10 || sum < 0.999999 || sum > 1.000001 {
		t.Fatalf("proposal %+v weights %v", v.Config, w)
	}
	if err := s.Submit(ctx, "analyst", 1); !errors.Is(err, ErrState) {
		t.Errorf("submitted without simulation: %v", err)
	}

	r, err := s.Simulate(ctx, "analyst", 1, now)
	if err != nil {
		t.Fatal(err)
	}
	gap := func(k string) float64 { return r.MeanScore[k][0] - r.MeanScore[k][1] }
	if r.Events != 91 || r.Labelled != 91 || gap("candidate") <= gap("current") {
		t.Errorf("report %+v", r)
	}
	tp, fp := 0, 0
	for _, b := range severityBands {
		tp += r.Verdicts["candidate"][b][0]
		fp += r.Verdicts["candidate"][b][1]
	}
	if tp != 50 || fp != 41 {
		t.Errorf("verdicts by band: %v", r.Verdicts)
	}
	t.Logf("current: mean TP %.1f FP %.1f, bands %v; candidate: mean TP %.1f FP %.1f, bands %v; moved %v",
		r.MeanScore["current"][0], r.MeanScore["current"][1], r.Severity["current"], r.MeanScore["candidate"][0], r.MeanScore["candidate"][1], r.Severity["candidate"], r.Moved)

	if err := s.Submit(ctx, "analyst", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(ctx, "analyst", 1); !errors.Is(err, ErrFourEyes) {
		t.Errorf("author approved: %v", err)
	}
	n, err := s.Approve(ctx, "ciso", 1)
	if err != nil {
		t.Fatal(err)
	}
	rel, _ := s.Policies.Latest(ctx)
	cfg, _ := rel.Data["wantimpres26.risk.config"].(map[string]any)
	if rel.Number != n || cfg["version"] != "risk-cal-1" {
		t.Fatalf("release %d: %v", rel.Number, rel.Data["wantimpres26.risk.config"])
	}
	// Decisions now carry the calibrated version; a later release cut by another module keeps it.
	pq, err := policysvc.Query(ctx, policy.Files, rel.Overrides(), "data.wantimpres26.decision.result.risk_version")
	if err != nil {
		t.Fatal(err)
	}
	in, _ := flip.PDPInput()
	if rs, err := pq.Eval(ctx, rego.EvalInput(in)); err != nil || rs[0].Expressions[0].Value != "risk-cal-1" {
		t.Errorf("decision risk_version: %v %v", rs, err)
	}
	tx, _ := db.Begin(ctx)
	n2, err := s.Policies.CutRelease(ctx, tx, "catalog", "app status change")
	_ = tx.Commit(ctx)
	rel, _ = s.Policies.Latest(ctx)
	if err != nil || rel.Number != n2 || rel.Data["wantimpres26.risk.config"] == nil {
		t.Errorf("later release lost the weights: %v", err)
	}

	// A config the bundle builder would refuse never becomes a version.
	bad := clone(v.Config)
	bad["weights"].(map[string]any)["sens"] = 0.9
	if _, err := s.Create(ctx, "analyst", bad); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid config: %v", err)
	}
	var actions []string
	rows, _ := db.Query(ctx, "SELECT action FROM audit.audit_log WHERE action LIKE 'riskcal.%' ORDER BY seq")
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	if fmt.Sprint(actions) != "[riskcal.version.propose riskcal.version.simulate riskcal.version.submit riskcal.version.approve]" {
		t.Errorf("audit %v", actions)
	}
}

func TestBlend(t *testing.T) {
	cur := [6]float64{0.30, 0.20, 0.15, 0.15, 0.10, 0.10}
	// Only dest and attack vary; the fit says dest matters three times attack.
	got := blend(cur, [6]float64{0, 3, 1, 0, 0, 0}, [6]bool{false, true, true, false, false, false})
	if got != [6]float64{0.30, 0.23, 0.12, 0.15, 0.10, 0.10} {
		t.Errorf("blend %v", got)
	}
	if blend(cur, [6]float64{-1, -1, -1, -1, -1, -1}, [6]bool{true, true, true, true, true, true}) != cur {
		t.Error("no positive coefficient must keep the weights")
	}
}
