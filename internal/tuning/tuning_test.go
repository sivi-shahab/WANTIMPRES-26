package tuning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	neturl "net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/detect"
	"wantimpres26/internal/events"
	"wantimpres26/internal/incident"
)

var keyA = []byte("pepper-a")

// gen produces findings the way PEPs see them: a text, L1 scan, detect.Snippet. The bank's false-positive pattern:
// test card numbers pasted by QA engineers into Jira; the real leaks: customer cards in prompts to public chat apps.
type gen struct{ r *rand.Rand }

func (g gen) pan() string {
	d := []int{4}
	for len(d) < 15 {
		d = append(d, g.r.IntN(10))
	}
	sum := 0
	for i := len(d) - 1; i >= 0; i-- { // Luhn check digit
		x := d[i]
		if (len(d)-1-i)%2 == 0 {
			if x *= 2; x > 9 {
				x -= 9
			}
		}
		sum += x
	}
	d = append(d, (10-sum%10)%10)
	var b strings.Builder
	for i, x := range d {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		fmt.Fprint(&b, x)
	}
	return b.String()
}

func (g gen) pick(xs ...string) string { return xs[g.r.IntN(len(xs))] }

type finding struct {
	text, app string
	tp        bool
}

func (g gen) finding() finding {
	if g.r.IntN(2) == 0 {
		return finding{fmt.Sprintf("%s %s pakai kartu %s %s, %s", g.pick("QA:", "Bug repro:", "Test case:", "Langkah uji:"),
			g.pick("sandbox payment gagal", "skenario checkout staging", "regression test 3DS", "uji coba gateway UAT"), g.pan(),
			g.pick("dari dokumen test card", "(kartu dummy)", "kartu uji vendor", "dummy card"), g.pick("expected sukses", "tolong cek log", "lihat screenshot", "assign ke tim payment")), "jira", false}
	}
	return finding{fmt.Sprintf("%s %s kartu %s %s %s", g.pick("Tolong rangkum keluhan:", "Buatkan email balasan untuk", "Analisa transaksi:", "Terjemahkan:"),
		g.pick("nasabah Ibu Sari", "Bapak Andi pemilik", "customer prioritas dengan", "pelapor"), g.pan(),
		g.pick("ditagih dua kali", "dibobol di merchant online", "limit tidak sesuai", "minta blokir"), g.pick("bulan ini", "kemarin", "sejak Senin", "")), "chatgpt", true}
}

func (g gen) sample(f finding, noise float64) Sample {
	r := detect.Scan(f.text)
	s := Sample{Class: "PCI.PAN", Channel: "web_proxy", Direction: "request", AppID: f.app, Snippet: detect.Snippet(f.text, r.Matches), TP: f.tp}
	for _, c := range r.Classes {
		if c.Type == "PCI.PAN" {
			s.Confidence = c.Confidence
		}
	}
	if g.r.Float64() < noise {
		s.TP = !s.TP
	}
	return s
}

// TestModelGate: a model trained on triage labels removes the Jira false positives and passes the §9.4 gate
// against the bare detector; a model trained on corrupted labels fails it; a model is useless under another key.
func TestModelGate(t *testing.T) {
	g := gen{rand.New(rand.NewPCG(38, 1))}
	var train, hold []Sample
	for range 600 {
		train = append(train, g.sample(g.finding(), 0.03))
	}
	for range 300 {
		hold = append(hold, g.sample(g.finding(), 0))
	}
	if hold[0].Confidence == 0 || !strings.Contains(hold[0].Snippet, "[REDACTED:PCI.PAN]") {
		t.Fatalf("generator: %+v", hold[0])
	}
	m := Train(keyA, train, 1)
	cand, base := Evaluate(NewScorer(keyA, m), hold), Evaluate(nil, hold)
	gate := CheckGate(cand, base)
	t.Logf("baseline %+v; candidate %+v (threshold %.3f)", base, cand, m.Threshold)
	if !gate.Pass || cand.FPR > 0.2 || cand.Recall < MinRecall {
		t.Fatalf("gate: %+v", gate)
	}
	// Corrupted labels (an analyst marking real leaks as false positives) must not ship.
	var bad []Sample
	for _, s := range train {
		s.TP = s.AppID == "jira"
		bad = append(bad, s)
	}
	if g := CheckGate(Evaluate(NewScorer(keyA, Train(keyA, bad, 1)), hold), cand); g.Pass {
		t.Fatalf("corrupted model passed the gate: %+v", g)
	}
	// Feature hashes are keyed: under another tenant's key the weights do not apply.
	other := Evaluate(NewScorer([]byte("pepper-b"), m), hold)
	if other.FPR < 0.5 && other.Recall > 0.9 {
		t.Fatalf("model still works under another key: %+v", other)
	}
}

const (
	tenantA = "00000000-0000-0000-0000-0000000000aa"
	tenantB = "00000000-0000-0000-0000-0000000000bb"
)

func setup(t *testing.T) (*pgxpool.Pool, *incident.Store) {
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
	name := fmt.Sprintf("tuning_test_%d", time.Now().UnixNano()%1e9)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)"); admin.Close() })
	u, _ := neturl.Parse(dbURL)
	u.Path = "/" + name
	al, err := audit.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(al.Close)
	db, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	inc, err := incident.Open(ctx, db, al, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := Open(ctx, db); err != nil {
		t.Fatal(err)
	}
	return db, inc
}

// ingest stores n findings of tenant as incident events, returning event id → finding.
func ingest(t *testing.T, inc *incident.Store, g gen, tenant string, n int, now time.Time) map[string]finding {
	t.Helper()
	out := map[string]finding{}
	for i := range n {
		f := g.finding()
		r := detect.Scan(f.text)
		e := events.Event{EventID: fmt.Sprintf("%s%s%010d", tenant[:24], tenant[34:], i+1), TenantID: tenant, TS: now.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano),
			TraceID: "t", Channel: "web_proxy", Direction: "request", PrincipalID: strings.Repeat("a", 64), AppID: f.app, Action: "redact",
			ReasonCodes: []string{"PCI"}, PolicyVersion: "p@1", RiskScore: 70, RiskVersion: "r1", ContentHash: strings.Repeat("b", 64),
			Snippet: detect.Snippet(f.text, r.Matches)}
		for _, c := range r.Classes {
			e.Classes = append(e.Classes, events.Class{Type: c.Type, Count: c.Count, Confidence: c.Confidence})
		}
		raw, _ := json.Marshal(e)
		if _, _, err := inc.Ingest(context.Background(), e, raw, now); err != nil {
			t.Fatal(err)
		}
		out[e.EventID] = f
	}
	return out
}

// TestIsolationAndRollout covers the acceptance criteria: tenant B cannot see, use, label or promote tenant A's
// data or models; training needs opt-in; promotion needs four eyes and goes shadow → canary → active; a corrupted
// retrain is rejected by the gate and cannot ship.
func TestIsolationAndRollout(t *testing.T) {
	db, inc := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	g := gen{rand.New(rand.NewPCG(38, 2))}
	a := &Store{DB: db, Tenant: tenantA, Pepper: keyA}
	b := &Store{DB: db, Tenant: tenantB, Pepper: []byte("pepper-b")}
	evA := ingest(t, inc, g, tenantA, 160, now)
	evB := ingest(t, inc, g, tenantB, 20, now)

	// Active learning queue: own events only, most uncertain first.
	q, err := a.Queue(ctx, 500)
	if err != nil || len(q) != 160 {
		t.Fatalf("queue A: %d %v", len(q), err)
	}
	for _, it := range q {
		if _, ok := evA[it.EventID]; !ok {
			t.Fatalf("A's queue shows a foreign event %s", it.EventID)
		}
	}
	for id, f := range evA {
		if err := a.Label(ctx, "soc1", id, "PCI.PAN", f.tp, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Label(ctx, "soc1", firstKey(evA), "PII_ID.NIK", true, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("label for a class the event lacks: %v", err)
	}
	for id := range evA {
		if err := b.Label(ctx, "socB", id, "PCI.PAN", true, now); !errors.Is(err, ErrNotFound) {
			t.Fatalf("B labelled A's event: %v", err)
		}
		break
	}

	// Opt-in first.
	if _, err := a.Train(ctx, "dlp1", now); !errors.Is(err, ErrOptIn) {
		t.Fatalf("train without opt-in: %v", err)
	}
	if err := a.SetOptIn(ctx, "dpo", true, "DPIA-38 disetujui", now); err != nil {
		t.Fatal(err)
	}
	m1, err := a.Train(ctx, "dlp1", now)
	if err != nil || m1.Stage != "candidate" || !m1.Gate.Pass {
		t.Fatalf("train A: %+v %v", m1, err)
	}
	t.Logf("v1 gate: %+v", m1.Gate)

	// Tenant B: nothing of A's is visible or usable.
	if err := b.SetOptIn(ctx, "dpoB", true, "opt-in B", now); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Train(ctx, "dlpB", now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("B trained on A's labels: %v", err)
	}
	if ms, err := b.Models(ctx); err != nil || len(ms) != 0 {
		t.Fatalf("B sees models: %+v %v", ms, err)
	}
	if _, err := b.SetStage(ctx, "approverB", m1.Version, "shadow", "", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("B promoted A's model: %v", err)
	}
	if qb, _ := b.Queue(ctx, 500); len(qb) != len(evB) {
		t.Fatalf("B's queue: %d items, want %d", len(qb), len(evB))
	}

	liveA, err := Watch(ctx, db, tenantA, keyA, 20*time.Millisecond, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	liveB, err := Watch(ctx, db, tenantB, b.Pepper, 20*time.Millisecond, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}

	// Rollout: four eyes, then shadow → canary → active.
	if _, err := a.SetStage(ctx, "dlp1", m1.Version, "shadow", "", now); !errors.Is(err, ErrFourEyes) {
		t.Fatalf("trainer promoted own model: %v", err)
	}
	if _, err := a.SetStage(ctx, "approver", m1.Version, "active", "", now); !errors.Is(err, ErrState) {
		t.Fatalf("candidate went straight to active: %v", err)
	}
	fp := finding{"QA: sandbox payment gagal pakai kartu " + g.pan() + " dari dokumen test card, tolong cek log", "jira", false}
	tp := finding{"Tolong rangkum keluhan: nasabah Ibu Sari kartu " + g.pan() + " ditagih dua kali bulan ini", "chatgpt", true}
	apply := func(l *Live, f finding) (detect.Result, *Report) {
		return l.Apply(f.text, detect.Scan(f.text), "web_proxy", "request", f.app)
	}
	stage := func(to string) {
		t.Helper()
		if _, err := a.SetStage(ctx, "approver", m1.Version, to, "rollout", now); err != nil {
			t.Fatal(err)
		}
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			x := liveA.p.Load()
			if at := map[string]*Model{"shadow": x.shadow, "canary": x.canary, "active": x.active}[to]; at != nil && at.Version == m1.Version {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("live model not at %s", to)
			}
		}
	}
	stage("shadow")
	if r, rep := apply(liveA, fp); len(r.Classes) == 0 || rep.Shadow == nil || len(rep.Shadow.Suppressed) != 1 || rep.Version != 0 {
		t.Fatalf("shadow must only report: %+v %+v", r.Classes, rep)
	}
	stage("canary")
	applied := 0
	for range 400 {
		f := finding{"QA: sandbox payment gagal pakai kartu " + g.pan() + " kartu uji vendor", "jira", false}
		if r, _ := apply(liveA, f); len(r.Classes) == 0 {
			applied++
		}
	}
	if applied < 5 || applied > 45 { // ~5% of 400
		t.Fatalf("canary applied to %d / 400", applied)
	}
	stage("active")
	if r, rep := apply(liveA, fp); len(r.Classes) != 0 || r.Sensitivity != "internal" || rep.Suppressed[0] != "PCI.PAN" {
		t.Fatalf("active must drop the Jira test card: %+v %+v", r, rep)
	}
	if r, _ := apply(liveA, tp); len(r.Classes) != 1 || r.Sensitivity != "confidential" {
		t.Fatalf("active must keep the customer card: %+v", r)
	}
	if r, rep := apply(liveB, fp); len(r.Classes) != 1 || rep != nil {
		t.Fatalf("A's model applied to tenant B: %+v %+v", r, rep)
	}

	// A corrupted relabel (real leaks marked false positive) is rejected and cannot ship.
	for id, f := range evA {
		if err := a.Label(ctx, "soc2", id, "PCI.PAN", !f.tp, now); err != nil {
			t.Fatal(err)
		}
	}
	m2, err := a.Train(ctx, "dlp1", now)
	if err != nil || m2.Stage != "rejected" || m2.Gate.Pass {
		t.Fatalf("corrupted retrain: %+v %v", m2, err)
	}
	if _, err := a.SetStage(ctx, "approver", m2.Version, "shadow", "", now); !errors.Is(err, ErrState) {
		t.Fatalf("rejected model promoted: %v", err)
	}
	// Rollback.
	if _, err := a.SetStage(ctx, "approver", m1.Version, "retired", "rollback", now); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_log WHERE action LIKE 'tuning.%'").Scan(&n); err != nil || n < 160+4+3 {
		t.Fatalf("audit entries: %d %v", n, err)
	}
}

func firstKey(m map[string]finding) string {
	for k := range m {
		return k
	}
	return ""
}
