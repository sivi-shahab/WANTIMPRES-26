// Package riskcal recalibrates the risk weights with SOC triage verdicts (ticket 25, spec FR-RISK-3). Verdicts come
// from how incidents were resolved (contained = true positive, resolved as false positive/benign = false positive),
// overridden per event by the analysts' class labels (ticket 38). A quarterly proposal fits the factor weights to
// those verdicts; any new weight version is replayed against labelled and recent events (severity distribution,
// true/false positives per severity) and goes live only after that simulation and a second person's approval, as
// part of a signed policy release.
package riskcal

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-policy-agent/opa/v1/rego"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/events"
	"wantimpres26/internal/incident"
	"wantimpres26/internal/lifecycle"
	"wantimpres26/internal/policysvc"
	"wantimpres26/internal/tenantdb"
)

//go:embed schema.sql
var schemaSQL string

var (
	ErrNotFound   = lifecycle.ErrNotFound
	ErrInvalid    = lifecycle.ErrInvalid
	ErrState      = lifecycle.ErrState
	ErrFourEyes   = lifecycle.ErrFourEyes
	ErrTooFew     = errors.New("too few triage verdicts to calibrate")
	factorNames   = []string{"sens", "dest", "attack", "agency", "volume", "ident"}
	severityBands = []string{"low", "medium", "high", "critical"}
)

// Labels needed for a proposal: below that the fit is noise.
const (
	MinLabels   = 60
	MinPerClass = 20
	// Shrink: a proposal moves the weights of factors the labels say something about halfway to the fit.
	Shrink = 0.5
)

type Store struct {
	DB       *pgxpool.Pool
	Tenant   string
	Policies *lifecycle.Store
	FS       fs.FS                 // the policy engine (wantimpres26/policy), for the built-in config and simulation
	Source   lifecycle.EventSource // recent decision events for the severity distribution; nil = labelled only
}

// Open applies the schema and puts the active version into every policy release.
func Open(ctx context.Context, s *Store) error {
	if _, err := s.DB.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("apply riskcal schema: %w", err)
	}
	if err := tenantdb.Isolate(ctx, s.DB, "riskcal.versions"); err != nil {
		return err
	}
	s.Policies.AddExtra(func(ctx context.Context, tx pgx.Tx) (policysvc.Overrides, error) {
		var cfg map[string]any
		err := tx.QueryRow(ctx, "SELECT config FROM riskcal.versions WHERE tenant_id = $1 AND state = 'active'", s.Tenant).Scan(&cfg)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // the built-in config
		}
		return policysvc.Overrides{"wantimpres26.risk.config": cfg}, err
	})
	return nil
}

// Version is one weight version.
type Version struct {
	Version     int            `json:"version"`
	State       string         `json:"state"`
	Config      map[string]any `json:"config"`
	Basis       map[string]any `json:"basis,omitempty"`
	Report      *Report        `json:"report,omitempty"`
	Author      string         `json:"author"`
	Approver    string         `json:"approver,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	ActivatedAt *time.Time     `json:"activated_at,omitempty"`
}

const cols = "version, state, config, basis, report, author, coalesce(approver, ''), created_at, activated_at"

func scan(r pgx.Row) (Version, error) {
	var v Version
	err := r.Scan(&v.Version, &v.State, &v.Config, &v.Basis, &v.Report, &v.Author, &v.Approver, &v.CreatedAt, &v.ActivatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}

func (s *Store) Versions(ctx context.Context) ([]Version, error) {
	rows, err := s.DB.Query(ctx, "SELECT "+cols+" FROM riskcal.versions WHERE tenant_id = $1 ORDER BY version DESC", s.Tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Current is the config decisions use now: the active version, else the built-in one.
func (s *Store) Current(ctx context.Context) (map[string]any, error) {
	var cfg map[string]any
	err := s.DB.QueryRow(ctx, "SELECT config FROM riskcal.versions WHERE tenant_id = $1 AND state = 'active'", s.Tenant).Scan(&cfg)
	if !errors.Is(err, pgx.ErrNoRows) {
		return cfg, err
	}
	raw, err := fs.ReadFile(s.FS, "wantimpres26/risk/config/data.json")
	if err == nil {
		err = json.Unmarshal(raw, &cfg)
	}
	return cfg, err
}

// --- verdicts and the fit -------------------------------------------------------------------------------------

// Labelled is an incident event with the SOC's verdict.
type Labelled struct {
	Event events.Event
	TP    bool
}

// Labels are the verdicts on events of incidents resolved in [from, to).
func (s *Store) Labels(ctx context.Context, from, to time.Time) ([]Labelled, error) {
	rows, err := s.DB.Query(ctx, `
		WITH verdict AS (
		  SELECT i.id, CASE
		    WHEN EXISTS (SELECT 1 FROM incident.transitions t WHERE t.incident_id = i.id AND t.to_state = 'Contained') THEN true
		    WHEN EXISTS (SELECT 1 FROM incident.transitions t WHERE t.incident_id = i.id AND t.from_state = 'Investigating' AND t.to_state = 'Resolved') THEN false
		  END AS tp
		  FROM incident.incidents i
		  WHERE i.tenant_id = $1 AND i.state IN ('Resolved', 'Closed') AND i.resolved_at >= $2 AND i.resolved_at < $3)
		SELECT ie.event, coalesce(l.tp, v.tp)
		FROM incident.incident_events ie JOIN verdict v ON v.id = ie.incident_id
		LEFT JOIN (SELECT event_id, bool_or(tp) AS tp FROM tuning.labels WHERE tenant_id = $1 GROUP BY event_id) l ON l.event_id = ie.event_id
		WHERE coalesce(l.tp, v.tp) IS NOT NULL
		ORDER BY ie.ts`, s.Tenant, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Labelled
	for rows.Next() {
		var raw []byte
		var x Labelled
		if err := rows.Scan(&raw, &x.TP); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &x.Event); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// risk evaluates data.wantimpres26.risk with the latest release, its risk config optionally replaced.
func (s *Store) risk(ctx context.Context, cfg map[string]any) (rego.PreparedEvalQuery, error) {
	rel, err := s.Policies.Latest(ctx)
	if err != nil {
		return rego.PreparedEvalQuery{}, err
	}
	ov := rel.Overrides()
	if cfg != nil {
		ov["wantimpres26.risk.config"] = cfg
	}
	return policysvc.Query(ctx, s.FS, ov, "data.wantimpres26.risk")
}

type scored struct {
	score   int
	factors [6]float64
}

func eval(ctx context.Context, pq rego.PreparedEvalQuery, e events.Event) (scored, bool) {
	in, ok := e.PDPInput()
	if !ok {
		return scored{}, false
	}
	rs, err := pq.Eval(ctx, rego.EvalInput(in))
	if err != nil || len(rs) != 1 {
		return scored{}, false
	}
	m, _ := rs[0].Expressions[0].Value.(map[string]any)
	out := scored{score: int(num(m["score"]))}
	f, _ := m["factors"].(map[string]any)
	for i, k := range factorNames {
		out.factors[i] = num(f[k])
	}
	return out, true
}

func num(v any) float64 {
	switch x := v.(type) {
	case json.Number:
		f, _ := x.Float64()
		return f
	case float64:
		return x
	case int:
		return float64(x)
	}
	return 0
}

// Propose fits the factor weights to the verdicts of the last quarter and stores the result as a draft. Factors the
// verdicts cannot speak to (constant across them) keep their weight; the others move halfway (Shrink) to the
// fitted share of the weight they hold together.
func (s *Store) Propose(ctx context.Context, actor string, now time.Time) (Version, error) {
	labels, err := s.Labels(ctx, now.AddDate(0, -3, 0), now)
	if err != nil {
		return Version{}, err
	}
	cur, err := s.Current(ctx)
	if err != nil {
		return Version{}, err
	}
	pq, err := s.risk(ctx, nil)
	if err != nil {
		return Version{}, err
	}
	var xs [][6]float64
	var ys []bool
	tp := 0
	for _, l := range labels {
		if sc, ok := eval(ctx, pq, l.Event); ok {
			xs, ys = append(xs, sc.factors), append(ys, l.TP)
			if l.TP {
				tp++
			}
		}
	}
	if len(xs) < MinLabels || tp < MinPerClass || len(xs)-tp < MinPerClass {
		return Version{}, fmt.Errorf("%w: %d verdicts (%d true positive), need %d with %d of each", ErrTooFew, len(xs), tp, MinLabels, MinPerClass)
	}
	curW := weightsOf(cur)
	coef := fit(xs, ys)
	newW := blend(curW, coef, varying(xs))
	cfg := clone(cur)
	w := map[string]any{}
	for i, k := range factorNames {
		w[k] = newW[i]
	}
	cfg["weights"] = w
	basis := map[string]any{"verdicts": len(xs), "true_positives": tp, "coefficients": coefMap(coef), "previous_weights": cur["weights"],
		"window": map[string]any{"from": now.AddDate(0, -3, 0), "to": now}}
	return s.create(ctx, actor, "riskcal.version.propose", cfg, basis)
}

// Create stores a hand-made config as a draft (weights, levels or override scores changed by an analyst).
func (s *Store) Create(ctx context.Context, actor string, cfg map[string]any) (Version, error) {
	return s.create(ctx, actor, "riskcal.version.create", cfg, nil)
}

func (s *Store) create(ctx context.Context, actor, action string, cfg, basis map[string]any) (Version, error) {
	if err := s.validate(ctx, cfg); err != nil {
		return Version{}, err
	}
	var v Version
	err := s.change(ctx, actor, action, func(tx pgx.Tx) (map[string]any, error) {
		var n int
		if err := tx.QueryRow(ctx, "SELECT coalesce(max(version), 0) + 1 FROM riskcal.versions WHERE tenant_id = $1", s.Tenant).Scan(&n); err != nil {
			return nil, err
		}
		cfg["version"] = fmt.Sprintf("risk-cal-%d", n)
		var err error
		v, err = scan(tx.QueryRow(ctx, `INSERT INTO riskcal.versions (tenant_id, version, state, config, basis, author) VALUES ($1, $2, 'draft', $3, $4, $5)
			RETURNING `+cols, s.Tenant, n, cfg, basis, actor))
		return map[string]any{"version": n, "weights": cfg["weights"]}, err
	})
	return v, err
}

// validate refuses a config the bundle builder would refuse (risk.config_errors).
func (s *Store) validate(ctx context.Context, cfg map[string]any) error {
	pq, err := policysvc.Query(ctx, s.FS, policysvc.Overrides{"wantimpres26.risk.config": cfg}, "data.wantimpres26.risk.config_errors")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	rs, err := pq.Eval(ctx)
	if err != nil {
		return err
	}
	if len(rs) == 1 {
		if errs, _ := rs[0].Expressions[0].Value.([]any); len(errs) > 0 {
			return fmt.Errorf("%w: %v", ErrInvalid, errs)
		}
	}
	return nil
}

// fit is logistic regression of the verdict on the six factors (gradient descent, small L2).
func fit(xs [][6]float64, ys []bool) [6]float64 {
	var w [6]float64
	var b float64
	n := float64(len(xs))
	for range 3000 {
		var g [6]float64
		var gb float64
		for i, x := range xs {
			z := b
			for j := range x {
				z += w[j] * x[j]
			}
			y := 0.0
			if ys[i] {
				y = 1
			}
			d := 1/(1+math.Exp(-z)) - y
			for j := range x {
				g[j] += d * x[j]
			}
			gb += d
		}
		for j := range w {
			w[j] -= 0.5 * (g[j]/n + 1e-3*w[j])
		}
		b -= 0.5 * gb / n
	}
	return w
}

// varying marks factors that take more than one value among the verdicts.
func varying(xs [][6]float64) [6]bool {
	var out [6]bool
	for j := range out {
		for _, x := range xs {
			if x[j] != xs[0][j] {
				out[j] = true
				break
			}
		}
	}
	return out
}

// blend moves the varying factors' weights toward the fit, keeping their total and every other weight, then rounds
// to two decimals with the rounding left on the largest weight so they sum to 1.
func blend(cur, coef [6]float64, vary [6]bool) [6]float64 {
	mass, pos := 0.0, 0.0
	for j := range cur {
		if vary[j] {
			mass += cur[j]
			pos += max(coef[j], 0)
		}
	}
	out := cur
	if pos > 0 {
		for j := range cur {
			if vary[j] {
				out[j] = (1-Shrink)*cur[j] + Shrink*mass*max(coef[j], 0)/pos
			}
		}
	}
	sum, big := 0.0, 0
	for j := range out {
		out[j] = math.Round(out[j]*100) / 100
		sum += out[j]
		if out[j] > out[big] {
			big = j
		}
	}
	out[big] = math.Round((out[big]+1-sum)*100) / 100
	return out
}

func weightsOf(cfg map[string]any) [6]float64 {
	var w [6]float64
	m, _ := cfg["weights"].(map[string]any)
	for i, k := range factorNames {
		w[i] = num(m[k])
	}
	return w
}

func coefMap(c [6]float64) map[string]float64 {
	m := map[string]float64{}
	for i, k := range factorNames {
		m[k] = math.Round(c[i]*1000) / 1000
	}
	return m
}

func clone(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

// --- simulation -----------------------------------------------------------------------------------------------

// Report compares the current weights with a candidate on the same events (FR-RISK-3 simulation).
type Report struct {
	From      time.Time                    `json:"from"`
	To        time.Time                    `json:"to"`
	Events    int                          `json:"events"`
	Labelled  int                          `json:"labelled"`
	Severity  map[string]map[string]int    `json:"severity"`          // current|candidate → band → events
	Verdicts  map[string]map[string][2]int `json:"verdicts"`          // current|candidate → band → [true, false positives]
	MeanScore map[string][2]float64        `json:"mean_score"`        // current|candidate → [true, false positives]
	Moved     map[string]int               `json:"moved"`             // events whose severity went up / down
	Incidents map[string]int               `json:"incidents_opening"` // events at or above incident.MinRisk
}

// Simulate replays the labelled events of the last quarter and the decision events of the last 30 days under the
// current and the candidate config, stores the report and marks the version simulated.
func (s *Store) Simulate(ctx context.Context, actor string, version int, now time.Time) (Report, error) {
	v, err := s.get(ctx, s.DB, version)
	if err != nil {
		return Report{}, err
	}
	if v.State != "draft" && v.State != "simulated" {
		return Report{}, fmt.Errorf("%w: %s", ErrState, v.State)
	}
	cur, err := s.risk(ctx, nil)
	if err != nil {
		return Report{}, err
	}
	cand, err := s.risk(ctx, v.Config)
	if err != nil {
		return Report{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	labels, err := s.Labels(ctx, now.AddDate(0, -3, 0), now)
	if err != nil {
		return Report{}, err
	}
	var recent []events.Event
	if s.Source != nil {
		if recent, err = s.Source(ctx, now.AddDate(0, 0, -30), now, 100_000); err != nil {
			return Report{}, err
		}
	}
	r := Report{From: now.AddDate(0, -3, 0), To: now, Severity: map[string]map[string]int{}, Verdicts: map[string]map[string][2]int{},
		MeanScore: map[string][2]float64{}, Moved: map[string]int{"up": 0, "down": 0}, Incidents: map[string]int{}}
	for _, k := range []string{"current", "candidate"} {
		r.Severity[k], r.Verdicts[k] = map[string]int{}, map[string][2]int{}
		for _, b := range severityBands {
			r.Severity[k][b], r.Verdicts[k][b] = 0, [2]int{}
		}
	}
	sums := map[string][2]float64{}
	counts := [2]float64{}
	seen := map[string]bool{}
	add := func(e events.Event, verdict *bool) {
		a, ok1 := eval(ctx, cur, e)
		b, ok2 := eval(ctx, cand, e)
		if !ok1 || !ok2 {
			return
		}
		r.Events++
		for k, sc := range map[string]int{"current": a.score, "candidate": b.score} {
			band := incident.SeverityFor(sc)
			r.Severity[k][band]++
			if sc >= incident.MinRisk {
				r.Incidents[k]++
			}
			if verdict != nil {
				i := 1
				if *verdict {
					i = 0
				}
				v := r.Verdicts[k][band]
				v[i]++
				r.Verdicts[k][band] = v
				acc := sums[k]
				acc[i] += float64(sc)
				sums[k] = acc
			}
		}
		if verdict != nil {
			r.Labelled++
			if *verdict {
				counts[0]++
			} else {
				counts[1]++
			}
		}
		if d := slices.Index(severityBands, incident.SeverityFor(b.score)) - slices.Index(severityBands, incident.SeverityFor(a.score)); d > 0 {
			r.Moved["up"]++
		} else if d < 0 {
			r.Moved["down"]++
		}
	}
	for _, l := range labels {
		seen[l.Event.EventID] = true
		add(l.Event, &l.TP)
	}
	for _, e := range recent {
		if !seen[e.EventID] {
			add(e, nil)
		}
	}
	for k, acc := range sums {
		r.MeanScore[k] = [2]float64{math.Round(acc[0]/max(counts[0], 1)*10) / 10, math.Round(acc[1]/max(counts[1], 1)*10) / 10}
	}
	err = s.change(ctx, actor, "riskcal.version.simulate", func(tx pgx.Tx) (map[string]any, error) {
		_, err := tx.Exec(ctx, "UPDATE riskcal.versions SET state = 'simulated', report = $3 WHERE tenant_id = $1 AND version = $2", s.Tenant, version, r)
		return map[string]any{"version": version, "events": r.Events, "labelled": r.Labelled, "moved": r.Moved}, err
	})
	return r, err
}

// --- state machine --------------------------------------------------------------------------------------------

func (s *Store) get(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, version int) (Version, error) {
	return scan(q.QueryRow(ctx, "SELECT "+cols+" FROM riskcal.versions WHERE tenant_id = $1 AND version = $2", s.Tenant, version))
}

func (s *Store) change(ctx context.Context, actor, action string, f func(pgx.Tx) (map[string]any, error)) error {
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		target, err := f(tx)
		if err != nil {
			return err
		}
		_, err = audit.AppendTx(ctx, tx, s.Tenant, actor, action, target)
		return err
	})
}

func (s *Store) transition(ctx context.Context, actor, action string, version int, from []string, to string, f func(tx pgx.Tx, v Version) (map[string]any, error)) error {
	return s.change(ctx, actor, action, func(tx pgx.Tx) (map[string]any, error) {
		v, err := s.get(ctx, tx, version)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(from, v.State) {
			return nil, fmt.Errorf("%w: version %d is %s", ErrState, version, v.State)
		}
		target := map[string]any{"version": version, "from": v.State, "to": to}
		if f != nil {
			more, err := f(tx, v)
			if err != nil {
				return nil, err
			}
			for k, x := range more {
				target[k] = x
			}
		}
		_, err = tx.Exec(ctx, "UPDATE riskcal.versions SET state = $3 WHERE tenant_id = $1 AND version = $2", s.Tenant, version, to)
		return target, err
	})
}

// Submit asks for approval: only a simulated version (its report is what the approver reviews).
func (s *Store) Submit(ctx context.Context, actor string, version int) error {
	return s.transition(ctx, actor, "riskcal.version.submit", version, []string{"simulated"}, "pending_approval", nil)
}

// Reject sends a pending version back to draft.
func (s *Store) Reject(ctx context.Context, actor string, version int, note string) error {
	return s.transition(ctx, actor, "riskcal.version.reject", version, []string{"pending_approval"}, "draft",
		func(pgx.Tx, Version) (map[string]any, error) { return map[string]any{"note": note}, nil })
}

// Approve activates a pending version (approver ≠ author), retires the active one and cuts a policy release in the
// same transaction, so the sidecars get the weights with the next bundle.
func (s *Store) Approve(ctx context.Context, actor string, version int) (int64, error) {
	var n int64
	err := s.transition(ctx, actor, "riskcal.version.approve", version, []string{"pending_approval"}, "active", func(tx pgx.Tx, v Version) (map[string]any, error) {
		if strings.EqualFold(v.Author, actor) {
			return nil, ErrFourEyes
		}
		if _, err := tx.Exec(ctx, "UPDATE riskcal.versions SET state = 'retired' WHERE tenant_id = $1 AND state = 'active'", s.Tenant); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, "UPDATE riskcal.versions SET state = 'active', approver = $3, activated_at = now() WHERE tenant_id = $1 AND version = $2",
			s.Tenant, version, actor); err != nil {
			return nil, err
		}
		var err error
		n, err = s.Policies.CutRelease(ctx, tx, actor, fmt.Sprintf("risk weights v%d", version))
		return map[string]any{"author": v.Author, "release": n, "weights": v.Config["weights"]}, err
	})
	return n, err
}
