package tuning

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/authz"
	"wantimpres26/internal/detect"
	"wantimpres26/internal/events"
	"wantimpres26/internal/tenantdb"
)

//go:embed schema.sql
var schemaSQL string

var (
	ErrInvalid  = errors.New("invalid request")
	ErrNotFound = errors.New("not found")
	ErrOptIn    = errors.New("tenant has not opted in to model training")
	ErrState    = errors.New("stage change not allowed")
	ErrFourEyes = errors.New("four-eyes: the approver must not be the trainer")
)

const (
	// MinLabels for a training run, and per label value in each split: below that the gate measures noise.
	MinLabels  = 40
	minPerSide = 5
	// CanaryPercent of requests use the canary model (spec §9.4: canary 5%).
	CanaryPercent = 5
)

// Store is one tenant's tuning data.
type Store struct {
	DB     *pgxpool.Pool
	Tenant string
	Pepper []byte
}

func Open(ctx context.Context, db *pgxpool.Pool) error {
	if _, err := db.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("apply tuning schema: %w", err)
	}
	return tenantdb.Isolate(ctx, db, "tuning.optin", "tuning.labels", "tuning.models", "tuning.holdout")
}

func (s *Store) tx(ctx context.Context, actor, action string, target map[string]any, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		_, err := audit.AppendTx(ctx, tx, s.Tenant, actor, action, target)
		return err
	})
}

// --- opt-in ---

type OptIn struct {
	Enabled bool      `json:"enabled"`
	Note    string    `json:"note,omitempty"`
	Actor   string    `json:"actor,omitempty"`
	At      time.Time `json:"at,omitzero"`
}

func (s *Store) OptIn(ctx context.Context) (OptIn, error) {
	var o OptIn
	err := s.DB.QueryRow(ctx, "SELECT enabled, note, actor, at FROM tuning.optin WHERE tenant_id = $1 ORDER BY at DESC LIMIT 1", s.Tenant).
		Scan(&o.Enabled, &o.Note, &o.Actor, &o.At)
	if errors.Is(err, pgx.ErrNoRows) {
		return OptIn{}, nil
	}
	return o, err
}

// SetOptIn records the tenant's decision (DPO). A reason is required either way.
func (s *Store) SetOptIn(ctx context.Context, actor string, enabled bool, note string, now time.Time) error {
	if note == "" {
		return fmt.Errorf("%w: note (reason, e.g. DPIA reference) required", ErrInvalid)
	}
	return s.tx(ctx, actor, "tuning.optin", map[string]any{"enabled": enabled, "note": note}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO tuning.optin (tenant_id, enabled, note, actor, at) VALUES ($1, $2, $3, $4, $5)", s.Tenant, enabled, note, actor, now)
		return err
	})
}

// --- labels and the active-learning queue ---

// tenantEvent reads an incident event of this tenant.
func (s *Store) tenantEvent(ctx context.Context, q pgx.Tx, eventID string) (events.Event, error) {
	var raw []byte
	err := q.QueryRow(ctx, `SELECT ie.event FROM incident.incident_events ie JOIN incident.incidents i ON i.id = ie.incident_id
		WHERE i.tenant_id = $1 AND ie.event_id::text = $2`, s.Tenant, eventID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return events.Event{}, ErrNotFound
	}
	var e events.Event
	if err == nil {
		err = json.Unmarshal(raw, &e)
	}
	return e, err
}

// Label records a triage verdict for one class of one incident event (re-labelling replaces it).
func (s *Store) Label(ctx context.Context, actor, eventID, class string, tp bool, now time.Time) error {
	return s.tx(ctx, actor, "tuning.label", map[string]any{"event_id": eventID, "class": class, "tp": tp}, func(tx pgx.Tx) error {
		e, err := s.tenantEvent(ctx, tx, eventID)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(e.Classes, func(c events.Class) bool { return c.Type == class }) {
			return fmt.Errorf("%w: event has no class %q", ErrInvalid, class)
		}
		_, err = tx.Exec(ctx, `INSERT INTO tuning.labels (tenant_id, event_id, class, tp, labeled_by, labeled_at) VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (tenant_id, event_id, class) DO UPDATE SET tp = excluded.tp, labeled_by = excluded.labeled_by, labeled_at = excluded.labeled_at`,
			s.Tenant, eventID, class, tp, actor, now)
		return err
	})
}

func sample(e events.Event, c events.Class) Sample {
	return Sample{Class: c.Type, Channel: e.Channel, Direction: e.Direction, AppID: e.AppID, Confidence: c.Confidence, Snippet: e.Snippet}
}

// QueueItem is an unlabelled finding to show an analyst; Uncertainty 0 = the model cannot tell.
type QueueItem struct {
	EventID     string  `json:"event_id"`
	IncidentID  string  `json:"incident_id"`
	Class       string  `json:"class"`
	Channel     string  `json:"channel"`
	AppID       string  `json:"app_id"`
	Confidence  float64 `json:"confidence"`
	Snippet     string  `json:"snippet"` // already redacted by the PEP
	Prob        float64 `json:"p_true_positive"`
	Uncertainty float64 `json:"uncertainty"`
}

// Queue ranks unlabelled findings of recent incident events by uncertainty (active learning): under the live model
// |p - threshold|, without one the detector confidence's distance from detect.Threshold.
func (s *Store) Queue(ctx context.Context, limit int) ([]QueueItem, error) {
	sc, err := s.liveScorer(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.Query(ctx, `SELECT ie.event_id::text, ie.incident_id::text, ie.event FROM incident.incident_events ie
		JOIN incident.incidents i ON i.id = ie.incident_id WHERE i.tenant_id = $1 ORDER BY ie.ts DESC LIMIT 2000`, s.Tenant)
	if err != nil {
		return nil, err
	}
	type row struct {
		ev, inc string
		raw     []byte
	}
	rs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		return x, r.Scan(&x.ev, &x.inc, &x.raw)
	})
	if err != nil {
		return nil, err
	}
	done := map[[2]string]bool{}
	lrows, err := s.DB.Query(ctx, "SELECT event_id::text, class FROM tuning.labels WHERE tenant_id = $1", s.Tenant)
	if err != nil {
		return nil, err
	}
	var k [2]string
	if _, err := pgx.ForEachRow(lrows, []any{&k[0], &k[1]}, func() error { done[k] = true; return nil }); err != nil {
		return nil, err
	}
	var out []QueueItem
	for _, r := range rs {
		var e events.Event
		if json.Unmarshal(r.raw, &e) != nil {
			continue
		}
		for _, c := range e.Classes {
			if done[[2]string{r.ev, c.Type}] {
				continue
			}
			it := QueueItem{EventID: r.ev, IncidentID: r.inc, Class: c.Type, Channel: e.Channel, AppID: e.AppID, Confidence: c.Confidence, Snippet: e.Snippet}
			if sc != nil {
				it.Prob = sc.Prob(sample(e, c))
				it.Uncertainty = math.Abs(it.Prob - sc.m.Threshold)
			} else {
				it.Prob = c.Confidence
				it.Uncertainty = math.Abs(c.Confidence - detect.Threshold)
			}
			out = append(out, it)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Uncertainty < out[j].Uncertainty })
	return out[:min(len(out), limit)], nil
}

// labelled returns the tenant's training samples and the quarter's frozen holdout. Events are split by keyed hash
// of the event id, so an event stays on its side as labels accumulate and holdout events are never trained on. The
// holdout is frozen at the quarter's first training run (inside tx, so concurrent runs agree).
func (s *Store) labelled(ctx context.Context, tx pgx.Tx, now time.Time) (train, holdout []Sample, quarter string, err error) {
	quarter = fmt.Sprintf("%dQ%d", now.Year(), (int(now.Month())-1)/3+1)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended('tuning.holdout|' || $1, 0))", s.Tenant); err != nil {
		return nil, nil, "", err
	}
	var frozen bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM tuning.holdout WHERE tenant_id = $1 AND quarter = $2)", s.Tenant, quarter).Scan(&frozen); err != nil {
		return nil, nil, "", err
	}
	read := func(q string, args ...any) ([]Sample, []string, error) {
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return nil, nil, err
		}
		var out []Sample
		var ids []string
		var id, class string
		var tp bool
		var raw []byte
		_, err = pgx.ForEachRow(rows, []any{&id, &class, &tp, &raw}, func() error {
			var e events.Event
			if err := json.Unmarshal(raw, &e); err != nil {
				return err
			}
			for _, c := range e.Classes {
				if c.Type == class {
					x := sample(e, c)
					x.TP = tp
					out, ids = append(out, x), append(ids, id)
				}
			}
			return nil
		})
		return out, ids, err
	}
	all, ids, err := read(`SELECT l.event_id::text, l.class, l.tp, ie.event FROM tuning.labels l
		JOIN incident.incident_events ie ON ie.event_id = l.event_id JOIN incident.incidents i ON i.id = ie.incident_id
		WHERE l.tenant_id = $1 AND i.tenant_id = $1 ORDER BY l.event_id, l.class`, s.Tenant)
	if err != nil {
		return nil, nil, "", err
	}
	for k, x := range all {
		if !s.holdout(ids[k]) {
			train = append(train, x)
		} else if !frozen {
			holdout = append(holdout, x)
			if _, err := tx.Exec(ctx, "INSERT INTO tuning.holdout (tenant_id, quarter, event_id, class, tp) VALUES ($1, $2, $3, $4, $5)",
				s.Tenant, quarter, ids[k], x.Class, x.TP); err != nil {
				return nil, nil, "", err
			}
		}
	}
	if frozen {
		holdout, _, err = read(`SELECT h.event_id::text, h.class, h.tp, ie.event FROM tuning.holdout h
			JOIN incident.incident_events ie ON ie.event_id = h.event_id JOIN incident.incidents i ON i.id = ie.incident_id
			WHERE h.tenant_id = $1 AND i.tenant_id = $1 AND h.quarter = $2 ORDER BY h.event_id, h.class`, s.Tenant, quarter)
	}
	return train, holdout, quarter, err
}

func (s *Store) holdout(eventID string) bool {
	m := hmac.New(sha256.New, s.Pepper)
	m.Write([]byte("holdout|" + eventID))
	return binary.BigEndian.Uint32(m.Sum(nil))%5 == 0 // 20%
}

// --- models ---

type Model struct {
	Version   int       `json:"version"`
	Stage     string    `json:"stage"`
	Threshold float64   `json:"threshold"`
	Gate      Gate      `json:"gate"`
	Labels    int       `json:"labels"`
	TrainedBy string    `json:"trained_by"`
	TrainedAt time.Time `json:"trained_at"`
	ChangedAt time.Time `json:"changed_at"`
	weights   *Weights
}

const modelCols = "version, stage, weights, gate, labels, trained_by, trained_at, changed_at"

func scanModel(r pgx.Row) (Model, error) {
	var m Model
	var w []byte
	err := r.Scan(&m.Version, &m.Stage, &w, &m.Gate, &m.Labels, &m.TrainedBy, &m.TrainedAt, &m.ChangedAt)
	if err == nil {
		m.weights = &Weights{}
		err = json.Unmarshal(w, m.weights)
		m.Threshold = m.weights.Threshold
	}
	return m, err
}

func (s *Store) Models(ctx context.Context) ([]Model, error) {
	rows, err := s.DB.Query(ctx, "SELECT "+modelCols+" FROM tuning.models WHERE tenant_id = $1 ORDER BY version", s.Tenant)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Model, error) { return scanModel(r) })
}

func (s *Store) stageModel(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, stage string) (*Model, error) {
	m, err := scanModel(q.QueryRow(ctx, "SELECT "+modelCols+" FROM tuning.models WHERE tenant_id = $1 AND stage = $2", s.Tenant, stage))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &m, err
}

// liveScorer is the model analysts' queue is ranked by: active, else canary, else shadow.
func (s *Store) liveScorer(ctx context.Context) (*Scorer, error) {
	for _, st := range []string{"active", "canary", "shadow"} {
		m, err := s.stageModel(ctx, s.DB, st)
		if err != nil {
			return nil, err
		}
		if m != nil {
			return NewScorer(s.Pepper, m.weights), nil
		}
	}
	return nil, nil
}

// Train fits a new version on the tenant's labels and runs the §9.4 gate on the holdout against the active model
// (or the bare detector). A failed gate stores the version as rejected, with its reasons, for the record.
func (s *Store) Train(ctx context.Context, actor string, now time.Time) (Model, error) {
	o, err := s.OptIn(ctx)
	if err != nil {
		return Model{}, err
	}
	if !o.Enabled {
		return Model{}, ErrOptIn
	}
	m := Model{TrainedBy: actor, TrainedAt: now, ChangedAt: now}
	target := map[string]any{} // filled in below; audited on commit
	err = s.tx(ctx, actor, "tuning.train", target, func(tx pgx.Tx) error {
		train, hold, quarter, err := s.labelled(ctx, tx, now)
		if err != nil {
			return err
		}
		count := func(xs []Sample) (p, n int) {
			for _, x := range xs {
				if x.TP {
					p++
				} else {
					n++
				}
			}
			return
		}
		tp, fp := count(train)
		hp, hn := count(hold)
		if len(train)+len(hold) < MinLabels || min(tp, fp, hp, hn) < minPerSide {
			return fmt.Errorf("%w: need ≥ %d labels with ≥ %d true and false positives in both train and holdout (have train %d/%d, holdout %d/%d)",
				ErrInvalid, MinLabels, minPerSide, tp, fp, hp, hn)
		}
		w := Train(s.Pepper, train, 1)
		m.Labels, m.Threshold, m.weights = len(train), w.Threshold, w
		target["labels"], target["holdout"], target["holdout_quarter"] = len(train), len(hold), quarter
		active, err := s.stageModel(ctx, tx, "active")
		if err != nil {
			return err
		}
		var base *Scorer
		if active != nil {
			base = NewScorer(s.Pepper, active.weights)
		}
		m.Gate = CheckGate(Evaluate(NewScorer(s.Pepper, w), hold), Evaluate(base, hold))
		m.Stage = "candidate"
		if !m.Gate.Pass {
			m.Stage = "rejected"
		}
		if err := tx.QueryRow(ctx, "SELECT coalesce(max(version), 0) + 1 FROM tuning.models WHERE tenant_id = $1", s.Tenant).Scan(&m.Version); err != nil {
			return err
		}
		target["version"], target["stage"], target["gate"] = m.Version, m.Stage, m.Gate
		raw, _ := json.Marshal(w)
		_, err = tx.Exec(ctx, `INSERT INTO tuning.models (tenant_id, version, stage, weights, gate, labels, trained_by, trained_at, changed_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)`, s.Tenant, m.Version, m.Stage, raw, m.Gate, m.Labels, actor, now)
		return err
	})
	return m, err
}

// next is the rollout (spec §9.4): candidate → shadow → canary → active; any live stage → retired (rollback).
var next = map[string][]string{"candidate": {"shadow", "retired"}, "shadow": {"canary", "retired"}, "canary": {"active", "retired"}, "active": {"retired"}}

// SetStage moves a version along the rollout. Promotions need someone other than the trainer (four-eyes); a model
// promoted to active retires the previous active one. Retiring (rollback) is open to any approver.
func (s *Store) SetStage(ctx context.Context, actor string, version int, to, note string, now time.Time) (Model, error) {
	var m Model
	err := s.tx(ctx, actor, "tuning.stage", map[string]any{"version": version, "to": to, "note": note}, func(tx pgx.Tx) error {
		var err error
		m, err = scanModel(tx.QueryRow(ctx, "SELECT "+modelCols+" FROM tuning.models WHERE tenant_id = $1 AND version = $2 FOR UPDATE", s.Tenant, version))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !slices.Contains(next[m.Stage], to) {
			return fmt.Errorf("%w: %s → %s", ErrState, m.Stage, to)
		}
		if to != "retired" && actor == m.TrainedBy {
			return ErrFourEyes
		}
		if to == "active" {
			if _, err := tx.Exec(ctx, "UPDATE tuning.models SET stage = 'retired', changed_at = $2 WHERE tenant_id = $1 AND stage = 'active'", s.Tenant, now); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, "UPDATE tuning.models SET stage = $3, changed_at = $4 WHERE tenant_id = $1 AND version = $2", s.Tenant, version, to, now); err != nil {
			return err
		}
		m.Stage, m.ChangedAt = to, now
		return nil
	})
	return m, err
}

// --- serving ---

type live struct {
	shadow, canary, active *Model
	sc                     map[int]*Scorer
}

// Live is the tenant's shadow, canary and active models, refreshed in the background. A nil *Live does nothing.
type Live struct {
	p   atomic.Pointer[live]
	key []byte
}

// Watch loads the live models now and reloads them every interval when a stage changed.
func Watch(ctx context.Context, db *pgxpool.Pool, tenant string, pepper []byte, every time.Duration, log *slog.Logger) (*Live, error) {
	s := &Store{DB: db, Tenant: tenant, Pepper: pepper}
	l := &Live{key: pepper}
	cur := ""
	load := func() error {
		var v string // every version's stage: changes exactly when a reload is needed
		if err := db.QueryRow(ctx, "SELECT coalesce(string_agg(version || ':' || stage, ',' ORDER BY version), '') FROM tuning.models WHERE tenant_id = $1",
			tenant).Scan(&v); err != nil {
			return err
		}
		if v == cur && l.p.Load() != nil {
			return nil
		}
		x := &live{sc: map[int]*Scorer{}}
		for st, dst := range map[string]**Model{"shadow": &x.shadow, "canary": &x.canary, "active": &x.active} {
			m, err := s.stageModel(ctx, db, st)
			if err != nil {
				return err
			}
			if *dst = m; m != nil {
				x.sc[m.Version] = NewScorer(pepper, m.weights)
			}
		}
		l.p.Store(x)
		cur = v
		return nil
	}
	if err := load(); err != nil {
		return nil, fmt.Errorf("load tuning models: %w", err)
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if err := load(); err != nil {
				log.Warn("tuning model reload failed; keeping the previous models", "err", err)
			}
		}
	}()
	return l, nil
}

// Report says what the tenant model did to one scan.
type Report struct {
	Version    int                `json:"model_version"`
	Stage      string             `json:"stage"` // the model applied: canary or active
	Scores     map[string]float64 `json:"scores"`
	Suppressed []string           `json:"suppressed,omitempty"`
	Shadow     *ShadowReport      `json:"shadow,omitempty"`
}

// ShadowReport is what the shadow model would have done (logged, never applied).
type ShadowReport struct {
	Version    int                `json:"model_version"`
	Scores     map[string]float64 `json:"scores"`
	Suppressed []string           `json:"suppressed,omitempty"`
}

// Apply runs the tenant models over an L1 result (before similarity or other non-L1 findings are added): the shadow
// model only scores; CanaryPercent of texts (stable per text) use the canary model, the rest the active one, and
// classes it judges false positives are dropped (detect.Without). No live model: r unchanged, nil report.
func (l *Live) Apply(text string, r detect.Result, channel, direction, appID string) (detect.Result, *Report) {
	if l == nil {
		return r, nil
	}
	x := l.p.Load()
	if x == nil || (x.shadow == nil && x.canary == nil && x.active == nil) || len(r.Classes) == 0 {
		return r, nil
	}
	snippet := detect.Snippet(text, r.Matches)
	run := func(m *Model) (map[string]float64, []string) {
		scores := map[string]float64{}
		var drop []string
		for _, c := range r.Classes {
			s := Sample{Class: c.Type, Channel: channel, Direction: direction, AppID: appID, Confidence: c.Confidence, Snippet: snippet}
			sc := x.sc[m.Version]
			scores[c.Type] = math.Round(sc.Prob(s)*1000) / 1000
			if !sc.Keep(s) {
				drop = append(drop, c.Type)
			}
		}
		return scores, drop
	}
	var rep *Report
	m := x.active
	if x.canary != nil {
		h := fnv.New32a()
		h.Write([]byte(text))
		if h.Sum32()%100 < CanaryPercent { // the other 95% keep the active model, or the bare detector
			m = x.canary
		}
	}
	if m != nil {
		scores, drop := run(m)
		rep = &Report{Version: m.Version, Stage: m.Stage, Scores: scores, Suppressed: drop}
		if len(drop) > 0 {
			r = detect.Without(r, drop...)
		}
	}
	if x.shadow != nil {
		scores, drop := run(x.shadow)
		if rep == nil {
			rep = &Report{}
		}
		rep.Shadow = &ShadowReport{Version: x.shadow.Version, Scores: scores, Suppressed: drop}
	}
	return r, rep
}

// --- API (control-plane) ---

func Routes(rt *authz.Router, s *Store, now func() time.Time) {
	reply := func(w http.ResponseWriter, status int, v any, err error) {
		switch {
		case errors.Is(err, ErrInvalid):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, ErrNotFound):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, ErrOptIn), errors.Is(err, ErrFourEyes):
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, ErrState):
			http.Error(w, err.Error(), http.StatusConflict)
		case err != nil:
			http.Error(w, "internal error", http.StatusInternalServerError)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	decode := func(r *http.Request, v any) error {
		if json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<16)).Decode(v) != nil {
			return ErrInvalid
		}
		return nil
	}
	// Opt-in is the DPO's call (spec §9.3: explicit opt-in).
	rt.Handle("GET /tuning/optin", authz.ComplianceRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		o, err := s.OptIn(r.Context())
		reply(w, http.StatusOK, o, err)
	})
	rt.Handle("PUT /tuning/optin", authz.ComplianceWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b struct {
			Enabled bool   `json:"enabled"`
			Note    string `json:"note"`
		}
		err := decode(r, &b)
		if err == nil {
			err = s.SetOptIn(r.Context(), c.Username, b.Enabled, b.Note, now())
		}
		reply(w, http.StatusOK, b, err)
	})
	// Triage labels and the active-learning queue: SOC.
	rt.Handle("GET /tuning/queue", authz.IncidentRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 200 {
			limit = 50
		}
		q, err := s.Queue(r.Context(), limit)
		reply(w, http.StatusOK, q, err)
	})
	rt.Handle("POST /tuning/labels", authz.IncidentWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b struct {
			EventID string `json:"event_id"`
			Class   string `json:"class"`
			Label   string `json:"label"` // tp | fp
		}
		err := decode(r, &b)
		if err == nil && b.Label != "tp" && b.Label != "fp" {
			err = fmt.Errorf("%w: label must be tp or fp", ErrInvalid)
		}
		if err == nil {
			err = s.Label(r.Context(), c.Username, b.EventID, b.Class, b.Label == "tp", now())
		}
		reply(w, http.StatusCreated, b, err)
	})
	// Training is policy authoring (DLP analyst); rollout is publishing (approver, four-eyes).
	rt.Handle("GET /tuning/models", authz.PolicyRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		ms, err := s.Models(r.Context())
		reply(w, http.StatusOK, ms, err)
	})
	rt.Handle("POST /tuning/models", authz.PolicyWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		m, err := s.Train(r.Context(), c.Username, now())
		reply(w, http.StatusCreated, m, err)
	})
	rt.Handle("POST /tuning/models/{version}/stage", authz.PolicyPublish, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b struct {
			Stage string `json:"stage"`
			Note  string `json:"note"`
		}
		v, err := strconv.Atoi(r.PathValue("version"))
		if err != nil {
			err = ErrNotFound
		} else {
			err = decode(r, &b)
		}
		var m Model
		if err == nil {
			m, err = s.SetStage(r.Context(), c.Username, v, b.Stage, b.Note, now())
		}
		reply(w, http.StatusOK, m, err)
	})
}
