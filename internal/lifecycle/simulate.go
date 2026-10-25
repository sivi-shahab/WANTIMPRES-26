package lifecycle

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"wantimpres26/internal/events"
	"wantimpres26/internal/policysvc"
)

// EventSource returns stored decision events with ts in [from, to), at most limit (the event store, ticket 15).
type EventSource func(ctx context.Context, from, to time.Time, limit int) ([]events.Event, error)

// CorpusCase is a labelled canonical input (policy/corpus/*.jsonl): what the policy must decide.
type CorpusCase struct {
	Name   string         `json:"name"`
	Input  map[string]any `json:"input"`
	Expect string         `json:"expect"`
}

// LoadCorpus reads every corpus/*.jsonl in fsys.
func LoadCorpus(fsys fs.FS) ([]CorpusCase, error) {
	files, _ := fs.Glob(fsys, "corpus/*.jsonl")
	var out []CorpusCase
	for _, f := range files {
		raw, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(bytes.NewReader(raw))
		for line := 1; sc.Scan(); line++ {
			if len(bytes.TrimSpace(sc.Bytes())) == 0 {
				continue
			}
			var c CorpusCase
			if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
				return nil, fmt.Errorf("%s:%d: %w", f, line, err)
			}
			out = append(out, c)
		}
	}
	return out, nil
}

// Simulator replays stored events and the corpus through the active and the candidate composition.
type Simulator struct {
	Store     *Store
	Source    EventSource
	Corpus    []CorpusCase
	MaxEvents int // sample cap; the result says when it was hit
	Log       *slog.Logger
}

// MaxWindow is FR-POL-6's upper bound; requests without a window use DefaultWindow.
const (
	MaxWindow     = 30 * 24 * time.Hour
	DefaultWindow = 7 * 24 * time.Hour
)

// Sample is one event whose decision would change.
type Sample struct {
	EventID     string   `json:"event_id"`
	Old         string   `json:"old"`
	New         string   `json:"new"`
	ReasonCodes []string `json:"reason_codes"`
}

// Result is the §8.3 simulation output.
type Result struct {
	Total      int            `json:"total"`      // events read
	Replayable int            `json:"replayable"` // events with enough metadata to decide again
	Changed    int            `json:"changed"`
	Diff       map[string]int `json:"diff"` // "allow→block": n
	Samples    []Sample       `json:"samples"`
	Truncated  bool           `json:"truncated"` // MaxEvents reached: the window had more events
	Corpus     *CorpusResult  `json:"corpus,omitempty"`
}

type CorpusResult struct {
	Cases       int              `json:"cases"`
	Regressions []CorpusMismatch `json:"regressions"`
}

type CorpusMismatch struct {
	Name   string `json:"name"`
	Expect string `json:"expect"`
	Got    string `json:"got"`
}

func digest(rules []any) string {
	b, _ := json.Marshal(rules)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Start records a simulation of one version and runs it in the background; GET /simulations/{id} reports it.
// When it finishes and the version's rules are unchanged, a draft version becomes simulated.
func (sim *Simulator) Start(ctx context.Context, actor, policyID string, version int, from, to time.Time, includeCorpus bool) (string, error) {
	if to.IsZero() {
		to = time.Now()
	}
	if from.IsZero() {
		from = to.Add(-DefaultWindow)
	}
	if !to.After(from) || to.Sub(from) > MaxWindow {
		return "", fmt.Errorf("%w: window must be positive and at most %d days", ErrInvalid, int(MaxWindow.Hours()/24))
	}
	s := sim.Store
	var id string
	var v Version
	err := s.change(ctx, actor, "policy.simulate", func(tx pgx.Tx) (map[string]any, error) {
		var err error
		if v, err = getVersion(ctx, tx, policyID, version); err != nil {
			return nil, err
		}
		if v.State != Draft && v.State != Simulated {
			return nil, fmt.Errorf("%w: only draft or simulated versions are simulated, this one is %s", ErrState, v.State)
		}
		err = tx.QueryRow(ctx, `INSERT INTO policy.simulations (version_id, rules_digest, state, window_from, window_to, include_corpus, created_by)
			SELECT id, $3, 'running', $4, $5, $6, $7 FROM policy.versions WHERE policy_id::text = $1 AND version = $2 RETURNING id::text`,
			policyID, version, digest(v.Rules), from, to, includeCorpus, actor).Scan(&id)
		return map[string]any{"policy": policyID, "version": version, "simulation": id, "from": from, "to": to}, err
	})
	if err != nil {
		return "", err
	}
	go sim.run(context.WithoutCancel(ctx), id, v, from, to, includeCorpus)
	return id, nil
}

// ponytail: runs in the requesting replica; if it dies mid-run the simulation stays "running". Add a stale-run
// sweep (or a job queue) when simulations get long enough for that to matter.
func (sim *Simulator) run(ctx context.Context, id string, v Version, from, to time.Time, includeCorpus bool) {
	res, err := sim.evaluate(ctx, v, from, to, includeCorpus)
	s := sim.Store
	if err != nil {
		sim.Log.Error("simulation failed", "simulation", id, "err", err)
		_, _ = s.db.Exec(ctx, "UPDATE policy.simulations SET state = 'failed', error = $2, finished_at = now() WHERE id = $1", id, err.Error())
		return
	}
	err = s.change(ctx, "system", "policy.simulate.done", func(tx pgx.Tx) (map[string]any, error) {
		if _, err := tx.Exec(ctx, "UPDATE policy.simulations SET state = 'done', result = $2, finished_at = now() WHERE id = $1", id, res); err != nil {
			return nil, err
		}
		// Only if the version still has the simulated rules: an edit during the run voids the result.
		cur, err := getVersion(ctx, tx, v.PolicyID, v.Version)
		if err != nil {
			return nil, err
		}
		marked := digest(cur.Rules) == digest(v.Rules) && (cur.State == Draft || cur.State == Simulated)
		if marked {
			if _, err := tx.Exec(ctx, "UPDATE policy.versions SET state = 'simulated', simulation_id = $3 WHERE policy_id::text = $1 AND version = $2",
				v.PolicyID, v.Version, id); err != nil {
				return nil, err
			}
		}
		return map[string]any{"simulation": id, "policy": v.PolicyID, "version": v.Version, "changed": res.Changed,
			"total": res.Total, "version_marked_simulated": marked}, nil
	})
	if err != nil {
		sim.Log.Error("simulation result", "simulation", id, "err", err)
	}
}

func (sim *Simulator) evaluate(ctx context.Context, v Version, from, to time.Time, includeCorpus bool) (Result, error) {
	var baseRules, baseExc, candRules []any
	var extra policysvc.Overrides
	err := pgx.BeginTxFunc(ctx, sim.Store.db, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		if baseRules, baseExc, err = composition(ctx, tx, "", nil); err != nil {
			return err
		}
		if extra, err = sim.Store.extra(ctx, tx); err != nil {
			return err
		}
		candRules, _, err = composition(ctx, tx, v.PolicyID, v.Rules)
		return err
	})
	if err != nil {
		return Result{}, err
	}
	withExtra := func(ov policysvc.Overrides) policysvc.Overrides {
		for k, x := range extra {
			ov[k] = x
		}
		return ov
	}
	base, err := policysvc.NewEvaluator(ctx, sim.Store.fsys, withExtra(overrides("simulation-baseline", baseRules, baseExc)))
	if err != nil {
		return Result{}, err
	}
	cand, err := policysvc.NewEvaluator(ctx, sim.Store.fsys, withExtra(overrides(fmt.Sprintf("simulation-%s-v%d", v.Policy, v.Version), candRules, baseExc)))
	if err != nil {
		return Result{}, err
	}

	evs, err := sim.Source(ctx, from, to, sim.MaxEvents)
	if err != nil {
		return Result{}, fmt.Errorf("event store: %w", err)
	}
	res := Result{Total: len(evs), Diff: map[string]int{}, Samples: []Sample{}, Truncated: len(evs) >= sim.MaxEvents}
	var mu sync.Mutex
	var firstErr error
	jobs := make(chan events.Event)
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for e := range jobs {
				in, ok := e.PDPInput()
				if !ok {
					continue
				}
				old, err1 := base.Eval(ctx, in)
				nw, err2 := cand.Eval(ctx, in)
				mu.Lock()
				switch {
				case err1 != nil || err2 != nil:
					if firstErr == nil {
						firstErr = fmt.Errorf("event %s: %v %v", e.EventID, err1, err2)
					}
				default:
					res.Replayable++
					if old.Action != nw.Action {
						res.Changed++
						res.Diff[old.Action+"→"+nw.Action]++
						if len(res.Samples) < 20 {
							res.Samples = append(res.Samples, Sample{e.EventID, old.Action, nw.Action, nw.ReasonCodes})
						}
					}
				}
				mu.Unlock()
			}
		}()
	}
	for _, e := range evs {
		jobs <- e
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return Result{}, firstErr
	}
	sort.Slice(res.Samples, func(i, j int) bool { return res.Samples[i].EventID < res.Samples[j].EventID })

	if includeCorpus {
		cr := &CorpusResult{Cases: len(sim.Corpus), Regressions: []CorpusMismatch{}}
		for _, c := range sim.Corpus {
			d, err := cand.Eval(ctx, c.Input)
			if err != nil {
				return Result{}, fmt.Errorf("corpus %s: %w", c.Name, err)
			}
			if d.Action != c.Expect {
				cr.Regressions = append(cr.Regressions, CorpusMismatch{c.Name, c.Expect, d.Action})
			}
		}
		res.Corpus = cr
	}
	return res, nil
}

// Simulation is the stored record.
type Simulation struct {
	ID         string     `json:"id"`
	State      string     `json:"state"`
	WindowFrom time.Time  `json:"window_from"`
	WindowTo   time.Time  `json:"window_to"`
	Result     *Result    `json:"result,omitempty"`
	Error      *string    `json:"error,omitempty"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

func (s *Store) Simulation(ctx context.Context, id string) (Simulation, error) {
	rows, err := s.db.Query(ctx, `SELECT id::text, state, window_from, window_to, result, error, created_by, created_at, finished_at
		FROM policy.simulations WHERE id::text = $1`, id)
	if err != nil {
		return Simulation{}, err
	}
	sim, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[Simulation])
	return sim, notFound(err)
}
