// Package lifecycle is policy change management (spec §4.7 FR-POL-5..7): versioned rule sets that go
// draft → simulated → pending_approval → active → retired under 4-eyes, one-action rollback, and exceptions that
// must expire. Each publish-type change cuts a release that every control-plane replica turns into the signed
// bundle the OPA sidecars pull.
package lifecycle

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/policysvc"
)

//go:embed schema.sql
var schemaSQL string

type State string

const (
	Draft           State = "draft"
	Simulated       State = "simulated"
	PendingApproval State = "pending_approval"
	Active          State = "active"
	Retired         State = "retired"
)

var (
	ErrNotFound = errors.New("not found")
	ErrInvalid  = errors.New("invalid")
	ErrState    = errors.New("wrong state")
	ErrFourEyes = errors.New("four-eyes: the approver must not be the author")
)

// MaxExceptionAge is FR-POL-7's default ceiling; ExpiryNotice is when the owner is warned.
const (
	MaxExceptionAge = 90 * 24 * time.Hour
	ExpiryNotice    = 7 * 24 * time.Hour
)

// Store is the Postgres-backed lifecycle module (schema policy). fsys is the engine (wantimpres26/policy) every release
// is validated against before it can exist.
type Store struct {
	db     *pgxpool.Pool
	tenant string
	fsys   fs.FS

	extras []func(ctx context.Context, tx pgx.Tx) (policysvc.Overrides, error)
}

// AddExtra makes another module's documents (app catalog, agent registry) part of every release, read in the
// releasing transaction. Call it at startup, before changes are made.
func (s *Store) AddExtra(f func(ctx context.Context, tx pgx.Tx) (policysvc.Overrides, error)) {
	s.extras = append(s.extras, f)
}

func (s *Store) extra(ctx context.Context, tx pgx.Tx) (policysvc.Overrides, error) {
	ov := policysvc.Overrides{}
	for _, f := range s.extras {
		more, err := f(ctx, tx)
		if err != nil {
			return nil, err
		}
		for k, v := range more {
			ov[k] = v
		}
	}
	return ov, nil
}

// Open applies the schema and, on an empty database, activates the built-in FR-POL-8 templates as policy "builtin"
// version 1 (release 1), so sidecars always have a policy.
func Open(ctx context.Context, db *pgxpool.Pool, tenant string, fsys fs.FS) (*Store, error) {
	if _, err := db.Exec(ctx, schemaSQL); err != nil {
		return nil, fmt.Errorf("apply policy schema: %w", err)
	}
	s := &Store{db: db, tenant: tenant, fsys: fsys}
	raw, err := fs.ReadFile(fsys, "wantimpres26/rules/data.json")
	if err != nil {
		return nil, err
	}
	var builtin struct {
		Items []any `json:"items"`
	}
	if err := json.Unmarshal(raw, &builtin); err != nil {
		return nil, err
	}
	err = s.change(ctx, "system", "policy.seed", func(tx pgx.Tx) (map[string]any, error) {
		if _, err := tx.Exec(ctx, "LOCK TABLE policy.releases IN EXCLUSIVE MODE"); err != nil { // replicas start together
			return nil, err
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM policy.releases").Scan(&n); err != nil || n > 0 {
			return nil, err
		}
		var pid string
		if err := tx.QueryRow(ctx, "INSERT INTO policy.policies (name, created_by) VALUES ('builtin', 'system') RETURNING id").Scan(&pid); err != nil {
			return nil, err
		}
		_, err := tx.Exec(ctx, `INSERT INTO policy.versions (policy_id, version, state, rules, author, approver, published_at)
			VALUES ($1, 1, 'active', $2, 'system', 'system', now())`, pid, builtin.Items)
		if err != nil {
			return nil, err
		}
		n64, err := s.release(ctx, tx, "system", "seed built-in templates (FR-POL-8)")
		return map[string]any{"policy": pid, "release": n64}, err
	})
	return s, err
}

// change runs f in a transaction and audits it there: no transition without its record (ticket 12 AC).
// f returning a nil target means "nothing happened" (no audit entry).
func (s *Store) change(ctx context.Context, actor, action string, f func(pgx.Tx) (map[string]any, error)) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		target, err := f(tx)
		if err != nil || target == nil {
			return err
		}
		_, err = audit.AppendTx(ctx, tx, s.tenant, actor, action, target)
		return err
	})
}

// --- releases ----------------------------------------------------------------------------------------------

// composition is what sidecars would run: the active rules of every policy (with one policy optionally swapped
// for a candidate version) and the active, unexpired exceptions.
func composition(ctx context.Context, q pgx.Tx, swapPolicy string, swapRules []any) (rules []any, exceptions []any, err error) {
	rows, err := q.Query(ctx, `SELECT p.id::text, v.rules FROM policy.versions v JOIN policy.policies p ON p.id = v.policy_id
		WHERE v.state = 'active' ORDER BY p.name`)
	if err != nil {
		return nil, nil, err
	}
	rules = []any{}
	swapped := false
	for rows.Next() {
		var id string
		var pr []any
		if err := rows.Scan(&id, &pr); err != nil {
			return nil, nil, err
		}
		if id == swapPolicy {
			pr, swapped = swapRules, true
		}
		rules = append(rules, pr...)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if swapPolicy != "" && !swapped {
		rules = append(rules, swapRules...)
	}
	rows, err = q.Query(ctx, `SELECT id::text, rules, scope, expires_at FROM policy.exceptions
		WHERE state = 'active' AND expires_at > now() ORDER BY id`)
	if err != nil {
		return nil, nil, err
	}
	exceptions = []any{}
	for rows.Next() {
		var id string
		var rs []string
		var scope map[string]any
		var exp time.Time
		if err := rows.Scan(&id, &rs, &scope, &exp); err != nil {
			return nil, nil, err
		}
		exceptions = append(exceptions, map[string]any{"id": id, "rules": rs, "scope": scope, "expires_at": exp.UTC().Format(time.RFC3339)})
	}
	return rules, exceptions, rows.Err()
}

func overrides(version string, rules, exceptions []any) policysvc.Overrides {
	return policysvc.Overrides{
		"wantimpres26.rules":      map[string]any{"version": version, "items": rules},
		"wantimpres26.exceptions": map[string]any{"items": exceptions},
	}
}

// release snapshots the current composition (plus Extra documents) as the next release, after the engine accepted
// it (duplicate rule ids across policies, unknown ops, … abort the whole change), and notifies every replica on
// commit.
func (s *Store) release(ctx context.Context, tx pgx.Tx, actor, reason string) (int64, error) {
	rules, exceptions, err := composition(ctx, tx, "", nil)
	if err != nil {
		return 0, err
	}
	extra, err := s.extra(ctx, tx)
	if err != nil {
		return 0, err
	}
	var n int64
	if err := tx.QueryRow(ctx, "SELECT nextval(pg_get_serial_sequence('policy.releases', 'number'))").Scan(&n); err != nil {
		return 0, err
	}
	ov := overrides(fmt.Sprintf("release-%d", n), rules, exceptions)
	for k, v := range extra {
		ov[k] = v
	}
	if _, err := policysvc.NewEvaluator(ctx, s.fsys, ov); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	_, err = tx.Exec(ctx, "INSERT INTO policy.releases (number, rules, exceptions, data, reason, created_by) VALUES ($1, $2, $3, $4, $5, $6)",
		n, ov["wantimpres26.rules"], ov["wantimpres26.exceptions"], extra, reason, actor)
	if err != nil {
		return 0, err
	}
	_, err = tx.Exec(ctx, "SELECT pg_notify('policy_release', $1)", fmt.Sprint(n))
	return n, err
}

// CutRelease lets another module (the catalog) publish its change to the sidecars inside its own transaction.
func (s *Store) CutRelease(ctx context.Context, tx pgx.Tx, actor, reason string) (int64, error) {
	return s.release(ctx, tx, actor, reason)
}

// Overrides is what a release puts into the bundle.
func (r Release) Overrides() policysvc.Overrides {
	ov := policysvc.Overrides{"wantimpres26.rules": r.Rules, "wantimpres26.exceptions": r.Exceptions}
	for k, v := range r.Data {
		ov[k] = v
	}
	return ov
}

// Release is a stored release.
type Release struct {
	Number     int64          `json:"number"`
	Rules      map[string]any `json:"rules"`
	Exceptions map[string]any `json:"exceptions"`
	Data       map[string]any `json:"data"`
	Reason     string         `json:"reason"`
	CreatedBy  string         `json:"created_by"`
	CreatedAt  time.Time      `json:"created_at"`
}

func (s *Store) Latest(ctx context.Context) (Release, error) {
	var r Release
	err := s.db.QueryRow(ctx, "SELECT number, rules, exceptions, data, reason, created_by, created_at FROM policy.releases ORDER BY number DESC LIMIT 1").
		Scan(&r.Number, &r.Rules, &r.Exceptions, &r.Data, &r.Reason, &r.CreatedBy, &r.CreatedAt)
	return r, notFound(err)
}

func (s *Store) Releases(ctx context.Context, limit int) ([]Release, error) {
	rows, err := s.db.Query(ctx, "SELECT number, rules, exceptions, data, reason, created_by, created_at FROM policy.releases ORDER BY number DESC LIMIT $1", limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Release])
}

// --- policies and versions ---------------------------------------------------------------------------------

// Version is the API view of one policy version.
type Version struct {
	PolicyID     string     `json:"policy_id"`
	Policy       string     `json:"policy"`
	Version      int        `json:"version"`
	State        State      `json:"state"`
	Rules        []any      `json:"rules"`
	Author       string     `json:"author"`
	Approver     *string    `json:"approver,omitempty"`
	SimulationID *string    `json:"simulation_id,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	PublishedAt  *time.Time `json:"published_at,omitempty"`
	RetiredAt    *time.Time `json:"retired_at,omitempty"`
}

const versionCols = `v.policy_id::text, p.name, v.version, v.state, v.rules, v.author, v.approver, v.simulation_id::text,
	v.created_at, v.published_at, v.retired_at`

func (s *Store) Versions(ctx context.Context, policyID string) ([]Version, error) {
	rows, err := s.db.Query(ctx, "SELECT "+versionCols+` FROM policy.versions v JOIN policy.policies p ON p.id = v.policy_id
		WHERE ($1 = '' OR v.policy_id::text = $1) ORDER BY p.name, v.version`, policyID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Version])
}

func getVersion(ctx context.Context, tx pgx.Tx, policyID string, version int) (Version, error) {
	rows, err := tx.Query(ctx, "SELECT "+versionCols+` FROM policy.versions v JOIN policy.policies p ON p.id = v.policy_id
		WHERE v.policy_id::text = $1 AND v.version = $2 FOR UPDATE OF v`, policyID, version)
	if err != nil {
		return Version{}, err
	}
	v, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[Version])
	return v, notFound(err)
}

// checkRules rejects a rule set the engine would refuse, before it is stored.
func (s *Store) checkRules(ctx context.Context, rules []any) error {
	if len(rules) == 0 {
		return fmt.Errorf("%w: a policy needs at least one rule", ErrInvalid)
	}
	if _, err := policysvc.NewEvaluator(ctx, s.fsys, overrides("check", rules, nil)); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}

// CreatePolicy creates a policy with version 1 as a draft.
func (s *Store) CreatePolicy(ctx context.Context, actor, name string, rules []any) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("%w: name required", ErrInvalid)
	}
	if err := s.checkRules(ctx, rules); err != nil {
		return "", err
	}
	var pid string
	err := s.change(ctx, actor, "policy.create", func(tx pgx.Tx) (map[string]any, error) {
		if err := tx.QueryRow(ctx, "INSERT INTO policy.policies (name, created_by) VALUES ($1, $2) RETURNING id::text", name, actor).Scan(&pid); err != nil {
			if strings.Contains(err.Error(), "23505") {
				return nil, fmt.Errorf("%w: policy %q exists", ErrInvalid, name)
			}
			return nil, err
		}
		_, err := tx.Exec(ctx, "INSERT INTO policy.versions (policy_id, version, state, rules, author) VALUES ($1, 1, 'draft', $2, $3)", pid, rules, actor)
		return map[string]any{"policy": pid, "name": name, "version": 1}, err
	})
	return pid, err
}

// NewVersion starts a new draft of an existing policy.
func (s *Store) NewVersion(ctx context.Context, actor, policyID string, rules []any) (int, error) {
	if err := s.checkRules(ctx, rules); err != nil {
		return 0, err
	}
	var v int
	err := s.change(ctx, actor, "policy.version.create", func(tx pgx.Tx) (map[string]any, error) {
		err := tx.QueryRow(ctx, `INSERT INTO policy.versions (policy_id, version, state, rules, author)
			SELECT $1::text::uuid, coalesce(max(version), 0) + 1, 'draft', $2, $3 FROM policy.versions WHERE policy_id::text = $1::text RETURNING version`,
			policyID, rules, actor).Scan(&v)
		if err != nil && (strings.Contains(err.Error(), "23503") || strings.Contains(err.Error(), "22P02")) { // no such policy / not a uuid
			return nil, ErrNotFound
		}
		return map[string]any{"policy": policyID, "version": v}, err
	})
	return v, err
}

// transition moves one version from one of `from` to `to`, runs extra in the same transaction (with the locked
// version), and audits action.
func (s *Store) transition(ctx context.Context, actor, action, policyID string, version int, from []State, to State,
	extra func(tx pgx.Tx, v Version) (map[string]any, error)) error {
	return s.change(ctx, actor, action, func(tx pgx.Tx) (map[string]any, error) {
		v, err := getVersion(ctx, tx, policyID, version)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(from, v.State) {
			return nil, fmt.Errorf("%w: version %d is %s, %s needs %v", ErrState, version, v.State, action, from)
		}
		target := map[string]any{"policy": policyID, "name": v.Policy, "version": version, "from": v.State, "to": to}
		if extra != nil {
			more, err := extra(tx, v)
			if err != nil {
				return nil, err
			}
			for k, x := range more {
				target[k] = x
			}
		}
		_, err = tx.Exec(ctx, `UPDATE policy.versions SET state = $3,
			published_at = CASE WHEN $3 = 'active' THEN now() ELSE published_at END,
			retired_at = CASE WHEN $3 = 'retired' THEN now() WHEN $3 = 'active' THEN NULL ELSE retired_at END
			WHERE policy_id::text = $1 AND version = $2`, policyID, version, to)
		return target, err
	})
}

// UpdateDraft replaces the rules of a draft (or simulated) version; a simulated one goes back to draft, because its
// simulation no longer describes it.
func (s *Store) UpdateDraft(ctx context.Context, actor, policyID string, version int, rules []any) error {
	if err := s.checkRules(ctx, rules); err != nil {
		return err
	}
	return s.transition(ctx, actor, "policy.version.edit", policyID, version, []State{Draft, Simulated}, Draft,
		func(tx pgx.Tx, _ Version) (map[string]any, error) {
			_, err := tx.Exec(ctx, "UPDATE policy.versions SET rules = $3, simulation_id = NULL WHERE policy_id::text = $1 AND version = $2", policyID, version, rules)
			return nil, err
		})
}

// Submit asks for approval; only a simulated version can be submitted (FR-POL-6: see the diff before publish).
func (s *Store) Submit(ctx context.Context, actor, policyID string, version int) error {
	return s.transition(ctx, actor, "policy.version.submit", policyID, version, []State{Simulated}, PendingApproval, nil)
}

// Reject sends a pending version back to draft.
func (s *Store) Reject(ctx context.Context, actor, policyID string, version int, note string) error {
	return s.transition(ctx, actor, "policy.version.reject", policyID, version, []State{PendingApproval}, Draft,
		func(pgx.Tx, Version) (map[string]any, error) { return map[string]any{"note": note}, nil })
}

// Approve publishes a pending version (4-eyes: approver ≠ author). The policy's previous active version is retired
// and a release is cut in the same transaction.
func (s *Store) Approve(ctx context.Context, actor, policyID string, version int) (int64, error) {
	var n int64
	err := s.transition(ctx, actor, "policy.version.approve", policyID, version, []State{PendingApproval}, Active,
		func(tx pgx.Tx, v Version) (map[string]any, error) {
			if strings.EqualFold(v.Author, actor) {
				return nil, ErrFourEyes
			}
			if _, err := tx.Exec(ctx, "UPDATE policy.versions SET state = 'retired', retired_at = now() WHERE policy_id::text = $1 AND state = 'active'", policyID); err != nil {
				return nil, err
			}
			if _, err := tx.Exec(ctx, "UPDATE policy.versions SET approver = $3 WHERE policy_id::text = $1 AND version = $2", policyID, version, actor); err != nil {
				return nil, err
			}
			// The version must already be active when the release snapshots the composition.
			if _, err := tx.Exec(ctx, "UPDATE policy.versions SET state = 'active', published_at = now(), retired_at = NULL WHERE policy_id::text = $1 AND version = $2", policyID, version); err != nil {
				return nil, err
			}
			var err error
			n, err = s.release(ctx, tx, actor, fmt.Sprintf("approve %s v%d", v.Policy, version))
			return map[string]any{"author": v.Author, "release": n}, err
		})
	return n, err
}

// Rollback reactivates the version that was active before the current one, in one action. It restores something
// already approved, so it needs policy.publish (step-up) but no second approver.
func (s *Store) Rollback(ctx context.Context, actor, policyID string) (int64, error) {
	var cur int
	var prevPtr *int
	err := s.db.QueryRow(ctx, `SELECT a.version, (SELECT r.version FROM policy.versions r WHERE r.policy_id = a.policy_id
			AND r.state = 'retired' AND r.published_at < a.published_at ORDER BY r.published_at DESC LIMIT 1)
		FROM policy.versions a WHERE a.policy_id::text = $1 AND a.state = 'active'`, policyID).Scan(&cur, &prevPtr)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("%w: no active version to roll back", ErrState)
	} else if err != nil {
		return 0, err
	}
	if prevPtr == nil {
		return 0, fmt.Errorf("%w: no previously published version", ErrState)
	}
	prev := *prevPtr
	var n int64
	err = s.transition(ctx, actor, "policy.rollback", policyID, prev, []State{Retired}, Active,
		func(tx pgx.Tx, v Version) (map[string]any, error) {
			if _, err := tx.Exec(ctx, "UPDATE policy.versions SET state = 'retired', retired_at = now() WHERE policy_id::text = $1 AND version = $2 AND state = 'active'", policyID, cur); err != nil {
				return nil, err
			}
			if _, err := tx.Exec(ctx, "UPDATE policy.versions SET state = 'active', published_at = now(), retired_at = NULL WHERE policy_id::text = $1 AND version = $2", policyID, prev); err != nil {
				return nil, err
			}
			var err error
			n, err = s.release(ctx, tx, actor, fmt.Sprintf("rollback %s v%d -> v%d", v.Policy, cur, prev))
			return map[string]any{"rolled_back": cur, "release": n}, err
		})
	return n, err
}

// Retire deactivates a policy's active version without a replacement.
func (s *Store) Retire(ctx context.Context, actor, policyID string, version int) (int64, error) {
	var n int64
	err := s.transition(ctx, actor, "policy.retire", policyID, version, []State{Active}, Retired,
		func(tx pgx.Tx, v Version) (map[string]any, error) {
			if _, err := tx.Exec(ctx, "UPDATE policy.versions SET state = 'retired', retired_at = now() WHERE policy_id::text = $1 AND version = $2", policyID, version); err != nil {
				return nil, err
			}
			var err error
			n, err = s.release(ctx, tx, actor, fmt.Sprintf("retire %s v%d", v.Policy, version))
			return map[string]any{"release": n}, err
		})
	return n, err
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
