// Package remediate runs data-at-rest remediation (spec §4.3 FR-DATA-6, ticket 33): revoke anonymous links,
// remove broad or external grants, apply a label, quarantine. Nothing touches a source without an approval:
//
//  1. someone with data.remediate asks (Request); the connector worker dry-runs it into a plan of steps;
//  2. someone else with data.remediate.approve approves that plan (four eyes: never the requester);
//  3. the worker plans again just before executing and executes only if the plan is unchanged (otherwise the
//     request is stale and must be asked for again), then refreshes the asset's grants and exposure;
//  4. when the source can restore it, an undo can be requested; it is approved and executed the same way.
//
// Every transition is in the audit log.
package remediate

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/connector"
	"wantimpres26/internal/datascan"
)

//go:embed schema.sql
var schemaSQL string

var (
	ErrNotFound    = errors.New("not found")
	ErrInvalid     = errors.New("invalid")
	ErrState       = errors.New("not in a state that allows this")
	ErrSelf        = errors.New("the requester cannot approve their own remediation")
	ErrNotApproved = errors.New("remediation not approved")
)

// PlanTTL: an approval must come within this long of the plan, or the request expires (the source moves on).
const PlanTTL = 72 * time.Hour

// Remediation is one request.
type Remediation struct {
	ID           string           `json:"id"`
	AssetID      string           `json:"asset_id"`
	Action       connector.Action `json:"action"`
	UndoOf       *string          `json:"undo_of,omitempty"`
	State        string           `json:"state"`
	Plan         []string         `json:"plan"`
	Result       []string         `json:"result"`
	Undoable     bool             `json:"undoable"`
	Error        *string          `json:"error,omitempty"`
	Note         *string          `json:"note,omitempty"`
	RequestedBy  string           `json:"requested_by"`
	RequestedAt  time.Time        `json:"requested_at"`
	PlannedAt    *time.Time       `json:"planned_at,omitempty"`
	DecidedBy    *string          `json:"decided_by,omitempty"`
	DecidedAt    *time.Time       `json:"decided_at,omitempty"`
	DecisionNote *string          `json:"decision_note,omitempty"`
	ExecutedAt   *time.Time       `json:"executed_at,omitempty"`
}

const cols = `id::text, asset_id::text, action, undo_of::text, state, coalesce(plan, '{}'), coalesce(result, '{}'), undo IS NOT NULL,
	error, note, requested_by, requested_at, planned_at, decided_by, decided_at, decision_note, executed_at`

// Store is the request side (control-plane).
type Store struct {
	DB     *pgxpool.Pool
	Tenant string
}

func Open(ctx context.Context, db *pgxpool.Pool) error {
	if err := datascan.Open(ctx, db); err != nil { // data.assets must exist first
		return err
	}
	if _, err := db.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("apply remediation schema: %w", err)
	}
	return nil
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func list(ctx context.Context, q querier, where string, args ...any) ([]Remediation, error) {
	where, lock := strings.CutSuffix(where, " FOR UPDATE")
	sql := "SELECT " + cols + " FROM data.remediations " + where + " ORDER BY requested_at DESC"
	if lock {
		sql += " FOR UPDATE SKIP LOCKED"
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Remediation])
}

func one(ctx context.Context, q querier, where string, args ...any) (Remediation, error) {
	rs, err := list(ctx, q, where, args...)
	if err != nil {
		return Remediation{}, err
	}
	if len(rs) == 0 {
		return Remediation{}, ErrNotFound
	}
	return rs[0], nil
}

func (s *Store) tx(ctx context.Context, actor, action string, f func(pgx.Tx) (map[string]any, error)) error {
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		target, err := f(tx)
		if err != nil || target == nil {
			return err
		}
		_, err = audit.AppendTx(ctx, tx, s.Tenant, actor, action, target)
		return err
	})
}

var kinds = []string{connector.RevokeAnyoneLinks, connector.RemoveGrants, connector.ApplyLabel, connector.Quarantine}

// Request asks for a remediation of an asset. Nothing runs until it is planned and approved.
func (s *Store) Request(ctx context.Context, actor, assetID string, a connector.Action, note string, now time.Time) (Remediation, error) {
	switch {
	case !slices.Contains(kinds, a.Kind):
		return Remediation{}, fmt.Errorf("%w: kind must be one of %v", ErrInvalid, kinds)
	case a.Kind == connector.RemoveGrants && len(a.Grants) == 0:
		return Remediation{}, fmt.Errorf("%w: remove_grants needs grants", ErrInvalid)
	case a.Kind == connector.ApplyLabel && a.Label == "":
		return Remediation{}, fmt.Errorf("%w: apply_label needs a label", ErrInvalid)
	}
	var id string
	err := s.tx(ctx, actor, "data.remediation.request", func(tx pgx.Tx) (map[string]any, error) {
		var live bool
		if err := tx.QueryRow(ctx, "SELECT deleted_at IS NULL FROM data.assets WHERE id::text = $1", assetID).Scan(&live); err != nil || !live {
			return nil, ErrNotFound
		}
		err := tx.QueryRow(ctx, `INSERT INTO data.remediations (asset_id, action, state, note, requested_by, requested_at)
			VALUES ($1, $2, 'requested', $3, $4, $5) RETURNING id::text`, assetID, a, nullable(note), actor, now).Scan(&id)
		if err != nil && strings.Contains(err.Error(), "remediations_open") {
			return nil, fmt.Errorf("%w: the same remediation is already open for this asset", ErrState)
		}
		return map[string]any{"remediation_id": id, "asset_id": assetID, "action": a}, err
	})
	if err != nil {
		return Remediation{}, err
	}
	return s.Get(ctx, id)
}

// RequestUndo asks to reverse an executed remediation, when its source can.
func (s *Store) RequestUndo(ctx context.Context, actor, id, note string, now time.Time) (Remediation, error) {
	var nid string
	err := s.tx(ctx, actor, "data.remediation.undo.request", func(tx pgx.Tx) (map[string]any, error) {
		r, err := one(ctx, tx, "WHERE id::text = $1 FOR UPDATE", id)
		if err != nil {
			return nil, err
		}
		if r.State != "done" || !r.Undoable || r.UndoOf != nil {
			return nil, fmt.Errorf("%w: only an executed, restorable remediation can be undone", ErrState)
		}
		err = tx.QueryRow(ctx, `INSERT INTO data.remediations (asset_id, action, undo_of, state, note, requested_by, requested_at)
			VALUES ($1, '{"kind": "undo"}', $2, 'requested', $3, $4, $5) RETURNING id::text`, r.AssetID, id, nullable(note), actor, now).Scan(&nid)
		if err != nil && strings.Contains(err.Error(), "remediations_open") {
			return nil, fmt.Errorf("%w: an undo is already open", ErrState)
		}
		return map[string]any{"remediation_id": nid, "undo_of": id, "asset_id": r.AssetID}, err
	})
	if err != nil {
		return Remediation{}, err
	}
	return s.Get(ctx, nid)
}

// Decide approves or rejects a planned request. The approver must not be the requester, and must decide while
// the plan is fresh.
func (s *Store) Decide(ctx context.Context, actor, id string, approve bool, note string, now time.Time) (Remediation, error) {
	action, state := "data.remediation.reject", "rejected"
	if approve {
		action, state = "data.remediation.approve", "approved"
	}
	var expired bool
	err := s.tx(ctx, actor, action, func(tx pgx.Tx) (map[string]any, error) {
		r, err := one(ctx, tx, "WHERE id::text = $1 FOR UPDATE", id)
		if err != nil {
			return nil, err
		}
		if r.State != "planned" {
			return nil, fmt.Errorf("%w: %s (approval needs a dry-run plan)", ErrState, r.State)
		}
		if approve && strings.EqualFold(r.RequestedBy, actor) {
			return nil, ErrSelf
		}
		if now.Sub(*r.PlannedAt) > PlanTTL {
			_, err := tx.Exec(ctx, "UPDATE data.remediations SET state = 'expired' WHERE id = $1", r.ID)
			expired = true
			return nil, err
		}
		if _, err := tx.Exec(ctx, "UPDATE data.remediations SET state = $2, decided_by = $3, decided_at = $4, decision_note = $5 WHERE id = $1",
			r.ID, state, actor, now, nullable(note)); err != nil {
			return nil, err
		}
		return map[string]any{"remediation_id": id, "asset_id": r.AssetID, "action": r.Action, "plan": r.Plan, "state": state}, nil
	})
	if err == nil && expired {
		err = fmt.Errorf("%w: the plan is older than %v; request again", ErrState, PlanTTL)
	}
	if err != nil {
		return Remediation{}, err
	}
	return s.Get(ctx, id)
}

func (s *Store) Get(ctx context.Context, id string) (Remediation, error) {
	return one(ctx, s.DB, "WHERE id::text = $1", id)
}

func (s *Store) List(ctx context.Context, state, assetID string) ([]Remediation, error) {
	return list(ctx, s.DB, "WHERE ($1 = '' OR state = $1) AND ($2 = '' OR asset_id::text = $2)", state, assetID)
}

// --- the worker side ---

// Executor plans and executes requests with the sources' connectors (connector worker).
type Executor struct {
	DB       *pgxpool.Pool
	Tenant   string
	Scanners map[string]*datascan.Scanner // by source: its connector, and Refresh after a change
	Now      func() time.Time
	Log      *slog.Logger
}

const actor = "connector-worker"

type target struct {
	scanner *datascan.Scanner
	item    connector.Item
}

func (e *Executor) target(ctx context.Context, q pgx.Tx, assetID string) (target, error) {
	var source string
	var it connector.Item
	if err := q.QueryRow(ctx, "SELECT source_id, container_id, external_id, content_tag FROM data.assets WHERE id::text = $1", assetID).
		Scan(&source, &it.ContainerID, &it.ID, &it.ContentTag); err != nil {
		return target{}, err
	}
	sc, ok := e.Scanners[source]
	if !ok {
		return target{}, fmt.Errorf("%w: no connector for source %s here", connector.ErrNotSupported, source)
	}
	return target{sc, it}, nil
}

// apply runs the remediation (or undo) of r against its source, as a dry run or for real.
func (e *Executor) apply(ctx context.Context, tx pgx.Tx, r Remediation, t target, dryRun bool) (connector.Change, error) {
	if r.UndoOf == nil {
		return t.scanner.Conn.Remediate(ctx, t.item, r.Action, dryRun)
	}
	var undo json.RawMessage
	if err := tx.QueryRow(ctx, "SELECT undo FROM data.remediations WHERE id::text = $1", *r.UndoOf).Scan(&undo); err != nil {
		return connector.Change{}, err
	}
	return t.scanner.Conn.Undo(ctx, t.item, undo, dryRun)
}

// Run plans every requested remediation and executes every approved one; it returns how many it handled.
func (e *Executor) Run(ctx context.Context) (int, error) {
	n := 0
	for _, state := range []string{"requested", "approved"} {
		for {
			done, err := e.next(ctx, state)
			if err != nil {
				return n, err
			}
			if !done {
				break
			}
			n++
		}
	}
	return n, nil
}

// next handles one request in state; false when there is none.
func (e *Executor) next(ctx context.Context, state string) (bool, error) {
	found := false
	var refresh func()
	err := pgx.BeginFunc(ctx, e.DB, func(tx pgx.Tx) error {
		rs, err := list(ctx, tx, "WHERE state = $1 AND id = (SELECT id FROM data.remediations WHERE state = $1 ORDER BY requested_at LIMIT 1 FOR UPDATE SKIP LOCKED)", state)
		if err != nil || len(rs) == 0 {
			return err
		}
		found = true
		r := rs[0]
		if state == "requested" {
			return e.plan(ctx, tx, r)
		}
		refresh, err = e.execute(ctx, tx, r)
		return err
	})
	if err == nil && refresh != nil {
		refresh()
	}
	return found, err
}

func (e *Executor) record(ctx context.Context, tx pgx.Tx, action string, r Remediation, extra map[string]any) error {
	target := map[string]any{"remediation_id": r.ID, "asset_id": r.AssetID, "action": r.Action}
	for k, v := range extra {
		target[k] = v
	}
	_, err := audit.AppendTx(ctx, tx, e.Tenant, actor, action, target)
	return err
}

func (e *Executor) plan(ctx context.Context, tx pgx.Tx, r Remediation) error {
	t, err := e.target(ctx, tx, r.AssetID)
	var ch connector.Change
	if err == nil {
		ch, err = e.apply(ctx, tx, r, t, true)
	}
	now := e.Now()
	switch {
	case errors.Is(err, connector.ErrNothingToDo):
		_, err = tx.Exec(ctx, "UPDATE data.remediations SET state = 'nothing_to_do', planned_at = $2 WHERE id = $1", r.ID, now)
		if err == nil {
			err = e.record(ctx, tx, "data.remediation.nothing_to_do", r, nil)
		}
		return err
	case err != nil:
		_, err2 := tx.Exec(ctx, "UPDATE data.remediations SET state = 'failed', error = $2, planned_at = $3 WHERE id = $1", r.ID, "plan: "+err.Error(), now)
		if err2 == nil {
			err2 = e.record(ctx, tx, "data.remediation.plan_failed", r, map[string]any{"error": err.Error()})
		}
		return err2
	}
	if _, err := tx.Exec(ctx, "UPDATE data.remediations SET state = 'planned', plan = $2, planned_at = $3 WHERE id = $1", r.ID, ch.Steps, now); err != nil {
		return err
	}
	return e.record(ctx, tx, "data.remediation.plan", r, map[string]any{"plan": ch.Steps})
}

// execute runs an approved request whose plan still holds. It refuses anything not approved by someone other
// than the requester (the API enforces this too; the executor does not trust the row's history).
func (e *Executor) execute(ctx context.Context, tx pgx.Tx, r Remediation) (func(), error) {
	if r.State != "approved" || r.DecidedBy == nil || strings.EqualFold(*r.DecidedBy, r.RequestedBy) {
		return nil, fmt.Errorf("%w: %s", ErrNotApproved, r.ID)
	}
	t, err := e.target(ctx, tx, r.AssetID)
	var now = e.Now()
	fail := func(msg string) (func(), error) {
		if _, err := tx.Exec(ctx, "UPDATE data.remediations SET state = 'failed', error = $2, executed_at = $3 WHERE id = $1", r.ID, msg, now); err != nil {
			return nil, err
		}
		return nil, e.record(ctx, tx, "data.remediation.failed", r, map[string]any{"error": msg})
	}
	if err != nil {
		return fail(err.Error())
	}
	again, err := e.apply(ctx, tx, r, t, true)
	if err != nil || !slices.Equal(again.Steps, r.Plan) {
		// The source changed since the approver saw the plan: approving something else is not what happened.
		if _, err := tx.Exec(ctx, "UPDATE data.remediations SET state = 'stale', plan = $2, executed_at = $3 WHERE id = $1", r.ID, again.Steps, now); err != nil {
			return nil, err
		}
		return nil, e.record(ctx, tx, "data.remediation.stale", r, map[string]any{"approved_plan": r.Plan, "current_plan": again.Steps})
	}
	ch, err := e.apply(ctx, tx, r, t, false)
	if err != nil {
		// Partly done: the error names the step where it stopped; keep the undo data for what did happen.
		if _, err2 := tx.Exec(ctx, "UPDATE data.remediations SET undo = $2 WHERE id = $1", r.ID, ch.Undo); err2 != nil {
			return nil, err2
		}
		return fail("execute: " + err.Error())
	}
	if _, err := tx.Exec(ctx, "UPDATE data.remediations SET state = 'done', result = $2, undo = $3, executed_at = $4 WHERE id = $1",
		r.ID, ch.Steps, ch.Undo, now); err != nil {
		return nil, err
	}
	if r.UndoOf != nil {
		if _, err := tx.Exec(ctx, "UPDATE data.remediations SET state = 'undone' WHERE id::text = $1", *r.UndoOf); err != nil {
			return nil, err
		}
	}
	if err := e.record(ctx, tx, "data.remediation.execute", r, map[string]any{"steps": ch.Steps, "approved_by": *r.DecidedBy}); err != nil {
		return nil, err
	}
	return func() {
		if err := t.scanner.Refresh(ctx, r.AssetID); err != nil {
			e.Log.Error("refresh after remediation", "asset_id", r.AssetID, "err", err)
		}
	}, nil
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
