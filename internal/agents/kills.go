package agents

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// --- kill switch (FR-AGT-7, ticket 30) ----------------------------------------------------------------------

// Kill is one kill switch. Active while LiftedAt is nil.
type Kill struct {
	ID        int64      `json:"id"`
	Scope     string     `json:"scope"` // agent | tool | app | global
	Target    string     `json:"target"`
	Reason    string     `json:"reason"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	LiftedBy  *string    `json:"lifted_by,omitempty"`
	LiftedAt  *time.Time `json:"lifted_at,omitempty"`
}

var killScopes = []string{"agent", "tool", "app", "global"}

const killCols = "id, scope, target, reason, created_by, created_at, lifted_by, lifted_at"

func listKills(ctx context.Context, q querier, where string, args ...any) ([]Kill, error) {
	where, lock := strings.CutSuffix(where, " FOR UPDATE")
	sql := "SELECT " + killCols + " FROM agents.kills " + where + " ORDER BY id"
	if lock {
		sql += " FOR UPDATE"
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Kill])
}

// SetKill turns a kill switch on and releases it in the same transaction: every PDP blocks the scope with the
// next bundle and the MCP gateways cut its sessions. Killing what is already killed returns the active switch.
func (s *Store) SetKill(ctx context.Context, actor, scope, target, reason string) (Kill, error) {
	if !slices.Contains(killScopes, scope) || (scope == "global") != (target == "") || strings.TrimSpace(reason) == "" {
		return Kill{}, fmt.Errorf("%w: scope agent|tool|app with a target, or global without; and a reason", ErrInvalid)
	}
	var k Kill
	err := s.change(ctx, actor, "agent.kill", func(tx pgx.Tx) (map[string]any, error) {
		err := tx.QueryRow(ctx, `INSERT INTO agents.kills (scope, target, reason, created_by) VALUES ($1, $2, $3, $4)
			ON CONFLICT (scope, target) WHERE lifted_at IS NULL DO NOTHING RETURNING `+killCols, scope, target, reason, actor).
			Scan(&k.ID, &k.Scope, &k.Target, &k.Reason, &k.CreatedBy, &k.CreatedAt, &k.LiftedBy, &k.LiftedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			ks, err := listKills(ctx, tx, "WHERE scope = $1 AND target = $2 AND lifted_at IS NULL", scope, target)
			if err == nil && len(ks) > 0 {
				k = ks[0]
			}
			return nil, err // already active: nothing to audit or release
		}
		if err != nil {
			return nil, err
		}
		n, err := s.policies.CutRelease(ctx, tx, actor, fmt.Sprintf("kill switch %s %s", scope, target))
		return map[string]any{"kill_id": k.ID, "scope": scope, "target": target, "reason": reason, "release": n}, err
	})
	return k, err
}

// LiftKill turns a kill switch off. global says whether the caller may lift a global one.
func (s *Store) LiftKill(ctx context.Context, actor string, id int64, global bool) (Kill, error) {
	var k Kill
	err := s.change(ctx, actor, "agent.kill.lift", func(tx pgx.Tx) (map[string]any, error) {
		ks, err := listKills(ctx, tx, "WHERE id = $1 AND lifted_at IS NULL FOR UPDATE", id)
		if err != nil {
			return nil, err
		}
		if len(ks) == 0 {
			return nil, ErrNotFound
		}
		if (ks[0].Scope == "global") != global {
			return nil, errScope
		}
		if _, err := tx.Exec(ctx, "UPDATE agents.kills SET lifted_by = $2, lifted_at = now() WHERE id = $1", id, actor); err != nil {
			return nil, err
		}
		k = ks[0]
		n, err := s.policies.CutRelease(ctx, tx, actor, fmt.Sprintf("lift kill switch %s %s", k.Scope, k.Target))
		return map[string]any{"kill_id": id, "scope": k.Scope, "target": k.Target, "release": n}, err
	})
	if err != nil {
		return Kill{}, err
	}
	ks, err := listKills(ctx, s.db, "WHERE id = $1", id)
	if err != nil || len(ks) == 0 {
		return Kill{}, err
	}
	return ks[0], nil
}

// Kills lists kill switches; active only, or all.
func (s *Store) Kills(ctx context.Context, activeOnly bool) ([]Kill, error) {
	if activeOnly {
		return listKills(ctx, s.db, "WHERE lifted_at IS NULL")
	}
	return listKills(ctx, s.db, "")
}

// killsDoc is data.wantimpres26.kills: {global, agent: {id: reason}, tool: {…}, app: {…}} (wantimpres26/agent).
func killsDoc(ctx context.Context, tx pgx.Tx) (map[string]any, error) {
	ks, err := listKills(ctx, tx, "WHERE lifted_at IS NULL")
	if err != nil {
		return nil, err
	}
	doc := map[string]any{"version": len(ks), "global": false, "agent": map[string]any{}, "tool": map[string]any{}, "app": map[string]any{}}
	for _, k := range ks {
		if k.Scope == "global" {
			doc["global"] = true
		} else {
			doc[k.Scope].(map[string]any)[k.Target] = k.Reason
		}
	}
	return doc, nil
}
