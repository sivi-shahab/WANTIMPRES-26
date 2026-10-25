package agents

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"wantimpres26/internal/audit"
)

// --- HITL approvals (FR-AGT-6, ticket 30) -------------------------------------------------------------------

var (
	ErrExpired  = errors.New("approval expired")
	ErrConflict = errors.New("approval is no longer pending")
	errSelf     = errors.New("approvers cannot approve actions of an agent they own")
)

// DefaultApprovalTTL: an unanswered (or unused) approval request is a deny after this long (spec: timeout = deny).
const DefaultApprovalTTL = 15 * time.Minute

// Approval is one request for a human to allow one exact tool call.
type Approval struct {
	ID          string         `json:"approval_id"`
	AgentID     string         `json:"agent_id"`
	Server      string         `json:"server"`
	Tool        string         `json:"tool"`
	ArgsDigest  string         `json:"args_digest"`
	Preview     map[string]any `json:"preview"` // arguments, secrets and card data redacted by the gateway
	ReasonCodes []string       `json:"reason_codes"`
	TraceID     *string        `json:"trace_id,omitempty"`
	State       string         `json:"state"` // pending | approved | rejected | expired | used
	RequestedAt time.Time      `json:"requested_at"`
	ExpiresAt   time.Time      `json:"expires_at"`
	DecidedBy   *string        `json:"decided_by,omitempty"`
	DecidedAt   *time.Time     `json:"decided_at,omitempty"`
	Note        *string        `json:"note,omitempty"`
	UsedAt      *time.Time     `json:"used_at,omitempty"`
}

const approvalCols = `id, agent_id, server, tool, args_digest, preview, reason_codes, trace_id, state, requested_at, expires_at,
	decided_by, decided_at, note, used_at`

func listApprovals(ctx context.Context, q querier, where string, args ...any) ([]Approval, error) {
	where, lock := strings.CutSuffix(where, " FOR UPDATE")
	sql := "SELECT " + approvalCols + " FROM agents.approvals " + where + " ORDER BY requested_at DESC"
	if lock {
		sql += " FOR UPDATE"
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Approval])
}

// expireApprovals turns every open approval past its deadline into expired (one key, or all when agent is "").
func expireApprovals(ctx context.Context, tx pgx.Tx, now time.Time, key ...any) error {
	sql := "UPDATE agents.approvals SET state = 'expired' WHERE state IN ('pending', 'approved') AND expires_at <= $1"
	args := []any{now}
	if len(key) == 4 {
		sql += " AND agent_id = $2 AND server = $3 AND tool = $4 AND args_digest = $5"
		args = append(args, key...)
	}
	_, err := tx.Exec(ctx, sql, args...)
	return err
}

// RequestApproval returns the open request for exactly this call, or opens one (and notifies approvers). Retries
// of the same call never pile up requests.
func (s *Store) RequestApproval(ctx context.Context, a Approval, now time.Time) (Approval, error) {
	if a.AgentID == "" || a.Server == "" || a.Tool == "" || len(a.ArgsDigest) != 64 || a.Preview == nil {
		return Approval{}, fmt.Errorf("%w: agent_id, server, tool, args_digest and preview are required", ErrInvalid)
	}
	created := false
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		key := []any{a.AgentID, a.Server, a.Tool, a.ArgsDigest}
		if err := expireApprovals(ctx, tx, now, key...); err != nil {
			return err
		}
		open, err := listApprovals(ctx, tx, "WHERE agent_id = $1 AND server = $2 AND tool = $3 AND args_digest = $4 AND state IN ('pending', 'approved')", key...)
		if err != nil || len(open) > 0 {
			if len(open) > 0 {
				a = open[0]
			}
			return err
		}
		b := make([]byte, 9)
		_, _ = rand.Read(b)
		a.ID, a.State, a.RequestedAt, a.ExpiresAt = "apr-"+hex.EncodeToString(b), "pending", now, now.Add(s.ApprovalTTL)
		if a.ReasonCodes == nil {
			a.ReasonCodes = []string{}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agents.approvals (id, agent_id, server, tool, args_digest, preview, reason_codes, trace_id, state, requested_at, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, a.ID, a.AgentID, a.Server, a.Tool, a.ArgsDigest, a.Preview, a.ReasonCodes, a.TraceID, a.State, a.RequestedAt, a.ExpiresAt); err != nil {
			return err
		}
		created = true
		_, err = audit.AppendTx(ctx, tx, s.tenant, "mcp-gateway", "approval.request", map[string]any{"approval_id": a.ID, "agent_id": a.AgentID,
			"server": a.Server, "tool": a.Tool, "args_digest": a.ArgsDigest, "reason_codes": a.ReasonCodes, "expires_at": a.ExpiresAt})
		return err
	})
	if err == nil && created && s.Notify != nil {
		go s.Notify(a) // after commit; best effort (ponytail: no outbox, a lost notice leaves the request in the queue)
	}
	return a, err
}

// ClaimApproval uses an approved, unexpired approval of exactly this call, once. ok is false when there is none.
func (s *Store) ClaimApproval(ctx context.Context, agentID, server, tool, digest string, now time.Time) (id string, ok bool, err error) {
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `UPDATE agents.approvals SET state = 'used', used_at = $5
			WHERE agent_id = $1 AND server = $2 AND tool = $3 AND args_digest = $4 AND state = 'approved' AND expires_at > $5 RETURNING id`,
			agentID, server, tool, digest, now).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		ok = true
		_, err = audit.AppendTx(ctx, tx, s.tenant, "mcp-gateway", "approval.used", map[string]any{"approval_id": id, "agent_id": agentID, "tool": tool})
		return err
	})
	return id, ok, err
}

// DecideApproval approves or rejects a pending request. The deadline is checked here too: an approval given after
// the timeout is refused (the request is a deny already). The approver may not own the agent, and allowed(agent)
// checks the approver's ABAC scope.
func (s *Store) DecideApproval(ctx context.Context, actor, id string, approve bool, note string, now time.Time, allowed func(Agent) error) (Approval, error) {
	state, action := "rejected", "approval.reject"
	if approve {
		state, action = "approved", "approval.approve"
	}
	var expired bool
	err := s.change(ctx, actor, action, func(tx pgx.Tx) (map[string]any, error) {
		as, err := listApprovals(ctx, tx, "WHERE id = $1 FOR UPDATE", id)
		if err != nil {
			return nil, err
		}
		if len(as) == 0 {
			return nil, ErrNotFound
		}
		a := as[0]
		if a.State == "pending" && !now.Before(a.ExpiresAt) {
			if _, err := tx.Exec(ctx, "UPDATE agents.approvals SET state = 'expired' WHERE id = $1", id); err != nil {
				return nil, err
			}
			expired = true
			return nil, nil // commit the expiry, no decision to audit
		}
		if a.State != "pending" {
			return nil, ErrConflict
		}
		ag, err := list(ctx, tx, "WHERE agent_id = $1", a.AgentID)
		if err != nil {
			return nil, err
		}
		if len(ag) > 0 {
			if ag[0].Owner != nil && *ag[0].Owner == actor {
				return nil, errSelf
			}
			if err := allowed(ag[0]); err != nil {
				return nil, err
			}
		}
		if _, err := tx.Exec(ctx, "UPDATE agents.approvals SET state = $2, decided_by = $3, decided_at = $4, note = $5 WHERE id = $1",
			id, state, actor, now, note); err != nil {
			return nil, err
		}
		return map[string]any{"approval_id": id, "agent_id": a.AgentID, "tool": a.Tool, "state": state, "note": note}, nil
	})
	if err == nil && expired {
		err = ErrExpired
	}
	if err != nil {
		return Approval{}, err
	}
	as, err := listApprovals(ctx, s.db, "WHERE id = $1", id)
	if err != nil || len(as) == 0 {
		return Approval{}, err
	}
	return as[0], nil
}

// Approvals lists requests (state "" = all), after expiring overdue ones.
func (s *Store) Approvals(ctx context.Context, state string, now time.Time) ([]Approval, error) {
	if err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error { return expireApprovals(ctx, tx, now) }); err != nil {
		return nil, err
	}
	return listApprovals(ctx, s.db, "WHERE $1 = '' OR state = $1", state)
}

func (s *Store) GetApproval(ctx context.Context, id string) (Approval, error) {
	as, err := listApprovals(ctx, s.db, "WHERE id = $1", id)
	if err != nil {
		return Approval{}, err
	}
	if len(as) == 0 {
		return Approval{}, ErrNotFound
	}
	return as[0], nil
}

// WebhookNotifier posts new approval requests to a chat webhook (Teams/Slack/Mattermost-compatible {"text"}).
// The message names the agent, tool and deadline and links to the request; arguments stay in the console.
func WebhookNotifier(url, publicURL string, client *http.Client, log *slog.Logger) func(Approval) {
	return func(a Approval) {
		text := fmt.Sprintf("WANTIMPRES-26: agent %s asks to call %s on %s (%s). Approve or reject before %s: %s/approvals/%s",
			a.AgentID, a.Tool, a.Server, strings.Join(a.ReasonCodes, ", "), a.ExpiresAt.Format(time.RFC3339), strings.TrimSuffix(publicURL, "/"), a.ID)
		body, _ := json.Marshal(map[string]string{"text": text})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			log.Error("approval notice", "err", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			log.Error("approval notice", "approval_id", a.ID, "err", err)
			return
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 {
			log.Error("approval notice", "approval_id", a.ID, "status", resp.StatusCode)
		}
	}
}
