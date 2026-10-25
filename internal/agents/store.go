// Package agents is the agent registry (spec §4.8 FR-AGT-1/2): who owns each AI agent, what it is for, which
// workload identity it runs as, which tools it may call. The registry is the PDP's source of truth for whether an
// agent is registered (wantimpres26/agent), agents without an active owner are quarantined automatically, and agents
// seen in traffic but not registered wait in a review queue.
package agents

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/events"
	"wantimpres26/internal/identity"
	"wantimpres26/internal/lifecycle"
	"wantimpres26/internal/policysvc"
	"wantimpres26/internal/toolscope"
)

//go:embed schema.sql
var schemaSQL string

var (
	ErrNotFound = errors.New("not found")
	ErrInvalid  = errors.New("invalid")
)

// Tool is one allow-listed tool. Scopes are parameter limits and a rate (FR-AGT-4, format in toolscope), enforced
// by the MCP gateway.
type Tool struct {
	Name   string         `json:"name"`
	Risk   string         `json:"risk"` // low | medium | high
	Scopes map[string]any `json:"scopes,omitempty"`
	// WritesMemory: the tool writes the agent's long-term memory or a vector store (FR-AGT-9); the gateway holds
	// such writes to stricter injection rules and records their provenance.
	WritesMemory bool `json:"writes_memory,omitempty"`
}

// Identity is the agent's workload identity (FR-AGT-2). Shared user credentials are refused.
type Identity struct {
	Type string `json:"type"` // spiffe | oidc_client | managed_identity
	Ref  string `json:"ref"`
}

// Agent is a registry entry.
type Agent struct {
	ID           string    `json:"agent_id"`
	Name         string    `json:"name"`
	Owner        *string   `json:"owner"`
	BusinessUnit string    `json:"business_unit"`
	Purpose      string    `json:"purpose"`
	Model        *string   `json:"model,omitempty"`
	Framework    *string   `json:"framework,omitempty"`
	Environment  string    `json:"environment"`
	Identity     Identity  `json:"identity"`
	Tools        []Tool    `json:"tools"`
	DataScopes   []string  `json:"data_scopes"`
	RiskTier     string    `json:"risk_tier"`
	Status       string    `json:"status"`
	StatusReason *string   `json:"status_reason,omitempty"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedBy    string    `json:"updated_by"`
	UpdatedAt    time.Time `json:"updated_at"`
}

var (
	idRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	spiffeRe   = regexp.MustCompile(`^spiffe://[a-z0-9.-]+(/[A-Za-z0-9._~%!$&'()*+,;=:@-]+)+$`)
	clientRe   = regexp.MustCompile(`^[A-Za-z0-9._:-]{3,128}$`)
	managedRe  = regexp.MustCompile(`^(arn:aws[a-z-]*:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com)$`)
	Statuses   = []string{"active", "quarantined", "suspended", "retired"}
	riskTiers  = []string{"low", "medium", "high", "critical"}
	toolRisks  = []string{"low", "medium", "high"}
	envs       = []string{"dev", "staging", "prod"}
	NoOwner    = "no active owner"
	quarantine = "quarantined"
)

// validate checks the entry's own fields; owner activity and identity reuse need the database.
func (a Agent) validate() error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
	}
	switch {
	case !idRe.MatchString(a.ID):
		return bad("agent_id %q", a.ID)
	case strings.TrimSpace(a.Name) == "" || strings.TrimSpace(a.Purpose) == "" || strings.TrimSpace(a.BusinessUnit) == "":
		return bad("name, purpose and business_unit are required")
	case !slices.Contains(envs, a.Environment):
		return bad("environment %q", a.Environment)
	case !slices.Contains(riskTiers, a.RiskTier):
		return bad("risk_tier %q", a.RiskTier)
	}
	switch a.Identity.Type {
	case "spiffe":
		if !spiffeRe.MatchString(a.Identity.Ref) {
			return bad("SPIFFE ID %q", a.Identity.Ref)
		}
	case "oidc_client":
		if !clientRe.MatchString(a.Identity.Ref) {
			return bad("OIDC client id %q (a user account is not a workload identity)", a.Identity.Ref)
		}
	case "managed_identity":
		if !managedRe.MatchString(a.Identity.Ref) {
			return bad("managed identity %q (AWS role ARN, Azure object id or GCP service account)", a.Identity.Ref)
		}
	default:
		return bad("identity type %q: use spiffe, oidc_client or managed_identity; shared user credentials are not allowed", a.Identity.Type)
	}
	seen := map[string]bool{}
	for _, t := range a.Tools {
		if strings.TrimSpace(t.Name) == "" || seen[t.Name] || !slices.Contains(toolRisks, t.Risk) {
			return bad("tool %q: unique name and risk low|medium|high", t.Name)
		}
		seen[t.Name] = true
		if err := toolscope.Validate(t.Scopes); err != nil {
			return bad("tool %q: %v", t.Name, err)
		}
	}
	return nil
}

// Store is the registry (schema agents). Every change is audited and published as a policy release in one
// transaction, so the PDP sees status changes with the next bundle.
// Owners are identity users (SCIM, ticket 06) in the same database.
type Store struct {
	db       *pgxpool.Pool
	tenant   string
	policies *lifecycle.Store

	ApprovalTTL time.Duration  // HITL request lifetime (DefaultApprovalTTL)
	Notify      func(Approval) // tells approvers about a new request; nil = none
}

func Open(ctx context.Context, db *pgxpool.Pool, tenant string, policies *lifecycle.Store) (*Store, error) {
	if _, err := db.Exec(ctx, schemaSQL); err != nil {
		return nil, fmt.Errorf("apply agents schema: %w", err)
	}
	s := &Store{db: db, tenant: tenant, policies: policies, ApprovalTTL: DefaultApprovalTTL}
	policies.AddExtra(s.releaseDoc)
	return s, nil
}

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

const cols = `agent_id, name, owner, business_unit, purpose, model, framework, environment, identity_type, identity_ref,
	tools, data_scopes, risk_tier, status, status_reason, created_by, created_at, updated_by, updated_at`

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// list selects agents; a where ending in "FOR UPDATE" locks the rows (the clause has to follow ORDER BY).
func list(ctx context.Context, q querier, where string, args ...any) ([]Agent, error) {
	where, lock := strings.CutSuffix(where, " FOR UPDATE")
	sql := "SELECT " + cols + " FROM agents.agents " + where + " ORDER BY agent_id"
	if lock {
		sql += " FOR UPDATE"
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Agent, error) {
		var a Agent
		err := r.Scan(&a.ID, &a.Name, &a.Owner, &a.BusinessUnit, &a.Purpose, &a.Model, &a.Framework, &a.Environment, &a.Identity.Type,
			&a.Identity.Ref, &a.Tools, &a.DataScopes, &a.RiskTier, &a.Status, &a.StatusReason, &a.CreatedBy, &a.CreatedAt, &a.UpdatedBy, &a.UpdatedAt)
		return a, err
	})
}

func (s *Store) List(ctx context.Context, status string) ([]Agent, error) {
	return list(ctx, s.db, "WHERE ($1 = '' OR status = $1)", status)
}

func (s *Store) Get(ctx context.Context, id string) (Agent, error) {
	as, err := list(ctx, s.db, "WHERE agent_id = $1", id)
	if err != nil {
		return Agent{}, err
	}
	if len(as) == 0 {
		return Agent{}, ErrNotFound
	}
	return as[0], nil
}

// releaseDoc is data.wantimpres26.agents: what the PDP needs per agent (wantimpres26/agent), and what the MCP gateway needs to
// map a workload identity to its agent and enforce tool scopes (wantimpres26/mcp).
func (s *Store) releaseDoc(ctx context.Context, tx pgx.Tx) (policysvc.Overrides, error) {
	as, err := list(ctx, tx, "")
	if err != nil {
		return nil, err
	}
	items := map[string]any{}
	for _, a := range as {
		items[a.ID] = map[string]any{"status": a.Status, "risk_tier": a.RiskTier, "identity": a.Identity.Ref, "tools": a.Tools}
	}
	tools, err := toolsDoc(ctx, tx)
	if err != nil {
		return nil, err
	}
	kills, err := killsDoc(ctx, tx)
	if err != nil {
		return nil, err
	}
	return policysvc.Overrides{"wantimpres26.agents": map[string]any{"version": len(as), "items": items}, "wantimpres26.mcp_tools": tools, "wantimpres26.kills": kills}, nil
}

// settle decides the status an entry may have: without an active owner it is quarantined, whatever was asked.
func (s *Store) settle(ctx context.Context, tx pgx.Tx, a *Agent) error {
	active := false
	if a.Owner != nil && strings.TrimSpace(*a.Owner) != "" {
		var err error
		if active, err = identity.UserActive(ctx, tx, *a.Owner); err != nil {
			return err
		}
	}
	if !active && a.Status != "retired" {
		a.Status, a.StatusReason = quarantine, &NoOwner
	}
	return nil
}

// sharedCredential refuses identities that are really user accounts (FR-AGT-2).
func (s *Store) sharedCredential(ctx context.Context, tx pgx.Tx, id Identity) error {
	if id.Type != "managed_identity" && strings.Contains(id.Ref, "@") {
		return fmt.Errorf("%w: identity %q looks like a user account", ErrInvalid, id.Ref)
	}
	exists, err := identity.UserExists(ctx, tx, id.Ref)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: identity %q is a user account; shared user credentials are not allowed", ErrInvalid, id.Ref)
	}
	return nil
}

func (s *Store) write(ctx context.Context, tx pgx.Tx, actor string, a Agent, insert bool) error {
	q := `INSERT INTO agents.agents (agent_id, name, owner, business_unit, purpose, model, framework, environment, identity_type, identity_ref,
		tools, data_scopes, risk_tier, status, status_reason, created_by, updated_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$16)`
	if !insert {
		q = `UPDATE agents.agents SET name=$2, owner=$3, business_unit=$4, purpose=$5, model=$6, framework=$7, environment=$8, identity_type=$9,
			identity_ref=$10, tools=$11, data_scopes=$12, risk_tier=$13, status=$14, status_reason=$15, updated_by=$16, updated_at=now() WHERE agent_id=$1`
	}
	if a.Tools == nil {
		a.Tools = []Tool{}
	}
	if a.DataScopes == nil {
		a.DataScopes = []string{}
	}
	_, err := tx.Exec(ctx, q, a.ID, a.Name, a.Owner, a.BusinessUnit, a.Purpose, a.Model, a.Framework, a.Environment, a.Identity.Type,
		a.Identity.Ref, a.Tools, a.DataScopes, a.RiskTier, a.Status, a.StatusReason, actor)
	if err != nil && strings.Contains(err.Error(), "23505") {
		return fmt.Errorf("%w: agent id or workload identity already registered (identities are not shared)", ErrInvalid)
	}
	return err
}

func summary(a Agent) map[string]any {
	return map[string]any{"agent": a.ID, "owner": a.Owner, "business_unit": a.BusinessUnit, "status": a.Status, "status_reason": a.StatusReason,
		"identity": a.Identity, "risk_tier": a.RiskTier, "tools": len(a.Tools)}
}

// Register adds an agent (active when it has an active owner, quarantined otherwise) and closes a matching
// review-queue entry.
func (s *Store) Register(ctx context.Context, actor string, a Agent) (Agent, error) {
	a.Status, a.StatusReason = "active", nil
	if err := a.validate(); err != nil {
		return Agent{}, err
	}
	err := s.change(ctx, actor, "agent.register", func(tx pgx.Tx) (map[string]any, error) {
		if err := s.sharedCredential(ctx, tx, a.Identity); err != nil {
			return nil, err
		}
		if err := s.settle(ctx, tx, &a); err != nil {
			return nil, err
		}
		if err := s.write(ctx, tx, actor, a, true); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, "UPDATE agents.discovered SET state = 'registered', decided_by = $2, decided_at = now() WHERE agent_id = $1 AND state = 'pending'", a.ID, actor); err != nil {
			return nil, err
		}
		n, err := s.policies.CutRelease(ctx, tx, actor, "agent register "+a.ID)
		t := summary(a)
		t["release"] = n
		return t, err
	})
	if err != nil {
		return Agent{}, err
	}
	return s.Get(ctx, a.ID)
}

// Update replaces an agent's definition (not its id). Status follows the owner: losing it quarantines.
func (s *Store) Update(ctx context.Context, actor string, a Agent) (Agent, error) {
	if err := a.validate(); err != nil {
		return Agent{}, err
	}
	err := s.change(ctx, actor, "agent.update", func(tx pgx.Tx) (map[string]any, error) {
		cur, err := list(ctx, tx, "WHERE agent_id = $1 FOR UPDATE", a.ID)
		if err != nil {
			return nil, err
		}
		if len(cur) == 0 {
			return nil, ErrNotFound
		}
		if cur[0].Identity != a.Identity {
			if err := s.sharedCredential(ctx, tx, a.Identity); err != nil {
				return nil, err
			}
		}
		a.Status, a.StatusReason = cur[0].Status, cur[0].StatusReason
		if a.Status == quarantine && a.StatusReason != nil && *a.StatusReason == NoOwner {
			a.Status, a.StatusReason = "active", nil // an owner may have been added: settle decides
		}
		if err := s.settle(ctx, tx, &a); err != nil {
			return nil, err
		}
		if err := s.write(ctx, tx, actor, a, false); err != nil {
			return nil, err
		}
		n, err := s.policies.CutRelease(ctx, tx, actor, "agent update "+a.ID)
		return map[string]any{"before": summary(cur[0]), "after": summary(a), "release": n}, err
	})
	if err != nil {
		return Agent{}, err
	}
	return s.Get(ctx, a.ID)
}

// SetStatus changes status with a reason. Activation needs an active owner.
func (s *Store) SetStatus(ctx context.Context, actor, id, status, reason string) (Agent, error) {
	if !slices.Contains(Statuses, status) || strings.TrimSpace(reason) == "" {
		return Agent{}, fmt.Errorf("%w: status %q with a reason", ErrInvalid, status)
	}
	err := s.change(ctx, actor, "agent.status", func(tx pgx.Tx) (map[string]any, error) {
		cur, err := list(ctx, tx, "WHERE agent_id = $1 FOR UPDATE", id)
		if err != nil {
			return nil, err
		}
		if len(cur) == 0 {
			return nil, ErrNotFound
		}
		a := cur[0]
		from := a.Status
		a.Status, a.StatusReason = status, &reason
		if err := s.settle(ctx, tx, &a); err != nil {
			return nil, err
		}
		if status == "active" && a.Status != "active" {
			return nil, fmt.Errorf("%w: %s has no active owner and stays quarantined", ErrInvalid, id)
		}
		if err := s.write(ctx, tx, actor, a, false); err != nil {
			return nil, err
		}
		n, err := s.policies.CutRelease(ctx, tx, actor, fmt.Sprintf("agent %s %s -> %s", id, from, a.Status))
		return map[string]any{"agent": id, "from": from, "to": a.Status, "reason": reason, "release": n}, err
	})
	if err != nil {
		return Agent{}, err
	}
	return s.Get(ctx, id)
}

// Reconcile quarantines agents whose owner left or was deactivated (SCIM), in one audited release.
func (s *Store) Reconcile(ctx context.Context) (int, error) {
	var ids []string
	err := s.change(ctx, "system", "agent.quarantine", func(tx pgx.Tx) (map[string]any, error) {
		as, err := list(ctx, tx, "WHERE status IN ('active', 'suspended') FOR UPDATE")
		if err != nil {
			return nil, err
		}
		for _, a := range as {
			before := a.Status
			if err := s.settle(ctx, tx, &a); err != nil {
				return nil, err
			}
			if a.Status != before {
				if err := s.write(ctx, tx, "system", a, false); err != nil {
					return nil, err
				}
				ids = append(ids, a.ID)
			}
		}
		if len(ids) == 0 {
			return nil, nil
		}
		n, err := s.policies.CutRelease(ctx, tx, "system", fmt.Sprintf("quarantine %d agent(s) without an active owner", len(ids)))
		return map[string]any{"agents": ids, "reason": NoOwner, "release": n}, err
	})
	return len(ids), err
}

// --- shadow agents ------------------------------------------------------------------------------------------

// Handle is the events.Handler that queues agents seen in traffic but not registered.
func (s *Store) Handle(ctx context.Context, e events.Event, _ []byte) error {
	if e.AgentID == "" {
		return nil
	}
	ts, err := time.Parse(time.RFC3339Nano, e.TS)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `INSERT INTO agents.discovered (agent_id, source, state, first_seen, last_seen, events)
		SELECT $1, 'mcp_traffic', 'pending', $2, $2, 1 WHERE NOT EXISTS (SELECT 1 FROM agents.agents WHERE agent_id = $1)
		ON CONFLICT (agent_id) DO UPDATE SET last_seen = greatest(agents.discovered.last_seen, $2), events = agents.discovered.events + 1`, e.AgentID, ts)
	return err
}

// Discovered is a review-queue entry.
type Discovered struct {
	AgentID   string     `json:"agent_id"`
	Source    string     `json:"source"`
	State     string     `json:"state"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
	Events    int64      `json:"events"`
	DecidedBy *string    `json:"decided_by,omitempty"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`
	Note      *string    `json:"note,omitempty"`
}

func (s *Store) Discovered(ctx context.Context, state string) ([]Discovered, error) {
	rows, err := s.db.Query(ctx, `SELECT agent_id, source, state, first_seen, last_seen, events, decided_by, decided_at, note
		FROM agents.discovered WHERE ($1 = '' OR state = $1) ORDER BY last_seen DESC`, state)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Discovered])
}

// Dismiss closes a review-queue entry without registering (e.g. a test agent).
func (s *Store) Dismiss(ctx context.Context, actor, id, note string) error {
	if strings.TrimSpace(note) == "" {
		return fmt.Errorf("%w: a note is required", ErrInvalid)
	}
	return s.change(ctx, actor, "agent.discovered.dismiss", func(tx pgx.Tx) (map[string]any, error) {
		tag, err := tx.Exec(ctx, "UPDATE agents.discovered SET state = 'dismissed', decided_by = $2, decided_at = now(), note = $3 WHERE agent_id = $1 AND state = 'pending'", id, actor, note)
		if err == nil && tag.RowsAffected() == 0 {
			err = ErrNotFound
		}
		return map[string]any{"agent": id, "note": note}, err
	})
}

// --- the §1.5 metric -----------------------------------------------------------------------------------------

// Summary is the registry's posture: the "active agents without owner & policy" metric (target 0) is
// WithoutOwnerOrPolicy, where policy = a tool allow-list (FR-AGT-4).
type Summary struct {
	Total                int            `json:"total"`
	ByStatus             map[string]int `json:"by_status"`
	WithoutOwnerOrPolicy []string       `json:"active_without_owner_or_policy"`
	PendingReview        int            `json:"pending_review"`
}

func (s *Store) Summarize(ctx context.Context) (Summary, error) {
	sum := Summary{ByStatus: map[string]int{}, WithoutOwnerOrPolicy: []string{}}
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		as, err := list(ctx, tx, "")
		if err != nil {
			return err
		}
		for _, a := range as {
			sum.Total++
			sum.ByStatus[a.Status]++
			if a.Status != "active" {
				continue
			}
			owned := false
			if a.Owner != nil {
				if owned, err = identity.UserActive(ctx, tx, *a.Owner); err != nil {
					return err
				}
			}
			if !owned || len(a.Tools) == 0 {
				sum.WithoutOwnerOrPolicy = append(sum.WithoutOwnerOrPolicy, a.ID)
			}
		}
		return tx.QueryRow(ctx, "SELECT count(*) FROM agents.discovered WHERE state = 'pending'").Scan(&sum.PendingReview)
	})
	return sum, err
}
