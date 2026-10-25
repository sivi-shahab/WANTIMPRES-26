package incident

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/authz"
	"wantimpres26/internal/policysvc"
)

// FR-INC-5 containment actions. Each is a named Action; the incident module brings block_access (this principal to
// this app) and open_ticket (ITSM), the control-plane adds the ones other modules own (kill switch, agent
// suspension, share-link revocation). Every action taken is recorded on the incident and audited, and goes into
// the breach report as handling.

// Action is one containment step. Perm, if set, is needed on top of incident.write (a SOC analyst may block a user
// from an app, but killing an agent stays with whoever may do that in the agent registry).
type Action struct {
	Perm string
	Run  func(ctx context.Context, actor string, inc Incident, params map[string]string, now time.Time) (map[string]any, error)
}

// ActionRecord is a containment action taken.
type ActionRecord struct {
	ID     int64             `json:"id"`
	Action string            `json:"action"`
	Params map[string]string `json:"params"`
	Result map[string]any    `json:"result"`
	Actor  string            `json:"actor"`
	At     time.Time         `json:"at"`
}

// Contain runs a containment action on an open incident and records it.
func (s *Store) Contain(ctx context.Context, c authz.Caller, id, name string, params map[string]string, now time.Time) (ActionRecord, error) {
	a, ok := s.Actions[name]
	if !ok {
		return ActionRecord{}, fmt.Errorf("%w: unknown action %q (have %s)", ErrInvalid, name, strings.Join(slices.Sorted(maps.Keys(s.Actions)), ", "))
	}
	inc, err := s.Get(ctx, id)
	if err != nil {
		return ActionRecord{}, err
	}
	if a.Perm != "" && !c.Can(a.Perm, authz.Resource{}, now) {
		if _, err := s.audit.Append(ctx, inc.TenantID, c.Username, "incident.contain.denied", map[string]any{"incident": id, "action": name,
			"denied": "missing permission " + a.Perm}); err != nil {
			return ActionRecord{}, err
		}
		return ActionRecord{}, fmt.Errorf("%w: %s needs %s", ErrForbidden, name, a.Perm)
	}
	if params == nil {
		params = map[string]string{}
	}
	result, err := a.Run(ctx, c.Username, inc, params, now)
	if err != nil {
		return ActionRecord{}, err
	}
	rec := ActionRecord{Action: name, Params: params, Result: result, Actor: c.Username, At: now}
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "INSERT INTO incident.actions (incident_id, action, params, result, actor, at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
			id, name, params, result, c.Username, now).Scan(&rec.ID); err != nil {
			return err
		}
		_, err := audit.AppendTx(ctx, tx, inc.TenantID, c.Username, "incident.contain", map[string]any{"incident": id, "action": name,
			"params": params, "result": result})
		return err
	})
	return rec, err
}

// ActionsOf lists the containment actions taken on an incident.
func (s *Store) ActionsOf(ctx context.Context, id string) ([]ActionRecord, error) {
	rows, err := s.db.Query(ctx, "SELECT id, action, params, result, actor, at FROM incident.actions WHERE incident_id = $1 ORDER BY at, id", id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[ActionRecord])
}

// --- block_access -------------------------------------------------------------------------------------------

// MaxBlock caps a containment block; longer means a policy change (with its approval), not containment.
const MaxBlock = 30 * 24 * time.Hour

// Block is a containment block (data.wantimpres26.containment.blocks).
type Block struct {
	ID          int64      `json:"id"`
	PrincipalID string     `json:"principal_id"`
	AppID       string     `json:"app_id"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CreatedBy   string     `json:"created_by"`
	LiftedBy    *string    `json:"lifted_by,omitempty"`
	LiftedAt    *time.Time `json:"lifted_at,omitempty"`
}

// blockAccess blocks the incident's principals from the incident's apps (every pair seen in its events, or the one
// named by principal_id/app_id, which must be one of them) for hours (default 72) and cuts a policy release.
func (s *Store) blockAccess(ctx context.Context, actor string, inc Incident, p map[string]string, now time.Time) (map[string]any, error) {
	if s.Release == nil {
		return nil, fmt.Errorf("%w: policy releases are not wired", ErrInvalid)
	}
	ttl := 72 * time.Hour
	if h := p["hours"]; h != "" {
		n, err := strconv.Atoi(h)
		if err != nil || n < 1 || time.Duration(n)*time.Hour > MaxBlock {
			return nil, fmt.Errorf("%w: hours must be 1..%d", ErrInvalid, int(MaxBlock.Hours()))
		}
		ttl = time.Duration(n) * time.Hour
	}
	out := map[string]any{}
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT event->>'principal_id', event->>'app_id' FROM incident.incident_events
			WHERE incident_id = $1 AND ($2 = '' OR event->>'principal_id' = $2) AND ($3 = '' OR event->>'app_id' = $3)`, inc.ID, p["principal_id"], p["app_id"])
		if err != nil {
			return err
		}
		pairs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (p [2]string, err error) { return p, r.Scan(&p[0], &p[1]) })
		if err != nil {
			return err
		}
		if len(pairs) == 0 {
			return fmt.Errorf("%w: no event of this incident has that principal and app", ErrInvalid)
		}
		var ids []int64
		for _, pr := range pairs {
			var bid int64
			if err := tx.QueryRow(ctx, `INSERT INTO incident.blocks (tenant_id, incident_id, principal_id, app_id, expires_at, created_by, created_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`, inc.TenantID, inc.ID, pr[0], pr[1], now.Add(ttl), actor, now).Scan(&bid); err != nil {
				return err
			}
			ids = append(ids, bid)
		}
		n, err := s.Release(ctx, tx, actor, "containment block, incident "+inc.ID)
		out["blocks"], out["expires_at"], out["release"] = ids, now.Add(ttl), n
		return err
	})
	return out, err
}

// LiftBlock ends a containment block early and cuts a release.
func (s *Store) LiftBlock(ctx context.Context, id string, block int64, actor string, now time.Time) (int64, error) {
	if s.Release == nil {
		return 0, fmt.Errorf("%w: policy releases are not wired", ErrInvalid)
	}
	var n int64
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var tenant string
		err := tx.QueryRow(ctx, `UPDATE incident.blocks SET lifted_by = $3, lifted_at = $4
			WHERE id = $1 AND incident_id = $2 AND lifted_at IS NULL RETURNING tenant_id::text`, block, id, actor, now).Scan(&tenant)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if n, err = s.Release(ctx, tx, actor, fmt.Sprintf("lift containment block %d, incident %s", block, id)); err != nil {
			return err
		}
		_, err = audit.AppendTx(ctx, tx, tenant, actor, "incident.block.lift", map[string]any{"incident": id, "block": block, "release": n})
		return err
	})
	return n, err
}

// BlocksOf lists an incident's containment blocks.
func (s *Store) BlocksOf(ctx context.Context, id string) ([]Block, error) {
	rows, err := s.db.Query(ctx, `SELECT id, principal_id, app_id, expires_at, created_by, lifted_by, lifted_at FROM incident.blocks
		WHERE incident_id = $1 ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Block])
}

// ContainmentDoc is data.wantimpres26.containment for lifecycle.AddExtra: the tenant's blocks that are neither lifted nor
// expired. The PDP checks expires_at itself, so a block ends on time without another release.
func ContainmentDoc(tenant string) func(ctx context.Context, tx pgx.Tx) (policysvc.Overrides, error) {
	return func(ctx context.Context, tx pgx.Tx) (policysvc.Overrides, error) {
		rows, err := tx.Query(ctx, `SELECT principal_id, app_id, expires_at, incident_id::text FROM incident.blocks
			WHERE tenant_id = $1 AND lifted_at IS NULL AND expires_at > now() ORDER BY id`, tenant)
		if err != nil {
			return nil, err
		}
		blocks := []any{}
		for rows.Next() {
			var principal, app, incident string
			var exp time.Time
			if err := rows.Scan(&principal, &app, &exp, &incident); err != nil {
				return nil, err
			}
			blocks = append(blocks, map[string]any{"principal_id": principal, "app_id": app, "expires_at": exp.UTC().Format(time.RFC3339), "incident": incident})
		}
		return policysvc.Overrides{"wantimpres26.containment": map[string]any{"blocks": blocks}}, rows.Err()
	}
}

// --- ITSM ---------------------------------------------------------------------------------------------------

// Ticketer opens a ticket in the bank's ITSM.
type Ticketer interface {
	Name() string
	Open(ctx context.Context, t Ticket) (ref, url string, err error)
}

// Ticket is what goes to the ITSM: metadata only, never content (the title names classes, app and channel).
type Ticket struct {
	IncidentID, Title, Severity, Description string
}

// TicketRef is an incident's ITSM ticket.
type TicketRef struct {
	System    string    `json:"system"`
	Ref       string    `json:"ref"`
	URL       string    `json:"url"`
	CreatedAt time.Time `json:"created_at"`
}

// openTicket opens one ITSM ticket per incident; asking again returns the existing one.
func (s *Store) openTicket(ctx context.Context, _ string, inc Incident, p map[string]string, now time.Time) (map[string]any, error) {
	if s.ITSM == nil {
		return nil, fmt.Errorf("%w: no ITSM configured", ErrInvalid)
	}
	var t TicketRef
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		// The incident row lock keeps a second request from opening a twin ticket while the first is in flight.
		// ponytail: held across the ITSM call (≤ 30 s client timeout), so events joining this incident wait that
		// long; an outbox with a ticket worker if ITSM latency ever shows in consumer lag.
		if _, err := tx.Exec(ctx, "SELECT 1 FROM incident.incidents WHERE id = $1 FOR UPDATE", inc.ID); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, "SELECT system, ref, url, created_at FROM incident.tickets WHERE incident_id = $1", inc.ID).Scan(&t.System, &t.Ref, &t.URL, &t.CreatedAt)
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		desc := fmt.Sprintf("AI security incident %s\nSeverity: %s (max risk %d)\nState: %s\nEvents: %d, %s to %s\n",
			inc.ID, inc.Severity, inc.MaxRisk, inc.State, inc.EventCount, inc.FirstEventAt.Format(time.RFC3339), inc.LastEventAt.Format(time.RFC3339))
		if inc.Breach != nil {
			desc += fmt.Sprintf("UU PDP breach timer: notify by %s\n", inc.Breach.Deadline.Format(time.RFC3339))
		}
		if n := strings.TrimSpace(p["note"]); n != "" {
			desc += "\n" + n + "\n"
		}
		ref, url, err := s.ITSM.Open(ctx, Ticket{IncidentID: inc.ID, Title: "[WANTIMPRES-26] " + inc.Title, Severity: inc.Severity, Description: desc})
		if err != nil {
			return err
		}
		t = TicketRef{System: s.ITSM.Name(), Ref: ref, URL: url, CreatedAt: now}
		_, err = tx.Exec(ctx, "INSERT INTO incident.tickets (incident_id, system, ref, url, created_at) VALUES ($1, $2, $3, $4, $5)", inc.ID, t.System, ref, url, now)
		return err
	})
	return map[string]any{"system": t.System, "ref": t.Ref, "url": t.URL}, err
}

// TicketOf is the incident's ITSM ticket, if any.
func (s *Store) TicketOf(ctx context.Context, id string) (*TicketRef, error) {
	var t TicketRef
	err := s.db.QueryRow(ctx, "SELECT system, ref, url, created_at FROM incident.tickets WHERE incident_id = $1", id).Scan(&t.System, &t.Ref, &t.URL, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &t, err
}

// ServiceNow opens an incident through the Table API (POST /api/now/table/incident).
type ServiceNow struct {
	URL    string // instance, e.g. https://bank.service-now.com
	Auth   string // Authorization header value (Basic or Bearer)
	Client *http.Client
}

func (sn *ServiceNow) Name() string { return "servicenow" }

func (sn *ServiceNow) Open(ctx context.Context, t Ticket) (string, string, error) {
	// ServiceNow urgency/impact: 1 high, 2 medium, 3 low.
	level := map[string]string{"critical": "1", "high": "1", "medium": "2", "low": "3"}[t.Severity]
	var out struct {
		Result struct {
			SysID  string `json:"sys_id"`
			Number string `json:"number"`
		} `json:"result"`
	}
	err := postJSON(ctx, sn.Client, strings.TrimRight(sn.URL, "/")+"/api/now/table/incident?sysparm_fields=sys_id,number", sn.Auth, map[string]any{
		"short_description": t.Title, "description": t.Description, "urgency": level, "impact": level,
		"correlation_id": t.IncidentID, "correlation_display": "wantimpres26",
	}, &out)
	if err == nil && out.Result.Number == "" {
		err = errors.New("servicenow: no incident number in the response")
	}
	return out.Result.Number, strings.TrimRight(sn.URL, "/") + "/nav_to.do?uri=incident.do?sys_id=" + out.Result.SysID, err
}

// JiraSM opens a customer request in Jira Service Management (POST /rest/servicedeskapi/request).
type JiraSM struct {
	URL                          string // e.g. https://jira.bank.co.id
	Auth                         string
	ServiceDeskID, RequestTypeID string
	Client                       *http.Client
}

func (j *JiraSM) Name() string { return "jira-sm" }

func (j *JiraSM) Open(ctx context.Context, t Ticket) (string, string, error) {
	var out struct {
		IssueKey string `json:"issueKey"`
		Links    struct {
			Web string `json:"web"`
		} `json:"_links"`
	}
	err := postJSON(ctx, j.Client, strings.TrimRight(j.URL, "/")+"/rest/servicedeskapi/request", j.Auth, map[string]any{
		"serviceDeskId": j.ServiceDeskID, "requestTypeId": j.RequestTypeID,
		"requestFieldValues": map[string]any{"summary": t.Title, "description": t.Description},
	}, &out)
	if err == nil && out.IssueKey == "" {
		err = errors.New("jira-sm: no issue key in the response")
	}
	return out.IssueKey, out.Links.Web, err
}

func postJSON(ctx context.Context, c *http.Client, url, auth string, body, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", auth)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: HTTP %d: %s", url, resp.StatusCode, msg)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}
