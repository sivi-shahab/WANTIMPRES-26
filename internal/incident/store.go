package incident

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/authz"
	"wantimpres26/internal/events"
	"wantimpres26/internal/tenantdb"
)

//go:embed schema.sql
var schemaSQL string

var (
	ErrNotFound  = errors.New("not found")
	ErrForbidden = errors.New("forbidden")
)

// Store is the Postgres-backed incident module (schema incident). Every analyst action is written to the audit
// log (same database) in the transaction that makes it.
type Store struct {
	db    *pgxpool.Pool
	audit *audit.Store
	kek   []byte // wraps per-incident DEKs. ponytail: file key; a KMS/HSM unwrap call when spec §10.1's KMS lands

	// Release cuts a policy release inside tx (lifecycle.CutRelease), so containment blocks reach every PDP with the
	// next bundle. nil: blocks are refused.
	Release func(ctx context.Context, tx pgx.Tx, actor, reason string) (int64, error)
	ITSM    Ticketer          // nil: no ITSM configured, open_ticket is refused
	Actions map[string]Action // FR-INC-5 containment actions by name; Open adds block_access and open_ticket
}

func Open(ctx context.Context, db *pgxpool.Pool, auditLog *audit.Store, kek []byte) (*Store, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("incident KEK must be 32 bytes, got %d", len(kek))
	}
	if _, err := db.Exec(ctx, schemaSQL); err != nil {
		return nil, fmt.Errorf("apply incident schema: %w", err)
	}
	// Row level security (ticket 42): incidents and blocks by tenant_id, the rest through their incident.
	if err := tenantdb.Isolate(ctx, db, "incident.incidents", "incident.blocks"); err != nil {
		return nil, err
	}
	for _, t := range []string{"incident.incident_events", "incident.evidence", "incident.transitions", "incident.actions", "incident.tickets", "incident.unmask_requests"} {
		if err := tenantdb.IsolateChild(ctx, db, t, "incident_id", "incident.incidents"); err != nil {
			return nil, err
		}
	}
	s := &Store{db: db, audit: auditLog, kek: kek}
	s.Actions = map[string]Action{
		"block_access": {Run: s.blockAccess},
		"open_ticket":  {Run: s.openTicket},
	}
	return s, nil
}

// Ingest folds one decision event into incidents: below MinRisk it is ignored; otherwise it joins the open incident
// with its DedupKey whose events are within DedupWindow, or opens a new one. Redelivered events are no-ops.
func (s *Store) Ingest(ctx context.Context, e events.Event, raw []byte, now time.Time) (id string, created bool, err error) {
	if e.RiskScore < MinRisk {
		return "", false, nil
	}
	ts, err := time.Parse(time.RFC3339Nano, e.TS)
	if err != nil {
		return "", false, err
	}
	key, sev, trace := DedupKey(e), SeverityFor(e.RiskScore), chainTrace(e)
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		// Serialize per trace, then per key (always in that order), so two consumers cannot open twin incidents.
		for _, k := range []string{"trace|" + trace, key} {
			if k == "trace|" {
				continue
			}
			if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1 || '|' || $2, 0))", e.TenantID, k); err != nil {
				return err
			}
		}
		if err := tx.QueryRow(ctx, "SELECT incident_id FROM incident.incident_events WHERE event_id = $1", e.EventID).Scan(&id); err == nil {
			return nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		// FR-INC-1 chain: an event whose trace (an agent session at the MCP gateway) already has an open incident
		// joins it, whatever its key: prompt -> tool call -> result is one story. Otherwise the dedup key decides.
		err := pgx.ErrNoRows
		if trace != "" {
			err = tx.QueryRow(ctx, `SELECT ie.incident_id FROM incident.incident_events ie JOIN incident.incidents i ON i.id = ie.incident_id
				WHERE ie.trace_id = $1 AND i.tenant_id = $2 AND i.state = ANY($3) AND ie.ts BETWEEN $4::timestamptz - $5::interval AND $4::timestamptz + $5::interval
				ORDER BY ie.ts DESC LIMIT 1`, trace, e.TenantID, OpenStates, ts, DedupWindow.String()).Scan(&id)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			err = tx.QueryRow(ctx, `SELECT id FROM incident.incidents
				WHERE tenant_id = $1 AND dedup_key = $2 AND state = ANY($3)
				  AND $4 BETWEEN first_event_at - $5::interval AND last_event_at + $5::interval
				ORDER BY last_event_at DESC LIMIT 1`, e.TenantID, key, OpenStates, ts, DedupWindow.String()).Scan(&id)
		}
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			created = true
			dek := make([]byte, 32)
			if _, err := rand.Read(dek); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, "SELECT gen_random_uuid()").Scan(&id); err != nil {
				return err
			}
			wrapped, err := seal(s.kek, dek, []byte("dek:"+id))
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `INSERT INTO incident.incidents
				(id, tenant_id, dedup_key, title, state, severity, max_risk, event_count, first_event_at, last_event_at, opened_at, ack_deadline, dek_wrapped)
				VALUES ($1, $2, $3, $4, 'New', $5, $6, 0, $7, $7, $8, $9, $10)`,
				id, e.TenantID, key, title(e), sev, e.RiskScore, ts, now, ackDeadline(sev, now), wrapped)
			if err != nil {
				return err
			}
			// Audited so it reaches the SIEM (ticket 19) with the other security telemetry.
			if _, err := audit.AppendTx(ctx, tx, e.TenantID, "system", "incident.open", map[string]any{"incident": id, "severity": sev,
				"title": title(e), "risk": e.RiskScore, "event": e.EventID, "trace_id": e.TraceID}); err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			if err := s.escalate(ctx, tx, id, sev, now, "system", fmt.Sprintf("event %s risk %d", e.EventID, e.RiskScore)); err != nil {
				return err
			}
		}
		// ABAC attributes: the first unit/region seen sticks; sensitivity is the highest seen.
		_, err = tx.Exec(ctx, `UPDATE incident.incidents SET event_count = event_count + 1, max_risk = greatest(max_risk, $2),
			first_event_at = least(first_event_at, $3), last_event_at = greatest(last_event_at, $3),
			business_unit = CASE WHEN business_unit = '' THEN $4 ELSE business_unit END,
			region = CASE WHEN region = '' THEN $5 ELSE region END,
			sensitivity = CASE WHEN coalesce(array_position($7::text[], $6::text), 0) > coalesce(array_position($7::text[], sensitivity), 0)
			  THEN $6 ELSE sensitivity END
			WHERE id = $1`, id, e.RiskScore, ts, groupAttr(e, "bu:"), groupAttr(e, "region:"), e.Sensitivity, authz.Sensitivities)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "INSERT INTO incident.incident_events (incident_id, event_id, ts, risk_score, event, trace_id) VALUES ($1, $2, $3, $4, $5, nullif($6, ''))",
			id, e.EventID, ts, e.RiskScore, json.RawMessage(raw), trace)
		if err != nil || !Exposed(e) {
			return err
		}
		return s.startBreach(ctx, tx, id, "auto", "system", fmt.Sprintf("event %s: personal data allowed to %s", e.EventID, e.AppID), now)
	})
	return id, created, err
}

// groupAttr is an ABAC attribute the event's principal carries as an IdP group "<prefix><value>" (bu:retail,
// region:jakarta); "" when it has none, which leaves the incident unrestricted on that attribute.
func groupAttr(e events.Event, prefix string) string {
	for _, g := range e.PrincipalGroups {
		if v, ok := strings.CutPrefix(g, prefix); ok && v != "" {
			return v
		}
	}
	return ""
}

// chainTrace is the trace an event chains on; "" for a missing or all-zero trace id, which correlates nothing.
func chainTrace(e events.Event) string {
	if strings.Trim(e.TraceID, "0") == "" {
		return ""
	}
	return e.TraceID
}

func title(e events.Event) string {
	classes := make([]string, 0, len(e.Classes))
	for _, c := range e.Classes {
		classes = append(classes, c.Type)
	}
	what := strings.Join(classes, ", ")
	if what == "" {
		what = strings.Join(e.ReasonCodes, ", ")
	}
	return fmt.Sprintf("%s %s to %s via %s", e.Action, what, e.AppID, e.Channel)
}

func ackDeadline(sev string, from time.Time) *time.Time {
	sla, ok := AckSLA[sev]
	if !ok {
		return nil
	}
	t := from.Add(sla)
	return &t
}

// escalate raises severity to at least sev (never lowers it). While unacknowledged, a tighter SLA starts now.
func (s *Store) escalate(ctx context.Context, tx pgx.Tx, id, sev string, now time.Time, actor, note string) error {
	var cur string
	var state State
	if err := tx.QueryRow(ctx, "SELECT severity, state FROM incident.incidents WHERE id = $1 FOR UPDATE", id).Scan(&cur, &state); err != nil {
		return err
	}
	if SeverityRank(sev) <= SeverityRank(cur) {
		return nil
	}
	var tenant string
	err := tx.QueryRow(ctx, `UPDATE incident.incidents SET severity = $2,
		ack_deadline = CASE WHEN state = 'New' THEN least(coalesce(ack_deadline, $3), $3) ELSE ack_deadline END
		WHERE id = $1 RETURNING tenant_id::text`, id, sev, ackDeadline(sev, now)).Scan(&tenant)
	if err != nil {
		return err
	}
	_, err = audit.AppendTx(ctx, tx, tenant, actor, "incident.escalate", map[string]any{"incident": id, "from": cur, "to": sev, "note": note})
	return err
}

// Incident is the API view.
type Incident struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	Title          string     `json:"title"`
	State          State      `json:"state"`
	Severity       string     `json:"severity"`
	MaxRisk        int        `json:"max_risk"`
	EventCount     int        `json:"event_count"`
	FirstEventAt   time.Time  `json:"first_event_at"`
	LastEventAt    time.Time  `json:"last_event_at"`
	OpenedAt       time.Time  `json:"opened_at"`
	AckDeadline    *time.Time `json:"ack_deadline,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	ClosedAt       *time.Time `json:"closed_at,omitempty"`
	Breach         *Breach    `json:"breach,omitempty"`
	BusinessUnit   string     `json:"business_unit,omitempty"`
	Region         string     `json:"region,omitempty"`
	Sensitivity    string     `json:"sensitivity,omitempty"` // the most sensitive content among its events
}

// Breach is the FR-INC-6 timer of an incident (UU PDP Pasal 46: notify within 3×24 hours).
type Breach struct {
	StartedAt   time.Time  `json:"started_at"`
	Deadline    time.Time  `json:"deadline"`
	Basis       string     `json:"basis"` // auto | declared
	EscalatedAt *time.Time `json:"escalated_at,omitempty"`
	DraftedAt   *time.Time `json:"drafted_at,omitempty"`
	ClosedAt    *time.Time `json:"closed_at,omitempty"`
	Outcome     string     `json:"outcome,omitempty"` // notified | dismissed
}

const incidentCols = `id, tenant_id::text, title, state, severity, max_risk, event_count, first_event_at, last_event_at, opened_at,
	ack_deadline, acknowledged_at, resolved_at, closed_at,
	breach_started_at, breach_deadline, coalesce(breach_basis, ''), breach_escalated_at, breach_drafted_at, breach_closed_at, coalesce(breach_outcome, ''),
	business_unit, region, sensitivity`

func scanIncident(row pgx.Row) (Incident, error) {
	var i Incident
	var b Breach
	var started, deadline *time.Time
	err := row.Scan(&i.ID, &i.TenantID, &i.Title, &i.State, &i.Severity, &i.MaxRisk, &i.EventCount, &i.FirstEventAt, &i.LastEventAt,
		&i.OpenedAt, &i.AckDeadline, &i.AcknowledgedAt, &i.ResolvedAt, &i.ClosedAt,
		&started, &deadline, &b.Basis, &b.EscalatedAt, &b.DraftedAt, &b.ClosedAt, &b.Outcome,
		&i.BusinessUnit, &i.Region, &i.Sensitivity)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	if started != nil && deadline != nil {
		b.StartedAt, b.Deadline = *started, *deadline
		i.Breach = &b
	}
	return i, err
}

// List filters by severity and/or state (empty = any), most severe and oldest first.
func (s *Store) List(ctx context.Context, severity, state string, limit int) ([]Incident, error) {
	rows, err := s.db.Query(ctx, `SELECT `+incidentCols+` FROM incident.incidents
		WHERE ($1 = '' OR severity = $1) AND ($2 = '' OR state = $2)
		ORDER BY array_position(ARRAY['critical','high','medium','low'], severity), opened_at LIMIT $3`, severity, state, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Incident, error) { return scanIncident(r) })
}

func (s *Store) Get(ctx context.Context, id string) (Incident, error) {
	return scanIncident(s.db.QueryRow(ctx, "SELECT "+incidentCols+" FROM incident.incidents WHERE id = $1", id))
}

// Overdue counts unacknowledged incidents past their SLA (FR-INC-7 alerting).
func (s *Store) Overdue(ctx context.Context, now time.Time) (n int, err error) {
	err = s.db.QueryRow(ctx, "SELECT count(*) FROM incident.incidents WHERE state = 'New' AND ack_deadline < $1", now).Scan(&n)
	return n, err
}

// Transition moves an incident along FR-INC-3. Leaving New acknowledges it (stops the SLA timer).
func (s *Store) Transition(ctx context.Context, id string, to State, note, actor string, now time.Time) (Incident, error) {
	var tenant string
	var from State
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, "SELECT tenant_id::text, state FROM incident.incidents WHERE id = $1 FOR UPDATE", id).Scan(&tenant, &from)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if err := CheckTransition(from, to, note); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE incident.incidents SET state = $2,
			acknowledged_at = CASE WHEN acknowledged_at IS NULL AND $3 = 'New' THEN $4 ELSE acknowledged_at END,
			resolved_at = CASE WHEN $2 = 'Resolved' THEN $4 WHEN $2 = 'Investigating' THEN NULL ELSE resolved_at END,
			closed_at = CASE WHEN $2 = 'Closed' THEN $4 ELSE closed_at END
			WHERE id = $1`, id, to, from, now)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "INSERT INTO incident.transitions (incident_id, at, actor, from_state, to_state, note) VALUES ($1, $2, $3, $4, $5, $6)",
			id, now, actor, from, to, note)
		if err != nil {
			return err
		}
		_, err = audit.AppendTx(ctx, tx, tenant, actor, "incident.transition", map[string]any{"incident": id, "from": from, "to": to})
		return err
	})
	if err != nil {
		return Incident{}, err
	}
	return s.Get(ctx, id)
}

// RaiseSeverity is FR-INC-2's manual raise; lowering is refused.
func (s *Store) RaiseSeverity(ctx context.Context, id, sev, note, actor string, now time.Time) (Incident, error) {
	if SeverityRank(sev) < 0 {
		return Incident{}, fmt.Errorf("%w: unknown severity %q", ErrInvalidTransition, sev)
	}
	cur, err := s.Get(ctx, id)
	if err != nil {
		return Incident{}, err
	}
	if SeverityRank(sev) <= SeverityRank(cur.Severity) {
		return Incident{}, fmt.Errorf("%w: severity can only be raised (%s -> %s)", ErrInvalidTransition, cur.Severity, sev)
	}
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		return s.escalate(ctx, tx, id, sev, now, actor, note)
	})
	if err != nil {
		return Incident{}, err
	}
	return s.Get(ctx, id)
}

// EvidenceMeta describes evidence without revealing it.
type EvidenceMeta struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Events returns the redacted evidence: the decision events as they arrived.
func (s *Store) Events(ctx context.Context, id string) ([]json.RawMessage, error) {
	rows, err := s.db.Query(ctx, "SELECT event FROM incident.incident_events WHERE incident_id = $1 ORDER BY ts", id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[json.RawMessage])
}

func (s *Store) Evidence(ctx context.Context, id string) ([]EvidenceMeta, error) {
	rows, err := s.db.Query(ctx, "SELECT id, kind, sha256, created_at, expires_at FROM incident.evidence WHERE incident_id = $1 ORDER BY created_at", id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[EvidenceMeta])
}

// RawTTL is the forensic-capture default (spec §10.2).
const RawTTL = 30 * 24 * time.Hour

func (s *Store) dek(ctx context.Context, id string) ([]byte, error) {
	var wrapped []byte
	err := s.db.QueryRow(ctx, "SELECT dek_wrapped FROM incident.incidents WHERE id = $1", id).Scan(&wrapped)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	return open(s.kek, wrapped, []byte("dek:"+id))
}

// AddRawEvidence stores forensic-capture content encrypted with the incident's DEK. Only call it when the matched
// policy has forensic_capture on (FR-INC-4).
func (s *Store) AddRawEvidence(ctx context.Context, id, kind string, raw []byte, now time.Time) (string, error) {
	dek, err := s.dek(ctx, id)
	if err != nil {
		return "", err
	}
	var eid string
	if err := s.db.QueryRow(ctx, "SELECT gen_random_uuid()").Scan(&eid); err != nil {
		return "", err
	}
	ct, err := seal(dek, raw, []byte("evidence:"+id+":"+eid))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	_, err = s.db.Exec(ctx, "INSERT INTO incident.evidence (id, incident_id, kind, ciphertext, sha256, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		eid, id, kind, ct, hex.EncodeToString(sum[:]), now, now.Add(RawTTL))
	return eid, err
}

// PurgeExpired deletes raw evidence past its TTL.
func (s *Store) PurgeExpired(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.db.Exec(ctx, "DELETE FROM incident.evidence WHERE expires_at < $1", now)
	return tag.RowsAffected(), err
}

// Summary is the posture view of incidents (ticket 20).
type Summary struct {
	Open            int            `json:"open"` // not Resolved/Closed
	BySeverity      map[string]int `json:"open_by_severity"`
	AckSLA          int            `json:"with_ack_sla"` // New with a deadline
	AckOverdue      int            `json:"ack_overdue"`
	CriticalOpened  int            `json:"critical_opened"`                 // in the window
	MTTDCriticalSec *float64       `json:"mttd_critical_seconds,omitempty"` // mean of opened_at - first_event_at
	Top             []Incident     `json:"top"`                             // open, most severe and riskiest first
}

// Summarize reports open incidents now and critical detection time over incidents opened since `since`.
func (s *Store) Summarize(ctx context.Context, since, now time.Time) (Summary, error) {
	sum := Summary{BySeverity: map[string]int{}}
	rows, err := s.db.Query(ctx, "SELECT severity, count(*) FROM incident.incidents WHERE state = ANY($1) GROUP BY severity", OpenStates)
	if err != nil {
		return sum, err
	}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return sum, err
		}
		sum.BySeverity[sev], sum.Open = n, sum.Open+n
	}
	if err := rows.Err(); err != nil {
		return sum, err
	}
	err = s.db.QueryRow(ctx, `SELECT count(*) FILTER (WHERE ack_deadline IS NOT NULL), count(*) FILTER (WHERE ack_deadline < $1)
		FROM incident.incidents WHERE state = 'New'`, now).Scan(&sum.AckSLA, &sum.AckOverdue)
	if err != nil {
		return sum, err
	}
	err = s.db.QueryRow(ctx, `SELECT count(*), avg(extract(epoch FROM opened_at - first_event_at))::float8
		FROM incident.incidents WHERE severity = 'critical' AND opened_at >= $1`, since).Scan(&sum.CriticalOpened, &sum.MTTDCriticalSec)
	if err != nil {
		return sum, err
	}
	rows, err = s.db.Query(ctx, "SELECT "+incidentCols+` FROM incident.incidents WHERE state = ANY($1)
		ORDER BY array_position(ARRAY['critical','high','medium','low'], severity), max_risk DESC, opened_at LIMIT 10`, OpenStates)
	if err != nil {
		return sum, err
	}
	sum.Top, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Incident, error) { return scanIncident(r) })
	return sum, err
}

// Handle is the events.Handler that folds decision events into incidents.
func (s *Store) Handle(ctx context.Context, e events.Event, payload []byte) error {
	_, _, err := s.Ingest(ctx, e, payload, time.Now())
	return err
}
