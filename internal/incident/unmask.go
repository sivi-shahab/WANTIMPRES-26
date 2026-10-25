package incident

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/authz"
)

// Unmask abuse controls (ticket 45, threat model G6): ABAC on the incident's business unit, region and content
// sensitivity; four-eyes for restricted evidence; per-analyst volume metrics for alerting.

// UnmaskApprovalTTL: an approved request must be used within this.
const UnmaskApprovalTTL = time.Hour

// resource is the incident as ABAC sees it.
func (inc Incident) resource() authz.Resource {
	return authz.Resource{BusinessUnit: inc.BusinessUnit, Region: inc.Region, Sensitivity: inc.Sensitivity}
}

// mayUnmask is the check shared by unmask, request and approval: "" or the reason for refusing.
func mayUnmask(c authz.Caller, inc Incident, justification string, now time.Time) string {
	switch {
	case !c.Can(authz.EvidenceUnmask, authz.Resource{}, now):
		return "missing permission " + authz.EvidenceUnmask
	case !c.Can(authz.EvidenceUnmask, inc.resource(), now):
		return fmt.Sprintf("incident outside the caller's scope (business unit %q, region %q, sensitivity %q)", inc.BusinessUnit, inc.Region, inc.Sensitivity)
	case len(strings.TrimSpace(justification)) < authz.MinJustification:
		return fmt.Sprintf("justification shorter than %d characters", authz.MinJustification)
	}
	return ""
}

// deny audits a refusal and returns ErrForbidden.
func (s *Store) deny(ctx context.Context, tenant, actor, action, reason string, target map[string]any) error {
	target["denied"] = reason
	if _, err := s.audit.Append(ctx, tenant, actor, action, target); err != nil {
		return err
	}
	return fmt.Errorf("%w: %s", ErrForbidden, reason)
}

// Unmask decrypts raw evidence (FR-INC-4). The router already demanded evidence.unmask, a fresh login and a
// justification, and audited the access; this checks again with the incident's ABAC attributes and, for restricted
// evidence, consumes a second analyst's approval. It writes the domain record naming the evidence, denied or
// granted, before any plaintext exists.
func (s *Store) Unmask(ctx context.Context, c authz.Caller, id, eid, justification string, now time.Time) ([]byte, error) {
	inc, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	target := map[string]any{"incident": id, "evidence": eid, "justification": justification}
	if reason := mayUnmask(c, inc, justification, now); reason != "" {
		return nil, s.deny(ctx, inc.TenantID, c.Username, "evidence.unmask.denied", reason, target)
	}
	var ct []byte
	err = s.db.QueryRow(ctx, "SELECT ciphertext FROM incident.evidence WHERE id = $1 AND incident_id = $2", eid, id).Scan(&ct)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if inc.Sensitivity == "restricted" {
			var rid, approver string
			err := tx.QueryRow(ctx, `UPDATE incident.unmask_requests SET used_at = $4
				WHERE id = (SELECT id FROM incident.unmask_requests WHERE incident_id = $1 AND evidence_id = $2 AND requester = $3
				  AND approved_at > $4::timestamptz - $5::interval AND used_at IS NULL ORDER BY approved_at LIMIT 1 FOR UPDATE)
				RETURNING id::text, approver`, id, eid, c.Username, now, UnmaskApprovalTTL.String()).Scan(&rid, &approver)
			if errors.Is(err, pgx.ErrNoRows) {
				return errNoApproval
			} else if err != nil {
				return err
			}
			target["request"], target["approver"] = rid, approver
		}
		_, err := audit.AppendTx(ctx, tx, inc.TenantID, c.Username, "evidence.unmask", target)
		return err // no audit record, no plaintext
	})
	if errors.Is(err, errNoApproval) {
		return nil, s.deny(ctx, inc.TenantID, c.Username, "evidence.unmask.denied", "restricted evidence needs an approved request from a second analyst", target)
	} else if err != nil {
		return nil, err
	}
	dek, err := s.dek(ctx, id)
	if err != nil {
		return nil, err
	}
	return open(dek, ct, []byte("evidence:"+id+":"+eid))
}

var errNoApproval = errors.New("no approved unmask request")

// UnmaskRequest is a four-eyes request to unmask one piece of restricted evidence.
type UnmaskRequest struct {
	ID            string     `json:"id"`
	EvidenceID    string     `json:"evidence_id"`
	Requester     string     `json:"requester"`
	Justification string     `json:"justification"`
	CreatedAt     time.Time  `json:"created_at"`
	Approver      *string    `json:"approver,omitempty"`
	ApprovedAt    *time.Time `json:"approved_at,omitempty"`
	UsedAt        *time.Time `json:"used_at,omitempty"`
}

const unmaskCols = "id::text, evidence_id::text, requester, justification, created_at, approver, approved_at, used_at"

// RequestUnmask asks a second analyst to approve unmasking eid. The requester must be allowed to unmask the incident.
func (s *Store) RequestUnmask(ctx context.Context, c authz.Caller, id, eid, justification string, now time.Time) (UnmaskRequest, error) {
	inc, err := s.Get(ctx, id)
	if err != nil {
		return UnmaskRequest{}, err
	}
	target := map[string]any{"incident": id, "evidence": eid, "justification": justification}
	if reason := mayUnmask(c, inc, justification, now); reason != "" {
		return UnmaskRequest{}, s.deny(ctx, inc.TenantID, c.Username, "evidence.unmask.request.denied", reason, target)
	}
	var r UnmaskRequest
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `INSERT INTO incident.unmask_requests (incident_id, evidence_id, requester, justification, created_at)
			SELECT incident_id, id, $3, $4, $5 FROM incident.evidence WHERE id = $2 AND incident_id = $1 RETURNING `+unmaskCols,
			id, eid, c.Username, justification, now).Scan(&r.ID, &r.EvidenceID, &r.Requester, &r.Justification, &r.CreatedAt, &r.Approver, &r.ApprovedAt, &r.UsedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		target["request"] = r.ID
		_, err = audit.AppendTx(ctx, tx, inc.TenantID, c.Username, "evidence.unmask.request", target)
		return err
	})
	return r, err
}

// ApproveUnmask is the second pair of eyes: someone else, also allowed to unmask this incident, approves one use.
func (s *Store) ApproveUnmask(ctx context.Context, c authz.Caller, id, rid, justification string, now time.Time) (UnmaskRequest, error) {
	inc, err := s.Get(ctx, id)
	if err != nil {
		return UnmaskRequest{}, err
	}
	var r UnmaskRequest
	err = s.db.QueryRow(ctx, "SELECT "+unmaskCols+" FROM incident.unmask_requests WHERE id::text = $1 AND incident_id = $2", rid, id).
		Scan(&r.ID, &r.EvidenceID, &r.Requester, &r.Justification, &r.CreatedAt, &r.Approver, &r.ApprovedAt, &r.UsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return UnmaskRequest{}, ErrNotFound
	} else if err != nil {
		return UnmaskRequest{}, err
	}
	target := map[string]any{"incident": id, "request": rid, "requester": r.Requester, "justification": justification}
	reason := mayUnmask(c, inc, justification, now)
	switch {
	case reason != "":
	case strings.EqualFold(c.Username, r.Requester):
		reason = "the requester cannot approve their own unmask"
	case r.ApprovedAt != nil:
		return UnmaskRequest{}, fmt.Errorf("%w: request already approved", ErrInvalidTransition)
	}
	if reason != "" {
		return UnmaskRequest{}, s.deny(ctx, inc.TenantID, c.Username, "evidence.unmask.approve.denied", reason, target)
	}
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE incident.unmask_requests SET approver = $2, approved_at = $3 WHERE id::text = $1 AND approved_at IS NULL", rid, c.Username, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: request already approved", ErrInvalidTransition)
		}
		_, err = audit.AppendTx(ctx, tx, inc.TenantID, c.Username, "evidence.unmask.approve", target)
		return err
	})
	r.Approver, r.ApprovedAt = &c.Username, &now
	return r, err
}

// UnmaskRequests lists an incident's four-eyes requests.
func (s *Store) UnmaskRequests(ctx context.Context, id string) ([]UnmaskRequest, error) {
	rows, err := s.db.Query(ctx, "SELECT "+unmaskCols+" FROM incident.unmask_requests WHERE incident_id = $1 ORDER BY created_at", id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[UnmaskRequest])
}

// UnmaskVolume is the abuse metric: per analyst, unmasks granted since `since`, and the most unmasks of incidents
// involving one principal (the same person looked up again and again).
type UnmaskVolume struct {
	Analyst       string
	Unmasks       int
	SamePrincipal int
}

// WriteUnmaskMetrics writes the volumes as the gauges the UnmaskVolumeHigh / UnmaskSamePrincipalRepeated alerts
// read (deploy/cluster/alerts.yaml); thresholds live in the alerts.
func WriteUnmaskMetrics(w io.Writer, vols []UnmaskVolume) {
	_, _ = io.WriteString(w, "# TYPE evidence_unmasks_24h gauge\n# TYPE evidence_unmask_same_principal_24h gauge\n")
	for _, v := range vols {
		l := strconv.Quote(v.Analyst) // Prometheus label escaping matches Go's for \, " and newline
		_, _ = fmt.Fprintf(w, "evidence_unmasks_24h{analyst=%s} %d\nevidence_unmask_same_principal_24h{analyst=%s} %d\n", l, v.Unmasks, l, v.SamePrincipal)
	}
}

func (s *Store) UnmaskVolumes(ctx context.Context, since time.Time) ([]UnmaskVolume, error) {
	rows, err := s.db.Query(ctx, `
		WITH u AS (SELECT seq, actor, target->>'incident' AS incident FROM audit.audit_log WHERE action = 'evidence.unmask' AND ts >= $1),
		per_principal AS (
		  SELECT u.actor, count(DISTINCT u.seq) AS n FROM u
		  JOIN incident.incident_events ie ON ie.incident_id::text = u.incident
		  GROUP BY u.actor, ie.event->>'principal_id')
		SELECT u.actor, count(*)::int, coalesce((SELECT max(n) FROM per_principal p WHERE p.actor = u.actor), 0)::int
		FROM u GROUP BY u.actor ORDER BY u.actor`, since)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[UnmaskVolume])
}
