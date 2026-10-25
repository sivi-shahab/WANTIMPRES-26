package compliance

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/agents"
	"wantimpres26/internal/audit"
	"wantimpres26/internal/incident"
	"wantimpres26/internal/posture"
)

// Control is a platform control (control_id) that frameworks' requirements map to.
type Control struct {
	ID   string `json:"control_id"`
	Name string `json:"name"`
	// Proposed: not in spec §14's initial mapping; the compliance team decides whether it is evidence.
	Proposed bool `json:"proposed,omitempty"`
}

// Controls are spec §14's rows, plus data-at-rest (tickets 31-33).
var Controls = []Control{
	{ID: "CTL-INVENTORY", Name: "AI app inventory & shadow AI"},
	{ID: "CTL-DLP", Name: "Classification & DLP on prompts and responses"},
	{ID: "CTL-INJECTION", Name: "Prompt-injection detection"},
	{ID: "CTL-AGENT", Name: "Agent registry, least privilege, HITL, kill switch"},
	{ID: "CTL-MCP", Name: "MCP gateway and tool definition scanning"},
	{ID: "CTL-RATE", Name: "Rate limits and quotas"},
	{ID: "CTL-RESIDENCY", Name: "Data residency and transfer control per app"},
	{ID: "CTL-INCIDENT", Name: "Incident management and breach timer"},
	{ID: "CTL-AUDIT", Name: "Audit log hash chain and evidence"},
	{ID: "CTL-POSTURE", Name: "Posture report and control history"},
	{ID: "CTL-DATA", Name: "Data-at-rest discovery, oversharing analysis and remediation", Proposed: true},
}

var controlByID = func() map[string]Control {
	m := map[string]Control{}
	for _, c := range Controls {
		m[c.ID] = c
	}
	return m
}()

// Sources are where evidence comes from. Each is a func so tests can stand in for any of them.
type Sources struct {
	DB *pgxpool.Pool // data.*, agents.* tables
	// Rules: the policy release every PDP runs now (data.wantimpres26.rules).
	Rules      func(ctx context.Context) (release string, items []map[string]any, err error)
	Posture    func(ctx context.Context, now time.Time) (posture.Report, error)
	Agents     func(ctx context.Context) (agents.Summary, error)
	Incidents  func(ctx context.Context, since, now time.Time) (incident.Summary, error)
	AuditChain func(ctx context.Context, from, to time.Time) (entries int, err error) // verifies the hash chain
}

// Finding is one control's evaluation.
type Finding struct {
	Status  string         `json:"status"` // pass | partial | fail | unknown
	Reasons []string       `json:"reasons"`
	Facts   map[string]any `json:"facts"`
}

type check func(ctx context.Context, src Sources, now time.Time) (Finding, error)

// enforced reports which of ids are enforcing rules (mode enforce or unset) in the release.
func enforced(items []map[string]any, ids ...string) (have, missing []string) {
	on := map[string]bool{}
	for _, r := range items {
		id, _ := r["id"].(string)
		mode, _ := r["mode"].(string)
		on[id] = mode == "" || mode == "enforce"
	}
	for _, id := range ids {
		if on[id] {
			have = append(have, id)
		} else {
			missing = append(missing, id)
		}
	}
	return have, missing
}

// rulesCheck: the control is the listed policy rules being enforced, plus whatever more checks.
func rulesCheck(ids []string, more check) check {
	return func(ctx context.Context, src Sources, now time.Time) (Finding, error) {
		release, items, err := src.Rules(ctx)
		if err != nil {
			return Finding{}, fmt.Errorf("policy release: %w", err)
		}
		have, missing := enforced(items, ids...)
		f := Finding{Status: "pass", Facts: map[string]any{"release": release, "rules_enforced": have, "rules_missing": missing}}
		switch {
		case len(have) == 0:
			f.Status = "fail"
			f.Reasons = append(f.Reasons, "none of the control's rules are enforced")
		case len(missing) > 0:
			f.Status = "partial"
			f.Reasons = append(f.Reasons, fmt.Sprintf("rules not enforced: %v", missing))
		}
		if more != nil {
			m, err := more(ctx, src, now)
			if err != nil {
				return Finding{}, err
			}
			f = merge(f, m)
		}
		return f, nil
	}
}

var rank = map[string]int{"pass": 0, "partial": 1, "unknown": 2, "fail": 3}

// merge keeps the worse status and every reason and fact.
func merge(a, b Finding) Finding {
	if rank[b.Status] > rank[a.Status] {
		a.Status = b.Status
	}
	a.Reasons = append(a.Reasons, b.Reasons...)
	for k, v := range b.Facts {
		a.Facts[k] = v
	}
	return a
}

func count(ctx context.Context, db *pgxpool.Pool, sql string, args ...any) (int64, error) {
	var n int64
	err := db.QueryRow(ctx, sql, args...).Scan(&n)
	return n, err
}

// Checks evaluate each control from the running platform (FR-COMP-2: configuration, active policy,
// enforcement statistics). Thresholds are deliberately plain so an auditor can recompute them.
var Checks = map[string]check{
	"CTL-INVENTORY": func(ctx context.Context, src Sources, now time.Time) (Finding, error) {
		rep, err := src.Posture(ctx, now)
		if err != nil {
			return Finding{}, fmt.Errorf("posture: %w", err)
		}
		f := Finding{Status: "unknown", Facts: map[string]any{"inventory": rep.Inventory}}
		for _, m := range rep.Metrics {
			if m.Name == "Shadow AI apps identified and given a status (top-100 by usage)" && m.Value != nil {
				f.Facts["decided_pct"] = *m.Value
				switch v := *m.Value; {
				case v >= 90:
					f.Status = "pass"
				case v >= 50:
					f.Status, f.Reasons = "partial", []string{fmt.Sprintf("%.0f%% of the most used AI apps have a decided status (target 90%%)", v)}
				default:
					f.Status, f.Reasons = "fail", []string{fmt.Sprintf("%.0f%% of the most used AI apps have a decided status (target 90%%)", v)}
				}
			}
		}
		if f.Status == "unknown" {
			f.Reasons = []string{"no AI usage measured yet"}
		}
		return f, nil
	},
	"CTL-DLP":       rulesCheck([]string{"tpl.pii-id-to-unsanctioned", "tpl.secret-to-any-ai", "tpl.pci-pan-redact", "tpl.restricted-to-sanctioned"}, nil),
	"CTL-INJECTION": rulesCheck([]string{"tpl.injection-high", "tpl.indirect-injection", "tpl.injection-then-high-tool"}, nil),
	"CTL-AGENT": rulesCheck([]string{"tpl.agent-not-active", "tpl.tool-not-allowed", "tpl.tool-scope-violation", "tpl.kill-switch", "tpl.injection-then-high-tool"},
		func(ctx context.Context, src Sources, _ time.Time) (Finding, error) {
			sum, err := src.Agents(ctx)
			if err != nil {
				return Finding{}, fmt.Errorf("agent registry: %w", err)
			}
			kills, err := count(ctx, src.DB, "SELECT count(*) FROM agents.kills WHERE lifted_at IS NULL")
			if err != nil {
				return Finding{}, err
			}
			f := Finding{Status: "pass", Facts: map[string]any{"agents": sum, "active_kill_switches": kills}}
			if n := len(sum.WithoutOwnerOrPolicy); n > 0 {
				f.Status, f.Reasons = "fail", []string{fmt.Sprintf("%d active agent(s) without owner or tool allow-list", n)}
			}
			return f, nil
		}),
	"CTL-MCP": rulesCheck([]string{"tpl.mcp-tool-not-approved", "tpl.indirect-injection"}, func(ctx context.Context, src Sources, _ time.Time) (Finding, error) {
		review, err := count(ctx, src.DB, "SELECT count(*) FROM agents.mcp_tools WHERE status = 'under_review'")
		if err != nil {
			return Finding{}, err
		}
		tools, err := count(ctx, src.DB, "SELECT count(*) FROM agents.mcp_tools")
		return Finding{Status: "pass", Facts: map[string]any{"mcp_tools": tools, "under_review": review}}, err
	}),
	"CTL-RATE": rulesCheck([]string{"tpl.tool-rate-limit"}, func(context.Context, Sources, time.Time) (Finding, error) {
		// Agent tool calls are rate-limited; per-user token quotas on the AI gateway arrive with ticket 13.
		return Finding{Status: "partial", Reasons: []string{"AI gateway token quotas (FR-PSEC-9) not in place yet"}, Facts: map[string]any{}}, nil
	}),
	"CTL-RESIDENCY": rulesCheck([]string{"res.offshore-restricted", "res.offshore-confidential", "res.offshore-unsanctioned"},
		func(ctx context.Context, src Sources, now time.Time) (Finding, error) {
			rep, err := src.Posture(ctx, now)
			if err != nil {
				return Finding{}, fmt.Errorf("posture: %w", err)
			}
			f := Finding{Status: "pass", Facts: map[string]any{"offshore_without_ojk_approval": rep.Inventory.OffshoreNoOJK}}
			if rep.Inventory.OffshoreNoOJK > 0 {
				f.Status, f.Reasons = "partial", []string{fmt.Sprintf("%d offshore AI app(s) in use without an OJK approval reference", rep.Inventory.OffshoreNoOJK)}
			}
			return f, nil
		}),
	"CTL-INCIDENT": func(ctx context.Context, src Sources, now time.Time) (Finding, error) {
		sum, err := src.Incidents(ctx, now.Add(-30*24*time.Hour), now)
		if err != nil {
			return Finding{}, fmt.Errorf("incidents: %w", err)
		}
		sum.Top = nil
		f := Finding{Status: "partial", Reasons: []string{"UU PDP 3×24 h breach timer arrives with ticket 26"}, Facts: map[string]any{"incidents": sum}}
		if sum.AckOverdue > 0 {
			f.Status = "fail"
			f.Reasons = append(f.Reasons, fmt.Sprintf("%d incident(s) past their acknowledgement SLA", sum.AckOverdue))
		}
		return f, nil
	},
	"CTL-AUDIT": func(ctx context.Context, src Sources, now time.Time) (Finding, error) {
		from := now.Add(-24 * time.Hour)
		n, err := src.AuditChain(ctx, from, now)
		var broken *audit.BrokenError
		switch {
		case errors.As(err, &broken):
			return Finding{Status: "fail", Reasons: []string{broken.Error()}, Facts: map[string]any{"from": from, "to": now}}, nil
		case err != nil:
			return Finding{}, err
		}
		return Finding{Status: "pass", Facts: map[string]any{"from": from, "to": now, "entries_verified": n}}, nil
	},
	"CTL-POSTURE": func(ctx context.Context, src Sources, now time.Time) (Finding, error) {
		rep, err := src.Posture(ctx, now)
		if err != nil {
			return Finding{Status: "fail", Reasons: []string{"posture report cannot be computed: " + err.Error()}, Facts: map[string]any{}}, nil
		}
		return Finding{Status: "pass", Facts: map[string]any{"overall": rep.Overall, "domains": rep.Domains}}, nil
	},
	"CTL-DATA": func(ctx context.Context, src Sources, now time.Time) (Finding, error) {
		var assets, high, scanned int64
		var last *time.Time
		if err := src.DB.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE exposure_score >= 60), count(*) FILTER (WHERE content_scanned)
			FROM data.assets WHERE deleted_at IS NULL`).Scan(&assets, &high, &scanned); err != nil {
			return Finding{}, err
		}
		if err := src.DB.QueryRow(ctx, "SELECT max(last_scan) FROM data.containers WHERE container_id <> '@oauth-audit'").Scan(&last); err != nil {
			return Finding{}, err
		}
		done, err := count(ctx, src.DB, "SELECT count(*) FROM data.remediations WHERE state = 'done' AND executed_at > $1", now.Add(-30*24*time.Hour))
		if err != nil {
			return Finding{}, err
		}
		f := Finding{Status: "pass", Facts: map[string]any{"assets": assets, "content_scanned": scanned, "exposure_ge_60": high, "last_scan": last,
			"remediations_done_30d": done}}
		switch {
		case last == nil:
			f.Status, f.Reasons = "fail", []string{"no data source scanned"}
		case now.Sub(*last) > 48*time.Hour:
			f.Status, f.Reasons = "partial", []string{"no scan in the last 48 h"}
		}
		if high > 0 && f.Status == "pass" {
			f.Status, f.Reasons = "partial", []string{fmt.Sprintf("%d asset(s) with exposure >= 60 open", high)}
		}
		return f, nil
	},
}

// ControlState is a control's latest status.
type ControlState struct {
	Control
	Status   string    `json:"status"`
	Reasons  []string  `json:"reasons"`
	Since    time.Time `json:"since"`
	Evidence int64     `json:"evidence_id"`
}

// Collect evaluates every control once: one evidence row each, and a status row whenever status or reasons
// change. A control whose source fails is "unknown", with the error as its reason.
func (s *Store) Collect(ctx context.Context, src Sources, actor string, now time.Time) ([]ControlState, error) {
	var out []ControlState
	for _, c := range Controls {
		f, err := Checks[c.ID](ctx, src, now)
		if err != nil {
			f = Finding{Status: "unknown", Reasons: []string{err.Error()}, Facts: map[string]any{}}
		}
		if f.Reasons == nil {
			f.Reasons = []string{}
		}
		summary := map[string]any{"control_id": c.ID, "status": f.Status, "reasons": f.Reasons, "facts": f.Facts, "at": now}
		st := ControlState{Control: c, Status: f.Status, Reasons: f.Reasons, Since: now}
		err = pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, `INSERT INTO compliance.evidence (control_id, kind, status, summary, sha256, collected_by, collected_at)
				VALUES ($1, 'automatic', $2, $3, $4, $5, $6) RETURNING id`, c.ID, f.Status, summary, canonicalSHA(summary), actor, now).Scan(&st.Evidence); err != nil {
				return err
			}
			var prev string
			var prevReasons []string
			err := tx.QueryRow(ctx, "SELECT status, reasons FROM compliance.control_status WHERE control_id = $1 ORDER BY at DESC, id DESC LIMIT 1", c.ID).Scan(&prev, &prevReasons)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if prev == f.Status && slices.Equal(prevReasons, f.Reasons) {
				return nil
			}
			_, err = tx.Exec(ctx, "INSERT INTO compliance.control_status (control_id, status, reasons, evidence_id, at) VALUES ($1, $2, $3, $4, $5)",
				c.ID, f.Status, f.Reasons, st.Evidence, now)
			return err
		})
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, nil
}

// Attach adds evidence the compliance team provides (a test report, a signed document): its hash and a note.
func (s *Store) Attach(ctx context.Context, actor, control, status, sha, note string, now time.Time) (int64, error) {
	if _, ok := controlByID[control]; !ok || len(sha) != 64 || note == "" {
		return 0, fmt.Errorf("%w: known control, the attachment's SHA-256 and a note are required", ErrInvalid)
	}
	if status == "" {
		status = "unknown"
	}
	if _, ok := rank[status]; !ok {
		return 0, fmt.Errorf("%w: status pass|partial|fail|unknown", ErrInvalid)
	}
	var id int64
	summary := map[string]any{"control_id": control, "note": note, "attachment_sha256": sha}
	err := pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO compliance.evidence (control_id, kind, status, summary, sha256, collected_by, collected_at)
			VALUES ($1, 'attachment', $2, $3, $4, $5, $6) RETURNING id`, control, status, summary, sha, actor, now).Scan(&id); err != nil {
			return err
		}
		return auditTx(ctx, tx, s.Tenant, actor, "compliance.evidence.attach", map[string]any{"evidence_id": id, "control_id": control, "sha256": sha})
	})
	return id, err
}

func auditTx(ctx context.Context, tx pgx.Tx, tenant, actor, action string, target map[string]any) error {
	_, err := audit.AppendTx(ctx, tx, tenant, actor, action, target)
	return err
}

// Current is every control's latest status.
func (s *Store) Current(ctx context.Context) ([]ControlState, error) {
	var out []ControlState
	for _, c := range Controls {
		st := ControlState{Control: c, Status: "unknown", Reasons: []string{"not collected yet"}}
		err := s.DB.QueryRow(ctx, "SELECT status, reasons, at, evidence_id FROM compliance.control_status WHERE control_id = $1 ORDER BY at DESC, id DESC LIMIT 1", c.ID).
			Scan(&st.Status, &st.Reasons, &st.Since, &st.Evidence)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		out = append(out, st)
	}
	return out, nil
}

// History is a control's status changes in [from, to).
func (s *Store) History(ctx context.Context, control string, from, to time.Time) ([]Transition, error) {
	if _, ok := controlByID[control]; !ok {
		return nil, ErrNotFound
	}
	rows, err := s.DB.Query(ctx, "SELECT at, status, reasons, evidence_id FROM compliance.control_status WHERE control_id = $1 AND at >= $2 AND at < $3 ORDER BY at, id", control, from, to)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Transition])
}
