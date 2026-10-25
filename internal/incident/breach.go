package incident

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/events"
)

// FR-INC-6 breach workflow (UU PDP 27/2022 Pasal 46): an incident in which personal data got out starts a 3×24 hour
// notification timer. The system drafts the report (data exposed, when and how, handling and recovery, affected
// subjects as far as they can be told) and alerts when less than a day is left.

const (
	BreachWindow = 72 * time.Hour // Pasal 46 ayat (1): 3×24 jam
	BreachAlert  = 24 * time.Hour // escalate when less than this is left
)

var ErrInvalid = errors.New("invalid request")

// PersonalData reports whether a detector class is personal data (UU PDP Pasal 4): identity numbers and contact
// details, and the specific kinds (financial, health). Secrets and credentials are not.
func PersonalData(class string) bool {
	return strings.HasPrefix(class, "PII") || specific(class)
}

// specific is Pasal 4 ayat (2) data pribadi yang bersifat spesifik: financial (cards, accounts) and health.
func specific(class string) bool {
	return strings.HasPrefix(class, "PCI.") || strings.HasPrefix(class, "FIN.") || strings.HasPrefix(class, "PHI")
}

// Exposed reports whether an event let personal data out: an outbound event the PEP allowed (or only warned on)
// that carries a personal-data class. Blocked, redacted, tokenized or held events kept it in.
func Exposed(e events.Event) bool {
	if e.Direction == "response" || (e.Action != "allow" && e.Action != "warn") {
		return false
	}
	return slices.ContainsFunc(e.Classes, func(c events.Class) bool { return PersonalData(c.Type) })
}

// startBreach starts the timer once; later calls are no-ops. A breach is at least high severity (1 h ack SLA).
func (s *Store) startBreach(ctx context.Context, tx pgx.Tx, id, basis, actor, note string, now time.Time) error {
	var tenant string
	err := tx.QueryRow(ctx, `UPDATE incident.incidents SET breach_started_at = $2, breach_deadline = $3, breach_basis = $4
		WHERE id = $1 AND breach_started_at IS NULL RETURNING tenant_id::text`, id, now, now.Add(BreachWindow), basis).Scan(&tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	if _, err := audit.AppendTx(ctx, tx, tenant, actor, "incident.breach.start", map[string]any{"incident": id, "basis": basis,
		"deadline": now.Add(BreachWindow), "note": note}); err != nil {
		return err
	}
	return s.escalate(ctx, tx, id, "high", now, actor, "personal data breach")
}

// DeclareBreach starts the timer by hand for an incident the automatic rule missed (e.g. data out through a
// channel without a PEP). The timer runs from now.
func (s *Store) DeclareBreach(ctx context.Context, id, note, actor string, now time.Time) (Incident, error) {
	if strings.TrimSpace(note) == "" {
		return Incident{}, fmt.Errorf("%w: a declared breach needs a note", ErrInvalid)
	}
	inc, err := s.Get(ctx, id)
	if err != nil {
		return Incident{}, err
	}
	if inc.Breach != nil {
		return Incident{}, fmt.Errorf("%w: breach timer already running since %s", ErrInvalidTransition, inc.Breach.StartedAt.Format(time.RFC3339))
	}
	if err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error { return s.startBreach(ctx, tx, id, "declared", actor, note, now) }); err != nil {
		return Incident{}, err
	}
	return s.Get(ctx, id)
}

// CloseBreach stops the timer: notified (the DPO sent the notification) or dismissed (no personal data actually
// got out, e.g. test data). Both need a note; both are audited.
func (s *Store) CloseBreach(ctx context.Context, id, outcome, note, actor string, now time.Time) (Incident, error) {
	if (outcome != "notified" && outcome != "dismissed") || strings.TrimSpace(note) == "" {
		return Incident{}, fmt.Errorf("%w: outcome notified|dismissed with a note", ErrInvalid)
	}
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var tenant string
		var deadline time.Time
		err := tx.QueryRow(ctx, `UPDATE incident.incidents SET breach_closed_at = $2, breach_outcome = $3
			WHERE id = $1 AND breach_started_at IS NOT NULL AND breach_closed_at IS NULL RETURNING tenant_id::text, breach_deadline`, id, now, outcome).
			Scan(&tenant, &deadline)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: no running breach timer", ErrInvalidTransition)
		} else if err != nil {
			return err
		}
		_, err = audit.AppendTx(ctx, tx, tenant, actor, "incident.breach."+outcome, map[string]any{"incident": id, "note": note,
			"deadline": deadline, "late": now.After(deadline)})
		return err
	})
	if err != nil {
		return Incident{}, err
	}
	return s.Get(ctx, id)
}

// SweepBreaches escalates running timers with less than BreachAlert left, once each: severity critical and an
// incident.breach.escalate audit entry, which the SIEM and the SOAR webhook receive (siem-export).
func (s *Store) SweepBreaches(ctx context.Context, now time.Time) (n int, err error) {
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, tenant_id::text, breach_deadline FROM incident.incidents
			WHERE breach_started_at IS NOT NULL AND breach_closed_at IS NULL AND breach_escalated_at IS NULL AND breach_deadline < $1
			FOR UPDATE SKIP LOCKED`, now.Add(BreachAlert))
		if err != nil {
			return err
		}
		type due struct {
			id, tenant string
			deadline   time.Time
		}
		list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (due, error) {
			var d due
			return d, r.Scan(&d.id, &d.tenant, &d.deadline)
		})
		if err != nil {
			return err
		}
		for _, d := range list {
			left := d.deadline.Sub(now)
			if _, err := tx.Exec(ctx, "UPDATE incident.incidents SET breach_escalated_at = $2 WHERE id = $1", d.id, now); err != nil {
				return err
			}
			if _, err := audit.AppendTx(ctx, tx, d.tenant, "system", "incident.breach.escalate", map[string]any{"incident": d.id,
				"deadline": d.deadline, "remaining_hours": hours(left)}); err != nil {
				return err
			}
			if err := s.escalate(ctx, tx, d.id, "critical", now, "system", fmt.Sprintf("breach notification due in %.1f h", hours(left))); err != nil {
				return err
			}
		}
		n = len(list)
		return nil
	})
	return n, err
}

func hours(d time.Duration) float64 { return float64(d.Round(6*time.Minute)) / float64(time.Hour) }

// BreachTimers is the breach_timer_remaining_hours metric: running timers and the least time left (nil: none).
func (s *Store) BreachTimers(ctx context.Context, now time.Time) (running int, minHours *float64, err error) {
	var least *time.Time
	err = s.db.QueryRow(ctx, `SELECT count(*), min(breach_deadline) FROM incident.incidents
		WHERE breach_started_at IS NOT NULL AND breach_closed_at IS NULL`).Scan(&running, &least)
	if least != nil {
		h := hours(least.Sub(now))
		minHours = &h
	}
	return running, minHours, err
}

// --- draft report -------------------------------------------------------------------------------------------

// BreachReport is the draft notification material (Pasal 46 ayat (2)). It holds only what the redacted evidence
// says: classes and counts, never the values.
type BreachReport struct {
	Incident    string    `json:"incident"`
	Title       string    `json:"title"`
	GeneratedAt time.Time `json:"generated_at"`
	Timer       Breach    `json:"timer"`
	HoursLeft   float64   `json:"hours_left"`

	// a. data pribadi yang terungkap
	PersonalData []Exposure `json:"personal_data"`
	Sensitivity  []string   `json:"sensitivity"`
	// b. kapan dan bagaimana terungkap
	DetectedAt    time.Time      `json:"detected_at"`
	FirstExposure *time.Time     `json:"first_exposure,omitempty"`
	LastExposure  *time.Time     `json:"last_exposure,omitempty"`
	Channels      []string       `json:"channels"`
	Destinations  []string       `json:"destinations"`
	Principals    int            `json:"principals"` // pseudonymous ids; identities resolve through the IdP
	Agents        []string       `json:"agents,omitempty"`
	Timeline      []TimelineItem `json:"timeline"`
	// c. upaya penanganan dan pemulihan
	Handling []HandlingItem `json:"handling"`
	// subjek data terdampak
	Subjects Subjects `json:"subjects"`
}

type Exposure struct {
	Class    string `json:"class"`
	Specific bool   `json:"specific"` // Pasal 4 ayat (2)
	Values   int    `json:"values"`   // detected occurrences in exposed events
	Events   int    `json:"events"`
}

type TimelineItem struct {
	TS      time.Time `json:"ts"`
	Event   string    `json:"event"`
	Channel string    `json:"channel"`
	App     string    `json:"app"`
	Action  string    `json:"action"`
	Classes []string  `json:"classes"`
	Risk    int       `json:"risk"`
	Exposed bool      `json:"exposed"`
}

type HandlingItem struct {
	At    time.Time `json:"at"`
	Actor string    `json:"actor"`
	What  string    `json:"what"`
}

type Subjects struct {
	Determinable bool   `json:"determinable"`
	UpperBound   int    `json:"upper_bound"`
	Note         string `json:"note"`
}

// DraftBreachReport builds the draft from the incident's events, transitions and containment actions. The first
// draft is timestamped (breach_drafted_at: the "report within 24 hours of detection" metric) and audited.
func (s *Store) DraftBreachReport(ctx context.Context, id, actor string, now time.Time) (BreachReport, error) {
	inc, err := s.Get(ctx, id)
	if err != nil {
		return BreachReport{}, err
	}
	if inc.Breach == nil {
		return BreachReport{}, fmt.Errorf("%w: no breach timer on this incident", ErrInvalidTransition)
	}
	raws, err := s.Events(ctx, id)
	if err != nil {
		return BreachReport{}, err
	}
	r := BreachReport{Incident: id, Title: inc.Title, GeneratedAt: now, Timer: *inc.Breach, HoursLeft: hours(inc.Breach.Deadline.Sub(now)),
		DetectedAt: inc.OpenedAt, Channels: []string{}, Destinations: []string{}, Sensitivity: []string{}, PersonalData: []Exposure{},
		Timeline: []TimelineItem{}, Handling: []HandlingItem{}}
	byClass := map[string]*Exposure{}
	principals := map[string]bool{}
	for _, raw := range raws {
		var e events.Event
		if err := json.Unmarshal(raw, &e); err != nil {
			return BreachReport{}, err
		}
		ts, _ := time.Parse(time.RFC3339Nano, e.TS)
		item := TimelineItem{TS: ts, Event: e.EventID, Channel: e.Channel, App: e.AppID, Action: e.Action, Classes: []string{}, Risk: e.RiskScore, Exposed: Exposed(e)}
		for _, c := range e.Classes {
			item.Classes = append(item.Classes, c.Type)
		}
		r.Timeline = append(r.Timeline, item)
		// A declared breach may have no event the automatic rule counts; then every personal-data event is listed.
		if !item.Exposed && inc.Breach.Basis == "auto" {
			continue
		}
		counted := false
		for _, c := range e.Classes {
			if !PersonalData(c.Type) {
				continue
			}
			x := byClass[c.Type]
			if x == nil {
				x = &Exposure{Class: c.Type, Specific: specific(c.Type)}
				byClass[c.Type] = x
			}
			x.Values += max(c.Count, 1)
			x.Events++
			counted = true
		}
		if !counted {
			continue
		}
		if r.FirstExposure == nil {
			r.FirstExposure = &ts
		}
		r.LastExposure = &ts
		r.Channels = appendNew(r.Channels, e.Channel)
		r.Destinations = appendNew(r.Destinations, e.AppID)
		r.Sensitivity = appendNew(r.Sensitivity, e.Sensitivity)
		if e.AgentID != "" {
			r.Agents = appendNew(r.Agents, e.AgentID)
		}
		principals[e.PrincipalID] = true
	}
	r.Principals = len(principals)
	for _, x := range byClass {
		r.PersonalData = append(r.PersonalData, *x)
		r.Subjects.UpperBound += x.Values
	}
	slices.SortFunc(r.PersonalData, func(a, b Exposure) int { return strings.Compare(a.Class, b.Class) })
	r.Subjects.Note = "Evidence hanya menyimpan kelas dan jumlah (ter-redact), jadi jumlah subjek tidak dapat dipastikan; " +
		"batas atas = jumlah nilai data pribadi yang terdeteksi. Penentuan pasti memerlukan unmask evidence (evidence.unmask, dengan justifikasi)."

	r.Handling, err = s.handling(ctx, id)
	if err != nil {
		return BreachReport{}, err
	}
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE incident.incidents SET breach_drafted_at = $2 WHERE id = $1 AND breach_drafted_at IS NULL", id, now)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		r.Timer.DraftedAt = &now
		_, err = audit.AppendTx(ctx, tx, inc.TenantID, actor, "incident.breach.draft", map[string]any{"incident": id,
			"hours_since_detection": hours(now.Sub(inc.OpenedAt)), "classes": len(r.PersonalData)})
		return err
	})
	return r, err
}

// handling is what the SOC did: transitions and containment actions, in order.
func (s *Store) handling(ctx context.Context, id string) ([]HandlingItem, error) {
	rows, err := s.db.Query(ctx, `
		SELECT at, actor, 'status ' || from_state || ' -> ' || to_state || CASE WHEN note <> '' THEN ': ' || note ELSE '' END
		  FROM incident.transitions WHERE incident_id = $1
		UNION ALL
		SELECT at, actor, 'containment ' || action || ' ' || result::text FROM incident.actions WHERE incident_id = $1
		ORDER BY 1`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[HandlingItem])
}

func appendNew(list []string, v string) []string {
	if v == "" || slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}

// Markdown renders the draft for the DPO, in Indonesian, section by section of Pasal 46 ayat (2).
func (r BreachReport) Markdown() string {
	var b strings.Builder
	ts := func(t time.Time) string { return t.In(wib).Format("2006-01-02 15:04 WIB") }
	fmt.Fprintf(&b, "# DRAFT Laporan Kegagalan Pelindungan Data Pribadi\n\nInsiden: %s (%s)\n\n", r.Incident, r.Title)
	fmt.Fprintf(&b, "Timer 3×24 jam mulai %s, batas pemberitahuan **%s** (sisa %.1f jam). Draft dibuat %s.\n\n",
		ts(r.Timer.StartedAt), ts(r.Timer.Deadline), r.HoursLeft, ts(r.GeneratedAt))
	b.WriteString("## a. Data pribadi yang terungkap\n\n| Kelas | Jenis | Jumlah nilai | Event |\n|---|---|---|---|\n")
	for _, x := range r.PersonalData {
		kind := "umum"
		if x.Specific {
			kind = "spesifik"
		}
		fmt.Fprintf(&b, "| %s | %s | %d | %d |\n", x.Class, kind, x.Values, x.Events)
	}
	fmt.Fprintf(&b, "\nSensitivitas konten: %s.\n\n## b. Kapan dan bagaimana data pribadi terungkap\n\n", strings.Join(r.Sensitivity, ", "))
	if r.FirstExposure != nil {
		fmt.Fprintf(&b, "Pertama terungkap %s, terakhir %s; terdeteksi (insiden dibuka) %s.\n", ts(*r.FirstExposure), ts(*r.LastExposure), ts(r.DetectedAt))
	}
	fmt.Fprintf(&b, "Kanal: %s. Tujuan: %s. Pengguna internal (pseudonim): %d.", strings.Join(r.Channels, ", "), strings.Join(r.Destinations, ", "), r.Principals)
	if len(r.Agents) > 0 {
		fmt.Fprintf(&b, " Agent: %s.", strings.Join(r.Agents, ", "))
	}
	b.WriteString("\n\n| Waktu | Kanal | Tujuan | Aksi | Kelas | Terungkap |\n|---|---|---|---|---|---|\n")
	for _, t := range r.Timeline {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %v |\n", ts(t.TS), t.Channel, t.App, t.Action, strings.Join(t.Classes, ", "), t.Exposed)
	}
	b.WriteString("\n## c. Upaya penanganan dan pemulihan\n\n")
	for _, h := range r.Handling {
		fmt.Fprintf(&b, "- %s, %s: %s\n", ts(h.At), h.Actor, h.What)
	}
	if len(r.Handling) == 0 {
		b.WriteString("- (belum ada)\n")
	}
	fmt.Fprintf(&b, "\n## Subjek data terdampak\n\nBatas atas: %d. %s\n", r.Subjects.UpperBound, r.Subjects.Note)
	return b.String()
}

var wib = time.FixedZone("WIB", 7*3600)
