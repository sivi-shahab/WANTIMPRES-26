package shadow

import (
	"cmp"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"wantimpres26/internal/catalog"
)

// Report is the shadow AI baseline. Users appear only as HMAC pseudonyms; units are organisational, not personal.
type Report struct {
	GeneratedAt    time.Time `json:"generated_at"`
	From           string    `json:"from"`
	To             string    `json:"to"`
	DaysCovered    int       `json:"days_covered"`
	MeetsMinDays   bool      `json:"meets_min_days"` // ≥ MinDays distinct days of logs
	Lines          int       `json:"lines"`
	Unparsed       int       `json:"unparsed"`
	Requests       int       `json:"requests"`
	AIRequests     int       `json:"ai_requests"`     // attributed to a catalog app
	ReviewRequests int       `json:"review_requests"` // in the review queue (not attributed)
	AIUsers        int       `json:"ai_users"`
	Apps           []AppRow  `json:"apps"`
	Users          []UserRow `json:"top_users"`
	Units          []UnitRow `json:"units"`
	Weeks          []WeekRow `json:"weeks"`
	Review         []Review  `json:"review_queue"`
	// Servers that reached AI providers without the gateway (WatchBypass); feed to POST /catalog/gateway-bypass.
	GatewayBypass []catalog.Bypass `json:"gateway_bypass,omitempty"`
}

type AppRow struct {
	ID         string `json:"app_id"`
	Name       string `json:"name"`
	Category   string `json:"category"`
	Requests   int    `json:"requests"`
	Users      int    `json:"users"`
	ActiveDays int    `json:"active_days"`
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`
}

type UserRow struct {
	User     string   `json:"user"` // HMAC-SHA256 with the tenant pepper
	Unit     string   `json:"unit"`
	Requests int      `json:"requests"`
	Apps     []string `json:"apps"`
}

type UnitRow struct {
	Unit     string   `json:"unit"`
	Requests int      `json:"requests"`
	Users    int      `json:"users"`
	TopApps  []string `json:"top_apps"`
}

type WeekRow struct {
	Week     string   `json:"week"` // ISO week
	Requests int      `json:"requests"`
	Users    int      `json:"users"`
	TopApps  []string `json:"top_apps"`
}

type Review struct {
	Host       string   `json:"host"`
	Confidence float64  `json:"confidence"`
	Signals    []string `json:"signals"`
	Candidates []string `json:"candidates,omitempty"`
	Requests   int      `json:"requests"`
	Users      int      `json:"users"`
}

// Report summarises what was added; top limits the user list and the per-row app lists.
func (b *Baseline) Report(now time.Time, top int) Report {
	days := slices.Sorted(maps.Keys(b.days))
	r := Report{GeneratedAt: now.UTC(), DaysCovered: len(days), MeetsMinDays: len(days) >= MinDays, Lines: b.lines,
		Unparsed: b.unparsed, Requests: b.requests, AIRequests: b.aiRequests, ReviewRequests: b.reviewRequests, AIUsers: len(b.user)}
	if len(days) > 0 {
		r.From, r.To = days[0], days[len(days)-1]
	}
	for id, a := range b.app {
		r.Apps = append(r.Apps, AppRow{ID: id, Name: b.apps[id].Name, Category: b.apps[id].Category, Requests: a.requests,
			Users: len(a.users), ActiveDays: len(a.days), FirstSeen: a.first.Format(time.DateOnly), LastSeen: a.last.Format(time.DateOnly)})
	}
	slices.SortFunc(r.Apps, func(x, y AppRow) int {
		return cmp.Or(cmp.Compare(y.Users, x.Users), cmp.Compare(y.Requests, x.Requests), cmp.Compare(x.ID, y.ID))
	})
	for p, u := range b.user {
		r.Users = append(r.Users, UserRow{User: p, Unit: u.unit, Requests: u.requests, Apps: topKeys(u.apps, top)})
	}
	slices.SortFunc(r.Users, func(x, y UserRow) int {
		return cmp.Or(cmp.Compare(y.Requests, x.Requests), cmp.Compare(x.User, y.User))
	})
	r.Users = r.Users[:min(top, len(r.Users))]
	for name, u := range b.unit {
		r.Units = append(r.Units, UnitRow{Unit: name, Requests: u.requests, Users: len(u.users), TopApps: topKeys(u.apps, 5)})
	}
	slices.SortFunc(r.Units, func(x, y UnitRow) int { return cmp.Or(cmp.Compare(y.Users, x.Users), cmp.Compare(x.Unit, y.Unit)) })
	for wk, w := range b.week {
		r.Weeks = append(r.Weeks, WeekRow{Week: wk, Requests: w.requests, Users: len(w.users), TopApps: topKeys(w.apps, 5)})
	}
	slices.SortFunc(r.Weeks, func(x, y WeekRow) int { return cmp.Compare(x.Week, y.Week) })
	for host, v := range b.review {
		r.Review = append(r.Review, Review{Host: host, Confidence: v.d.Confidence, Signals: v.d.Signals, Candidates: v.d.Candidates,
			Requests: v.requests, Users: len(v.users)})
	}
	slices.SortFunc(r.Review, func(x, y Review) int { return cmp.Or(cmp.Compare(y.Users, x.Users), cmp.Compare(x.Host, y.Host)) })
	for _, f := range b.bypass {
		r.GatewayBypass = append(r.GatewayBypass, *f)
	}
	slices.SortFunc(r.GatewayBypass, func(x, y catalog.Bypass) int {
		return cmp.Or(cmp.Compare(y.Requests, x.Requests), cmp.Compare(x.Server, y.Server), cmp.Compare(x.Domain, y.Domain))
	})
	return r
}

func topKeys(m map[string]int, n int) []string {
	ks := slices.Collect(maps.Keys(m))
	slices.SortFunc(ks, func(a, b string) int { return cmp.Or(cmp.Compare(m[b], m[a]), cmp.Compare(a, b)) })
	return ks[:min(n, len(ks))]
}

// Markdown writes the report for people (the JSON is the same data for tools).
func (r Report) Markdown(w io.Writer) error {
	var s strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&s, f, a...) }
	p("# Baseline shadow AI\n\n")
	p("Periode %s s.d. %s (%d hari log", r.From, r.To, r.DaysCovered)
	if !r.MeetsMinDays {
		p(", **kurang dari %d hari: belum memenuhi syarat baseline**", MinDays)
	}
	p("). Dibuat %s.\n\n", r.GeneratedAt.Format(time.RFC3339))
	p("- Baris log: %d (tidak terbaca: %d)\n- Request: %d, ke app AI di katalog: %d, menunggu review: %d\n", r.Lines, r.Unparsed, r.Requests, r.AIRequests, r.ReviewRequests)
	p("- User yang memakai AI: %d (pseudonim HMAC)\n\n", r.AIUsers)
	p("## Top apps\n\n| App | Kategori | User | Request | Hari aktif | Pertama | Terakhir |\n|---|---|---:|---:|---:|---|---|\n")
	for _, a := range r.Apps {
		p("| %s (`%s`) | %s | %d | %d | %d | %s | %s |\n", a.Name, a.ID, a.Category, a.Users, a.Requests, a.ActiveDays, a.FirstSeen, a.LastSeen)
	}
	p("\n## Unit\n\n| Unit | User | Request | Top apps |\n|---|---:|---:|---|\n")
	for _, u := range r.Units {
		p("| %s | %d | %d | %s |\n", u.Unit, u.Users, u.Requests, strings.Join(u.TopApps, ", "))
	}
	p("\n## Top users (pseudonim)\n\n| User | Unit | Request | Apps |\n|---|---|---:|---|\n")
	for _, u := range r.Users {
		p("| `%s` | %s | %d | %s |\n", u.User[:16], u.Unit, u.Requests, strings.Join(u.Apps, ", "))
	}
	p("\n## Tren mingguan\n\n| Minggu | User | Request | Top apps |\n|---|---:|---:|---|\n")
	for _, wk := range r.Weeks {
		p("| %s | %d | %d | %s |\n", wk.Week, wk.Users, wk.Requests, strings.Join(wk.TopApps, ", "))
	}
	p("\n## Antrean review (confidence < 0,6 atau ambigu)\n\nTetapkan lewat katalog: app lokal (`POST /apps`) atau koreksi app yang ada.\n\n")
	p("| Host | Confidence | Sinyal | Kandidat | User | Request |\n|---|---:|---|---|---:|---:|\n")
	for _, v := range r.Review {
		p("| %s | %.2f | %s | %s | %d | %d |\n", v.Host, v.Confidence, strings.Join(v.Signals, ", "), strings.Join(v.Candidates, ", "), v.Users, v.Requests)
	}
	if len(r.GatewayBypass) > 0 {
		p("\n## Gateway bypass: server langsung ke provider AI\n\nTrafik ini seharusnya lewat AI gateway (runbook `docs/runbooks/egress-ai-gateway.md`). ")
		p("Kirim ke control-plane: `POST /catalog/gateway-bypass` dengan JSON laporan ini.\n\n| Server | Domain | App | Request | Pertama | Terakhir |\n|---|---|---|---:|---|---|\n")
		for _, f := range r.GatewayBypass {
			p("| %s | %s | %s | %d | %s | %s |\n", f.Server, f.Domain, f.AppID, f.Requests, f.FirstSeen.Format(time.RFC3339), f.LastSeen.Format(time.RFC3339))
		}
	}
	_, err := io.WriteString(w, s.String())
	return err
}
