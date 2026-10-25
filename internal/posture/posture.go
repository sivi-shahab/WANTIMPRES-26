// Package posture is the CISO dashboard (spec §4.11 FR-COMP-5, §1.5): a score per domain with the counts behind
// it, a 90-day trend, top risks, shadow AI, expiring exceptions, the AI inventory and the success metrics that M1
// can measure. Event figures come from the analytic store (OpenSearch, ticket 15); the rest from Postgres.
package posture

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"

	"wantimpres26/internal/agents"
	"wantimpres26/internal/catalog"
	"wantimpres26/internal/incident"
	"wantimpres26/internal/lifecycle"
)

// Domain is one posture score: Numerator/Denominator as a percentage (higher is better). Score is nil when there
// is nothing to measure (Denominator 0), not 100: an empty domain is unknown, not healthy.
type Domain struct {
	Score       *float64 `json:"score"`
	Numerator   int64    `json:"numerator"`
	Denominator int64    `json:"denominator"`
	Definition  string   `json:"definition"`
}

func ratio(num, den int64, def string) Domain {
	d := Domain{Numerator: num, Denominator: den, Definition: def}
	if den > 0 {
		v := 100 * float64(num) / float64(den)
		d.Score = &v
	}
	return d
}

// Definitions: the formula behind each domain score, returned with it so the number can be checked.
const (
	DefDiscovery = "AI events (30 d) to apps whose status the bank has decided / all AI events"
	DefData      = "sensitive events (classes, or confidential/restricted) that were blocked, redacted, tokenized, quarantined or held for approval / all sensitive events"
	DefPrompt    = "injection or jailbreak attempts (score >= 0.8) that were blocked, quarantined or held / all such attempts"
	DefAgent     = "agent events from agents marked registered / all agent events (missing = unregistered)"
	DefHygiene   = "time-bound controls in good standing / all: active exceptions not expiring within 7 d, catalog reviews not overdue, incidents not past their ack SLA"
)

var (
	protected = []string{"block", "redact", "tokenize", "quarantine", "require_approval"}
	stopped   = []string{"block", "quarantine", "require_approval"}
)

// eventAggs computes the event-based domains for whatever documents the enclosing query selects.
func eventAggs(decided []string) map[string]any {
	terms := func(field string, v []string) map[string]any {
		return map[string]any{"terms": map[string]any{field: v}}
	}
	should := func(q ...any) map[string]any {
		return map[string]any{"bool": map[string]any{"should": q, "minimum_should_match": 1}}
	}
	gte := func(field string) map[string]any {
		return map[string]any{"range": map[string]any{field: map[string]any{"gte": 0.8}}}
	}
	return map[string]any{
		"decided": map[string]any{"filter": terms("app_id", append([]string{}, decided...))},
		"sensitive": map[string]any{
			"filter": should(map[string]any{"exists": map[string]any{"field": "classes.type"}}, terms("sensitivity", []string{"confidential", "restricted"})),
			"aggs":   map[string]any{"protected": map[string]any{"filter": terms("action", protected)}},
		},
		"attack": map[string]any{
			"filter": should(gte("injection_score"), gte("jailbreak_score")),
			"aggs":   map[string]any{"stopped": map[string]any{"filter": terms("action", stopped)}},
		},
		"agent": map[string]any{
			"filter": map[string]any{"exists": map[string]any{"field": "agent_id"}},
			"aggs":   map[string]any{"registered": map[string]any{"filter": map[string]any{"term": map[string]any{"agent_registered": true}}}},
		},
	}
}

type count struct {
	DocCount int64 `json:"doc_count"`
}

type eventBuckets struct {
	DocCount  int64 `json:"doc_count"`
	Decided   count `json:"decided"`
	Sensitive struct {
		count
		Protected count `json:"protected"`
	} `json:"sensitive"`
	Attack struct {
		count
		Stopped count `json:"stopped"`
	} `json:"attack"`
	Agent struct {
		count
		Registered count `json:"registered"`
	} `json:"agent"`
}

func (b eventBuckets) domains() map[string]Domain {
	return map[string]Domain{
		"discovery": ratio(b.Decided.DocCount, b.DocCount, DefDiscovery),
		"data":      ratio(b.Sensitive.Protected.DocCount, b.Sensitive.DocCount, DefData),
		"prompt":    ratio(b.Attack.Stopped.DocCount, b.Attack.DocCount, DefPrompt),
		"agent":     ratio(b.Agent.Registered.DocCount, b.Agent.DocCount, DefAgent),
	}
}

func timeRange(from, to time.Time) map[string]any {
	return map[string]any{"range": map[string]any{"ts": map[string]any{"gte": from.UTC().Format(time.RFC3339Nano), "lt": to.UTC().Format(time.RFC3339Nano)}}}
}

// Searcher runs a query DSL body over the event indices (ingest.OpenSearch.Search).
type Searcher func(ctx context.Context, body []byte) ([]byte, error)

// Sources are the stores the report reads.
type Sources struct {
	Search    Searcher
	Apps      *catalog.Store
	Incidents *incident.Store
	Policies  *lifecycle.Store
	Agents    *agents.Store
}

// Day is one point of the trend.
type Day struct {
	Date   string              `json:"date"`
	Events int64               `json:"events"`
	Scores map[string]*float64 `json:"scores"`
}

// Metric is a §1.5 success metric.
type Metric struct {
	Name   string   `json:"name"`
	Target string   `json:"target"`
	Value  *float64 `json:"value,omitempty"`
	Unit   string   `json:"unit,omitempty"`
	Status string   `json:"status"` // measured | not_measured
	Note   string   `json:"note,omitempty"`
}

// Report is GET /posture.
type Report struct {
	GeneratedAt time.Time         `json:"generated_at"`
	WindowDays  int               `json:"window_days"`
	Overall     *float64          `json:"overall"` // mean of the domains that have data
	Domains     map[string]Domain `json:"domains"`
	Trend       []Day             `json:"trend"` // 90 days, event-based domains (hygiene is point-in-time)
	TopRisks    struct {
		Incidents []incident.Incident `json:"incidents"`
		Apps      []catalog.View      `json:"apps"` // most sensitive events
	} `json:"top_risks"`
	Incidents          incident.Summary      `json:"incidents"`
	ShadowAI           []catalog.View        `json:"shadow_ai"` // status not decided, most used first
	ExpiringExceptions []lifecycle.Exception `json:"expiring_exceptions"`
	Inventory          struct {
		Apps          int            `json:"apps"`
		BySanction    map[string]int `json:"by_sanction"`
		OffshoreNoOJK int            `json:"offshore_without_ojk_approval"`
		ReviewOverdue int            `json:"review_overdue"`
		NotInCatalog  int            `json:"observed_not_in_catalog"`
	} `json:"inventory"`
	Agents agents.Summary `json:"agents"`
	// Servers that reached AI providers without the AI gateway in the window (ticket 43): each is a finding.
	GatewayBypass []catalog.Bypass `json:"gateway_bypass"`
	Metrics       []Metric         `json:"metrics"`
}

const (
	Window      = 30 * 24 * time.Hour
	TrendWindow = 90 * 24 * time.Hour
)

// Compute builds the report as of now.
func (src Sources) Compute(ctx context.Context, now time.Time) (Report, error) {
	r := Report{GeneratedAt: now, WindowDays: int(Window.Hours() / 24), Domains: map[string]Domain{}}
	apps, _, err := src.Apps.List(ctx, catalog.ListOptions{Sort: "-events"}, now)
	if err != nil {
		return r, err
	}
	var decided []string
	for _, a := range apps {
		if a.Decided {
			decided = append(decided, a.ID)
		}
	}

	// Event domains over the window.
	body, _ := json.Marshal(map[string]any{"size": 0, "track_total_hits": true, "query": timeRange(now.Add(-Window), now), "aggs": eventAggs(decided)})
	raw, err := src.Search(ctx, body)
	if err != nil {
		return r, fmt.Errorf("analytic store: %w", err)
	}
	var res struct {
		Hits struct {
			Total struct {
				Value int64 `json:"value"`
			} `json:"total"`
		} `json:"hits"`
		Aggregations eventBuckets `json:"aggregations"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return r, err
	}
	res.Aggregations.DocCount = res.Hits.Total.Value
	for k, d := range res.Aggregations.domains() {
		r.Domains[k] = d
	}

	// Trend: the same aggregations per day.
	body, _ = json.Marshal(map[string]any{"size": 0, "query": timeRange(now.Add(-TrendWindow), now), "aggs": map[string]any{
		"days": map[string]any{"date_histogram": map[string]any{"field": "ts", "calendar_interval": "day", "min_doc_count": 0, "format": "yyyy-MM-dd",
			"extended_bounds": map[string]any{"min": now.Add(-TrendWindow).UTC().Format("2006-01-02"), "max": now.UTC().Format("2006-01-02")}},
			"aggs": eventAggs(decided)}}})
	if raw, err = src.Search(ctx, body); err != nil {
		return r, fmt.Errorf("analytic store: %w", err)
	}
	var trend struct {
		Aggregations struct {
			Days struct {
				Buckets []struct {
					Key string `json:"key_as_string"`
					eventBuckets
				} `json:"buckets"`
			} `json:"days"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(raw, &trend); err != nil {
		return r, err
	}
	for _, b := range trend.Aggregations.Days.Buckets {
		day := Day{Date: b.Key, Events: b.DocCount, Scores: map[string]*float64{}}
		for k, d := range b.domains() {
			day.Scores[k] = d.Score
		}
		r.Trend = append(r.Trend, day)
	}

	// Postgres: incidents, exceptions, catalog.
	if r.Incidents, err = src.Incidents.Summarize(ctx, now.Add(-Window), now); err != nil {
		return r, err
	}
	r.TopRisks.Incidents = r.Incidents.Top
	exc, err := src.Policies.Exceptions(ctx)
	if err != nil {
		return r, err
	}
	active, expiring := 0, []lifecycle.Exception{}
	for _, e := range exc {
		if e.State == "active" && e.ExpiresAt.After(now) {
			active++
			if e.ExpiresAt.Sub(now) <= lifecycle.ExpiryNotice {
				expiring = append(expiring, e)
			}
		}
	}
	sort.Slice(expiring, func(i, j int) bool { return expiring[i].ExpiresAt.Before(expiring[j].ExpiresAt) })
	r.ExpiringExceptions = expiring

	r.Inventory.BySanction = map[string]int{}
	reviewed, overdue := 0, 0
	for _, a := range apps {
		if a.Source == "observed" {
			r.Inventory.NotInCatalog++
		} else {
			r.Inventory.Apps++
			r.Inventory.BySanction[a.Sanction]++
		}
		if slices.Contains(a.Flags, catalog.FlagOffshoreNoOJK) {
			r.Inventory.OffshoreNoOJK++
		}
		if a.ReviewAt != nil {
			reviewed++
		}
		if slices.Contains(a.Flags, catalog.FlagReviewOverdue) {
			overdue++
		}
		if !a.Decided && a.Usage != nil && a.Usage.Events > 0 && len(r.ShadowAI) < 10 {
			r.ShadowAI = append(r.ShadowAI, a)
		}
	}
	r.Inventory.ReviewOverdue = overdue
	bySensitive := slices.Clone(apps)
	sort.SliceStable(bySensitive, func(i, j int) bool {
		return bySensitive[i].Usage.SensitiveEvents > bySensitive[j].Usage.SensitiveEvents
	})
	for _, a := range bySensitive {
		if a.Usage.SensitiveEvents > 0 && len(r.TopRisks.Apps) < 10 {
			r.TopRisks.Apps = append(r.TopRisks.Apps, a)
		}
	}

	items := int64(active + reviewed + r.Incidents.AckSLA)
	bad := int64(len(expiring) + overdue + r.Incidents.AckOverdue)
	r.Domains["policy_hygiene"] = ratio(items-bad, items, DefHygiene)

	var sum float64
	var n int
	for _, d := range r.Domains {
		if d.Score != nil {
			sum, n = sum+*d.Score, n+1
		}
	}
	if n > 0 {
		v := sum / float64(n)
		r.Overall = &v
	}
	reg, err := src.Agents.Summarize(ctx)
	if err != nil {
		return r, err
	}
	r.Agents = reg
	if r.GatewayBypass, err = src.Apps.Bypasses(ctx, now.Add(-Window)); err != nil {
		return r, err
	}
	r.Metrics = metrics(apps, r.Incidents, reg)
	servers := map[string]bool{}
	for _, b := range r.GatewayBypass {
		servers[b.Server] = true
	}
	bypassing := float64(len(servers))
	r.Metrics = append(r.Metrics, Metric{Name: "Servers reaching AI providers without the AI gateway", Target: "0", Value: &bypassing, Status: "measured",
		Note: fmt.Sprintf("%d server/domain pairs in the window, from SWG/DNS logs (shadow-baseline -servers)", len(r.GatewayBypass))})
	return r, nil
}

// metrics are the §1.5 targets M1 can measure; the rest say which ticket measures them.
func metrics(apps []catalog.View, inc incident.Summary, reg agents.Summary) []Metric {
	top := apps // already sorted by events, observed apps included
	if len(top) > 100 {
		top = top[:100]
	}
	used, decided := 0, 0
	for _, a := range top {
		if a.Usage != nil && a.Usage.Events > 0 {
			used++
			if a.Decided {
				decided++
			}
		}
	}
	m := []Metric{{Name: "Shadow AI apps identified and given a status (top-100 by usage)", Target: ">= 90%", Unit: "%", Status: "measured",
		Note: fmt.Sprintf("%d of %d used apps", decided, used)}}
	if used > 0 {
		v := 100 * float64(decided) / float64(used)
		m[0].Value = &v
	}
	mttd := Metric{Name: "MTTD critical incidents", Target: "<= 5 min", Unit: "minutes", Status: "measured",
		Note: fmt.Sprintf("%d critical incidents in the window; first event to incident", inc.CriticalOpened)}
	if inc.MTTDCriticalSec != nil {
		v := *inc.MTTDCriticalSec / 60
		mttd.Value = &v
	}
	m = append(m, mttd)
	orphans := float64(len(reg.WithoutOwnerOrPolicy))
	m = append(m, Metric{Name: "Active agents without owner and policy", Target: "0", Value: &orphans, Status: "measured",
		Note: fmt.Sprintf("%d registered agents; policy = tool allow-list; owner-less agents are quarantined automatically", reg.Total)})
	for _, nm := range []struct{ name, target, note string }{
		{"Visible AI traffic coverage (discovered / total AI egress)", ">= 95% via proxy", "needs the proxy log baseline (ticket 03)"},
		{"Precision of P0 sensitive-data detectors", ">= 0.95", "eval corpus (ticket 04) and detectors (08, 09)"},
		{"Recall of P0 sensitive-data detectors", ">= 0.90", "eval corpus (ticket 04) and detectors (08, 09)"},
		{"Prompt-injection classifier FPR on benign traffic", "<= 1%", "classifier (ticket 10)"},
		{"Attack success rate drop with gateway (AgentDojo-style)", ">= 70% lower", "gateway (ticket 13) and agent suite"},
		{"Added inline latency p95 (text <= 8K tokens)", "<= 80 ms", "gateway load test (ticket 21)"},
		{"Breach report preparation time", "<= 24 h", "breach workflow (ticket 26)"},
	} {
		m = append(m, Metric{Name: nm.name, Target: nm.target, Status: "not_measured", Note: nm.note})
	}
	return m
}
