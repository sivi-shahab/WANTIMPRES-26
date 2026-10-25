package mcpgw

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"wantimpres26/internal/incident"
)

// workflow is an agent's normal tool-call Markov chain: tool → [(next, p)], "" ends the session.
type workflow map[string][][2]any

var workflows = map[string]struct {
	start string
	flow  workflow
}{
	"cs-bot": {"search_customer", workflow{
		"search_customer": {{"get_account", 0.88}, {"get_cards", 0.09}, {"escalate_human", 0.03}},
		"get_account":     {{"create_ticket", 0.6}, {"send_reply", 0.4}},
		"get_cards":       {{"send_reply", 1.0}},
		"create_ticket":   {{"send_reply", 1.0}},
		"escalate_human":  {{"", 1.0}},
		"send_reply":      {{"", 1.0}},
	}},
	"payments-bot": {"get_balance", workflow{
		"get_balance":        {{"validate_recipient", 1.0}},
		"validate_recipient": {{"transfer", 0.7}, {"cancel", 0.3}},
		"transfer":           {{"notify", 1.0}},
		"cancel":             {{"", 1.0}},
		"notify":             {{"", 1.0}},
	}},
	"report-bot": {"query_sales", workflow{
		"query_sales":   {{"aggregate", 1.0}},
		"aggregate":     {{"render_report", 1.0}},
		"render_report": {{"email_report", 0.5}, {"", 0.5}},
		"email_report":  {{"", 1.0}},
	}},
}

type sim struct {
	r   *rand.Rand
	b   *Behavior
	now time.Time
	n   int
}

func (s *sim) session(agent string) []string {
	w := workflows[agent]
	s.n++
	sess := fmt.Sprint("trace-", s.n)
	var flagged []string
	for tool := w.start; tool != ""; {
		s.now = s.now.Add(time.Duration(5+s.r.IntN(20)) * time.Second)
		flagged = append(flagged, s.b.Observe(agent, sess, tool, s.now)...)
		x, next := s.r.Float64(), ""
		for _, c := range w.flow[tool] {
			if x -= c[1].(float64); x < 0 {
				next = c[0].(string)
				break
			}
		}
		tool = next
	}
	return flagged
}

// calls makes a scripted session of tools, gap apart.
func (s *sim) calls(agent string, tools []string, gap time.Duration) []string {
	s.n++
	sess := fmt.Sprint("trace-", s.n)
	var flagged []string
	for _, t := range tools {
		s.now = s.now.Add(gap)
		flagged = append(flagged, s.b.Observe(agent, sess, t, s.now)...)
	}
	return flagged
}

func repeat(t string, n int) []string { return slices.Repeat([]string{t}, n) }

// TestRogueAgentEval is the acceptance evaluation (ticket 39): agents run their normal workflows for a simulated
// working week, then each rogue scenario is injected into a fresh copy of that baseline. Every scenario must be
// caught with the expected anomaly; benign traffic after the week must stay below 1% flagged calls.
func TestRogueAgentEval(t *testing.T) {
	scenarios := []struct {
		name, agent string
		tools       []string
		gap         time.Duration
		want        string
	}{
		{"tool misuse: bulk export never used before (ASI02/ASI10)", "cs-bot", []string{"search_customer", "export_all_customers"}, 10 * time.Second, AnomalyNewTool},
		{"goal hijack: transfer without recipient validation (ASI01)", "payments-bot", []string{"get_balance", "transfer", "notify"}, 10 * time.Second, AnomalyRareSequence},
		{"runaway loop: report query repeated (ASI08 cascading failure)", "report-bot", repeat("query_sales", 120), 500 * time.Millisecond, AnomalyVolumeSpike},
		{"scraping: account lookups in a burst (ASI10)", "cs-bot", slices.Concat([]string{"search_customer"}, repeat("get_account", 60)), time.Second, AnomalyVolumeSpike},
	}
	run := func(days int) (calls, flagged int) {
		for seed := range uint64(10) {
			s := &sim{r: rand.New(rand.NewPCG(seed, 39)), b: &Behavior{}, now: time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)}
			week := func(count bool) {
				for range days * 40 {
					for _, agent := range []string{"cs-bot", "payments-bot", "report-bot"} {
						before := s.b.agents[agent]
						n := 0
						if before != nil {
							n = before.calls
						}
						f := s.session(agent)
						if count {
							calls += s.b.agents[agent].calls - n
							flagged += len(f)
						}
					}
					s.now = s.now.Add(time.Duration(s.r.IntN(10)) * time.Minute)
				}
			}
			week(false) // baseline
			week(true)  // benign traffic judged against it
			for _, sc := range scenarios {
				if got := s.clone().calls(sc.agent, sc.tools, sc.gap); !slices.Contains(got, sc.want) {
					t.Errorf("baseline %d days, seed %d, %s: anomalies %v, want %s", days, seed, sc.name, got, sc.want)
				}
			}
		}
		return calls, flagged
	}
	calls, flagged := run(5)
	t.Logf("baseline 5 working days: benign %d flagged of %d calls (%.3f%%); %d scenarios x 10 seeds all caught", flagged, calls, 100*float64(flagged)/float64(calls), len(scenarios))
	if float64(flagged) > 0.01*float64(calls) {
		t.Errorf("benign flag rate above 1%%")
	}
	// A one-day baseline has not seen every rare branch yet: measured, not required.
	calls, flagged = run(1)
	t.Logf("baseline 1 working day:  benign %d flagged of %d calls (%.3f%%)", flagged, calls, 100*float64(flagged)/float64(calls))
}

// clone copies the baselines so each scenario starts from the same learned week.
func (s *sim) clone() *sim {
	b := &Behavior{Config: s.b.Config, agents: map[string]*profile{}}
	for k, p := range s.b.agents {
		q := *p
		q.tools, q.from, q.prev = maps(p.tools), maps(p.from), map[string]string{}
		q.next = map[string]map[string]int{}
		for f, m := range p.next {
			q.next[f] = maps(m)
		}
		b.agents[k] = &q
	}
	return &sim{r: s.r, b: b, now: s.now.Add(time.Hour), n: s.n}
}

func maps[M ~map[K]V, K comparable, V any](m M) M {
	out := make(M, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestBehaviorWarmup(t *testing.T) {
	b := &Behavior{}
	now := time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)
	for i := range DefaultBehavior.Warmup {
		if an := b.Observe("new-agent", "s", fmt.Sprint("tool-", i), now.Add(time.Duration(i)*time.Minute)); an != nil {
			t.Fatalf("flagged during warm-up: %v", an)
		}
	}
	if an := b.Observe("new-agent", "s", "tool-x", now.Add(time.Hour)); !slices.Contains(an, AnomalyNewTool) {
		t.Fatalf("after warm-up: %v", an)
	}
	// Another agent's baseline is separate.
	if an := b.Observe("other", "s", "tool-x", now); an != nil {
		t.Fatalf("other agent: %v", an)
	}
}

// TestBehaviorThroughGateway: the gateway reports a call outside the agent's baseline to the PDP; the real risk
// policy floors the event at the "agent-behavior-anomaly" score, above incident.MinRisk, so the decision event
// opens an incident. The call itself is not blocked by this alone (policy rules may add that).
func TestBehaviorThroughGateway(t *testing.T) {
	e := newEnv(t)
	e.gw.Behavior = &Behavior{Config: BehaviorConfig{Warmup: 10, MinFrom: 5, SpikeFactor: 5, SpikeFloor: 20}}
	e.tools.reset(map[string]string{"read_inbox": "inbox", "get_transactions": "tx", "web_fetch": "page"}, false)
	for i := range 8 {
		for _, tool := range []string{"read_inbox", "get_transactions"} {
			e.now = e.now.Add(20 * time.Second)
			if _, isErr, rpcErr := e.tool(e.token(nil), "", tool, nil); isErr || rpcErr != nil {
				t.Fatalf("warm-up %d %s: %v", i, tool, rpcErr)
			}
			if ev := e.events.last("tool_call"); len(ev.BehaviorAnomalies) != 0 {
				t.Fatalf("warm-up flagged: %+v", ev.BehaviorAnomalies)
			}
		}
	}
	e.now = e.now.Add(20 * time.Second)
	if _, isErr, rpcErr := e.tool(e.token(nil), "", "web_fetch", map[string]any{"url": "https://example.com"}); isErr || rpcErr != nil {
		t.Fatalf("web_fetch: %v", rpcErr)
	}
	ev := e.events.last("tool_call")
	if !slices.Contains(ev.BehaviorAnomalies, AnomalyNewTool) || !slices.Contains(ev.RiskOverrides, "agent-behavior-anomaly") ||
		ev.RiskScore < 60 || ev.RiskScore < incident.MinRisk {
		t.Fatalf("anomalous call event: anomalies %v, overrides %v, risk %d", ev.BehaviorAnomalies, ev.RiskOverrides, ev.RiskScore)
	}
	// Replayed through policy simulation, the event carries the same signal.
	in, _ := ev.PDPInput()
	if a, _ := in["agent"].(map[string]any); !slices.Equal(a["behavior_anomalies"].([]string), ev.BehaviorAnomalies) {
		t.Fatalf("replay input: %+v", a)
	}
}
