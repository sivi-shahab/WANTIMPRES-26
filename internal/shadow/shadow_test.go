package shadow

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"wantimpres26/internal/catalog"
)

func TestParsers(t *testing.T) {
	ts := time.Date(2026, 10, 5, 8, 0, 1, 0, time.UTC)
	cases := []struct {
		name string
		p    Parser
		line string
		want Record
		ok   bool
		err  bool
	}{
		{"squid CONNECT", Squid, "1791187201.123    120 10.0.0.5 TCP_TUNNEL/200 3946 CONNECT api.openai.com:443 alice HIER_DIRECT/1.2.3.4 -",
			Record{Time: ts, User: "alice", Client: "10.0.0.5", Host: "api.openai.com", Method: "CONNECT"}, true, false},
		{"squid bumped URL, no user, syslog prefix", Squid, "Oct  5 08:00:01 px1 squid[42]: 1791187201.5 80 10.0.0.9 TCP_MISS/200 512 POST https://api.anthropic.com/v1/messages - HIER_DIRECT/1.2.3.4 application/json",
			Record{Time: ts, User: "10.0.0.9", Client: "10.0.0.9", Host: "api.anthropic.com", Method: "POST", Path: "/v1/messages"}, true, false},
		{"squid comment", Squid, "# rotated", Record{}, false, false},
		{"squid garbage", Squid, "not a log line", Record{}, false, true},
		{"bind", DNS, "05-Oct-2026 08:00:01.123 queries: info: client @0x7f3a 10.0.0.5#53211 (chatgpt.com): query: chatgpt.com IN A +E(0)K (10.0.0.1)",
			Record{Time: ts, User: "10.0.0.5", Client: "10.0.0.5", Host: "chatgpt.com"}, true, false},
		{"bind behind RFC 5424 syslog", DNS, "<30>1 2026-10-05T08:00:01Z ns1 named 77 - - client 10.0.0.6#5300 (claude.ai.): query: claude.ai. IN AAAA +",
			Record{Time: ts, User: "10.0.0.6", Client: "10.0.0.6", Host: "claude.ai"}, true, false},
		{"bind other message", DNS, "05-Oct-2026 08:00:01.123 general: info: zone loaded", Record{}, false, false},
		{"bind without a year", DNS, "Oct  5 08:00:01 ns1 named[77]: client 10.0.0.6#5300 (claude.ai): query: claude.ai IN A +", Record{}, false, true},
		{"jsonl mapped, epoch ms", JSONL(JSONFields{Time: "ts", User: "login", Host: "hostname", URL: "url", Method: "method", UserAgent: "ua"}),
			`{"ts": 1791187201000, "login": "Bob@bank.co.id", "url": "https://gemini.google.com/app", "method": "GET", "ua": "Mozilla"}`,
			Record{Time: ts, User: "Bob@bank.co.id", Host: "gemini.google.com", Method: "GET", Path: "/app", UserAgent: "Mozilla"}, true, false},
		{"jsonl RFC 3339", JSONL(DefaultJSONFields), `{"time": "2026-10-05T15:00:01+07:00", "user": "c", "host": "poe.com"}`,
			Record{Time: ts, User: "c", Host: "poe.com"}, true, false},
		{"jsonl no host", JSONL(DefaultJSONFields), `{"time": "2026-10-05T08:00:01Z", "user": "c"}`, Record{}, false, true},
	}
	for _, c := range cases {
		r, ok, err := c.p(c.line)
		if ok != c.ok || (err != nil) != c.err || r != c.want {
			t.Errorf("%s: got %+v ok=%v err=%v", c.name, r, ok, err)
		}
	}
	if f, err := ParseJSONFields("time=ts, user=login"); err != nil || f.Time != "ts" || f.User != "login" || f.Host != "host" {
		t.Errorf("field mapping: %+v %v", f, err)
	}
	if _, err := ParseJSONFields("when=ts"); err == nil {
		t.Error("unknown field name accepted")
	}
}

var pepper = []byte("0123456789abcdef-test-pepper")

// TestBaseline35Days is the ticket's report check on synthetic logs: 35 days of a proxy log with ten users in two
// units, catalogued apps, an uncatalogued AI-looking host, an OpenAI-compatible endpoint on an unknown host, and
// ordinary traffic. Nobody's name or IP may reach the report.
func TestBaseline35Days(t *testing.T) {
	units := map[string]string{}
	var users []string
	for i := range 10 {
		u := fmt.Sprintf("user%02d", i)
		users = append(users, u)
		if i < 6 {
			units[u] = "Treasury"
		} else {
			units[u] = "IT"
		}
	}
	b, err := NewBaseline(catalog.SeedApps(), pepper, units)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	line := func(at time.Time, client, user, method, url string) string {
		return fmt.Sprintf("%d.000 100 %s TCP_TUNNEL/200 100 %s %s %s HIER_DIRECT/1.2.3.4 -", at.Unix(), client, method, url, user)
	}
	for day := range 35 {
		at := start.AddDate(0, 0, day).Add(9 * time.Hour)
		for i, u := range users {
			b.Line(Squid, line(at, fmt.Sprintf("10.1.0.%d", i), u, "CONNECT", "chatgpt.com:443"))
			b.Line(Squid, line(at, "10.1.0.1", u, "CONNECT", "intranet.bank.co.id:443"))
			if i >= 6 { // IT also uses DeepSeek and Copilot
				b.Line(Squid, line(at, "10.1.0.1", u, "CONNECT", "chat.deepseek.com:443"))
				b.Line(Squid, line(at, "10.1.0.1", u, "CONNECT", "api.githubcopilot.com:443"))
			}
		}
		if day%7 == 0 {
			b.Line(Squid, line(at, "10.1.0.77", "-", "CONNECT", "newbrainy.ai:443"))
			b.Line(Squid, line(at, "10.1.0.78", "user03", "POST", "https://llm-proxy.example.net/v1/chat/completions"))
		}
	}
	b.Line(Squid, "garbage")
	r := b.Report(start.AddDate(0, 0, 40), 5)

	if r.DaysCovered != 35 || !r.MeetsMinDays || r.From != "2026-09-01" || r.To != "2026-10-05" || r.Unparsed != 1 {
		t.Errorf("coverage: %+v", r)
	}
	if ids := appIDs(r.Apps); !slices.Equal(ids, []string{"chatgpt", "deepseek", "github-copilot"}) {
		t.Errorf("apps %v", ids)
	}
	if a := r.Apps[0]; a.Users != 10 || a.Requests != 350 || a.ActiveDays != 35 || a.Category != "chat" {
		t.Errorf("chatgpt row %+v", a)
	}
	if r.AIUsers != 10 || len(r.Users) != 5 || r.Users[0].Unit != "IT" || len(r.Users[0].User) != 64 {
		t.Errorf("users %+v", r.Users)
	}
	if len(r.Units) != 2 || r.Units[0].Unit != "Treasury" || r.Units[0].Users != 6 || r.Units[1].TopApps[0] != "chatgpt" {
		t.Errorf("units %+v", r.Units)
	}
	if len(r.Weeks) != 6 || r.Weeks[0].Week != "2026-W36" {
		t.Errorf("weeks %+v", r.Weeks)
	}
	if len(r.Review) != 2 || r.ReviewRequests != 10 {
		t.Fatalf("review %+v", r.Review)
	}
	for _, v := range r.Review {
		switch v.Host {
		case "newbrainy.ai":
			if v.Confidence != WeightNameHeuristic || v.Requests != 5 {
				t.Errorf("heuristic row %+v", v)
			}
		case "llm-proxy.example.net":
			if v.Confidence != catalog.WeightAPI || !slices.Contains(v.Candidates, "chatgpt") || !slices.Contains(v.Candidates, "deepseek") {
				t.Errorf("ambiguous row %+v", v)
			}
		default:
			t.Errorf("unexpected review row %+v", v)
		}
	}

	js, _ := json.Marshal(r)
	var md bytes.Buffer
	if err := r.Markdown(&md); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{string(js), md.String()} {
		for _, s := range append(slices.Clone(users), "10.1.0.") {
			if strings.Contains(out, s) {
				t.Errorf("identity %q in the report", s)
			}
		}
	}
	if !strings.Contains(md.String(), "| ChatGPT / OpenAI API (`chatgpt`) | chat | 10 | 350 | 35 |") {
		t.Errorf("markdown:\n%s", md.String())
	}

	// A week of logs is reported, flagged as short.
	short, _ := NewBaseline(catalog.SeedApps(), pepper, nil)
	for day := range 7 {
		short.Line(Squid, line(start.AddDate(0, 0, day), "10.0.0.1", "x", "CONNECT", "claude.ai:443"))
	}
	if r := short.Report(start, 5); r.MeetsMinDays || r.DaysCovered != 7 || r.Units[0].Unit != "unknown" {
		t.Errorf("short baseline %+v", r)
	}
	md.Reset()
	_ = short.Report(start, 5).Markdown(&md)
	if !strings.Contains(md.String(), "belum memenuhi syarat") {
		t.Error("short baseline not flagged in markdown")
	}

	if _, err := NewBaseline(nil, []byte("short"), nil); err == nil {
		t.Error("short pepper accepted")
	}
}

func appIDs(rows []AppRow) (ids []string) {
	for _, a := range rows {
		ids = append(ids, a.ID)
	}
	return ids
}

// TestSeedCatalog: the ~200-app seed has unique ids and domains (one host never counts for two apps), and the
// regional cloud endpoints resolve.
func TestSeedCatalog(t *testing.T) {
	apps := catalog.SeedApps()
	if len(apps) < 190 {
		t.Errorf("seed has %d apps", len(apps))
	}
	owner := map[string]string{}
	for _, a := range apps {
		for _, d := range a.Domains {
			if o, dup := owner[d]; dup {
				t.Errorf("domain %s in %s and %s", d, o, a.ID)
			}
			owner[d] = a.ID
		}
	}
	for host, want := range map[string]string{
		"api.groq.com": "groq", "asia-southeast2-aiplatform.googleapis.com": "vertex-ai",
		"bedrock-runtime.ap-southeast-3.amazonaws.com": "aws-bedrock", "mybank.openai.azure.com": "azure-openai",
		"app.fireflies.ai": "fireflies", "www.notion.so": "", "s3.ap-southeast-3.amazonaws.com": "",
	} {
		d, _ := catalog.Match(apps, catalog.Signals{Host: host})
		if d.AppID != want {
			t.Errorf("%s → %q, want %q", host, d.AppID, want)
		}
	}
}

// Ticket 43: a server reaching an AI provider's API domain without the gateway is a finding; the gateway itself,
// workstations (users, via the SWG: shadow AI, not bypass), other hosts and non-API apps are not.
func TestGatewayBypass(t *testing.T) {
	b, err := NewBaseline(catalog.SeedApps(), pepper, nil)
	if err != nil {
		t.Fatal(err)
	}
	b.WatchBypass([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("fd00:20::/32")}, []netip.Addr{netip.MustParseAddr("10.20.0.5")})
	sq := func(sec int, client, host string) string {
		return fmt.Sprintf("%d.000 100 %s TCP_TUNNEL/200 100 CONNECT %s:443 - HIER_DIRECT/1.2.3.4 -", 1791187200+sec, client, host)
	}
	for _, l := range []string{
		sq(0, "10.20.3.7", "api.openai.com"),  // bypass
		sq(60, "10.20.3.7", "api.openai.com"), // same pair
		sq(120, "10.20.3.7", "eu.api.openai.com"),
		sq(0, "10.20.0.5", "api.openai.com"),        // the gateway
		sq(0, "10.50.1.9", "api.openai.com"),        // a workstation
		sq(0, "10.20.3.8", "repo.maven.apache.org"), // not AI
		sq(0, "10.20.3.8", "www.midjourney.com"),    // AI, but no API in the catalog
	} {
		b.Line(Squid, l)
	}
	b.Line(DNS, "05-Oct-2026 08:00:01.123 queries: info: client @0x7f 10.20.9.1#53211 (api.anthropic.com): query: api.anthropic.com IN A +E(0)K (10.0.0.1)")
	b.Line(JSONL(DefaultJSONFields), `{"time": "2026-10-05T08:00:01Z", "client_ip": "fd00:20::15", "host": "generativelanguage.googleapis.com"}`)
	b.Line(JSONL(DefaultJSONFields), `{"time": "2026-10-05T08:00:01Z", "user": "x", "host": "api.mistral.ai"}`) // no client address: cannot tell

	r := b.Report(time.Now(), 10)
	got := map[string]int{}
	for _, f := range r.GatewayBypass {
		got[f.Server+" "+f.Domain+" "+f.AppID] = f.Requests
	}
	want := map[string]int{"10.20.3.7 api.openai.com chatgpt": 3, "10.20.9.1 api.anthropic.com claude": 1, "fd00:20::15 generativelanguage.googleapis.com gemini": 1}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("bypass %v, want %v", got, want)
	}
	if f := r.GatewayBypass[0]; f.LastSeen.Sub(f.FirstSeen) != 2*time.Minute {
		t.Errorf("first/last seen %v %v", f.FirstSeen, f.LastSeen)
	}
	var md bytes.Buffer
	_ = r.Markdown(&md)
	if !strings.Contains(md.String(), "| 10.20.3.7 | api.openai.com | chatgpt | 3 |") || strings.Contains(md.String(), "10.50.1.9") {
		t.Errorf("markdown:\n%s", md.String())
	}
	// Off by default: no subnets, no findings.
	off, _ := NewBaseline(catalog.SeedApps(), pepper, nil)
	off.Line(Squid, sq(0, "10.20.3.7", "api.openai.com"))
	if r := off.Report(time.Now(), 10); r.GatewayBypass != nil {
		t.Errorf("findings without -servers: %v", r.GatewayBypass)
	}
}
