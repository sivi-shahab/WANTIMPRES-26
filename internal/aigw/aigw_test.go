package aigw

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"wantimpres26/internal/events"
	"wantimpres26/internal/mcpgw"
	"wantimpres26/internal/policysvc"
	"wantimpres26/policy"
)

// --- fakes ---

// upstream is a fake provider: it records what reached it and answers with a canned body.
type upstream struct {
	mu     sync.Mutex
	got    []*http.Request
	bodies [][]byte
	reply  []byte
	sse    []byte // answer to streaming requests
	status int
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.got, u.bodies = append(u.got, r), append(u.bodies, b)
	reply, status := u.reply, u.status
	stream := bytes.Contains(b, []byte(`"stream":true`)) || strings.Contains(r.URL.Path, "streamGenerateContent")
	if stream {
		reply = u.sse
	}
	u.mu.Unlock()
	w.Header().Set("Content-Type", map[bool]string{true: "text/event-stream", false: "application/json"}[stream])
	w.Header().Set("X-Request-Id", "req_upstream_1")
	w.Header().Set("Set-Cookie", "upstream=secret")
	if status == 0 {
		status = 200
	}
	w.WriteHeader(status)
	_, _ = w.Write(reply)
}

func (u *upstream) last(t *testing.T) (*http.Request, map[string]any) {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.got) == 0 {
		t.Fatal("nothing reached the provider")
	}
	var m map[string]any
	if err := json.Unmarshal(u.bodies[len(u.bodies)-1], &m); err != nil {
		t.Fatalf("provider got invalid JSON: %v", err)
	}
	return u.got[len(u.got)-1], m
}

func (u *upstream) calls() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.got)
}

type sink struct {
	mu     sync.Mutex
	schema *jsonschema.Schema
	evs    []events.Event
}

func (s *sink) emit(_ context.Context, e events.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := events.Marshal(e, s.schema); err != nil {
		panic(err) // a PEP must never produce an event the pipeline rejects
	}
	s.evs = append(s.evs, e)
	return nil
}

func (s *sink) all() []events.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.evs)
}

// --- environment ---

type env struct {
	t      *testing.T
	gw     *Gateway
	srv    *httptest.Server
	ups    map[string]*upstream
	events *sink
	pdpUp  bool
	now    time.Time
}

const (
	keyChat    = "gw-key-chat-0123456789"
	keyStrict  = "gw-key-strict-0123456789"
	keyLimited = "gw-key-limited-0123456789"
	keyCanary  = "gw-key-canary-0123456789"
)

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func newEnv(t *testing.T, extraRules ...map[string]any) *env {
	t.Helper()
	e := &env{t: t, ups: map[string]*upstream{}, pdpUp: true, now: time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)}
	schema, err := events.Compile(events.SchemaV1)
	if err != nil {
		t.Fatal(err)
	}
	e.events = &sink{schema: schema}
	// The real policy, with the catalog placing the public providers offshore (sanctioned) as a release would.
	catalog := map[string]any{"version": 1, "apps": map[string]any{
		"chatgpt": map[string]any{"sanction": "sanctioned", "region": "US"},
		"claude":  map[string]any{"sanction": "sanctioned", "region": "US"},
		"gemini":  map[string]any{"sanction": "sanctioned", "region": "US"},
	}}
	overrides := policysvc.Overrides{"wantimpres26.catalog": catalog}
	if len(extraRules) > 0 { // a bank's own rules, published on top of the templates
		raw, err := fs.ReadFile(policy.Files, "wantimpres26/rules/data.json")
		if err != nil {
			t.Fatal(err)
		}
		var rules map[string]any
		_ = json.Unmarshal(raw, &rules)
		for _, r := range extraRules {
			rules["items"] = append(rules["items"].([]any), r)
		}
		overrides["wantimpres26.rules"] = rules
	}
	pq, err := policysvc.Query(context.Background(), policy.Files, overrides, "data.wantimpres26.decision.result")
	if err != nil {
		t.Fatal(err)
	}
	decide := func(ctx context.Context, input map[string]any) (mcpgw.Decision, error) {
		if !e.pdpUp {
			return mcpgw.Decision{}, errors.New("PDP: connection refused")
		}
		rs, err := pq.Eval(ctx, rego.EvalInput(input))
		if err != nil || len(rs) != 1 {
			return mcpgw.Decision{}, fmt.Errorf("PDP: %v", err)
		}
		b, _ := json.Marshal(rs[0].Expressions[0].Value)
		var d mcpgw.Decision
		return d, json.Unmarshal(b, &d)
	}
	dir := t.TempDir()
	providers := map[string]Provider{}
	for _, p := range []Provider{
		{Name: "openai", Kind: KindOpenAI, AppID: "chatgpt", Sanction: "unsanctioned", Region: "unknown"},
		{Name: "anthropic", Kind: KindAnthropic, AppID: "claude", Sanction: "unsanctioned", Region: "unknown"},
		{Name: "gemini", Kind: KindGemini, AppID: "gemini", Sanction: "unsanctioned", Region: "unknown"},
		{Name: "vllm", Kind: KindOpenAI, AppID: "llm-internal", Sanction: "sanctioned", Region: "ID"},
	} {
		u := &upstream{}
		e.ups[p.Name] = u
		s := httptest.NewServer(u)
		t.Cleanup(s.Close)
		p.Upstream, p.KeyFile, p.Auth = s.URL+"/base", filepath.Join(dir, p.Name+".key"), defaultAuth(p.Kind)
		if err := os.WriteFile(p.KeyFile, []byte("sk-provider-"+p.Name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		providers[p.Name] = p
	}
	all := []string{"openai", "anthropic", "gemini", "vllm"}
	e.gw = &Gateway{
		Apps: []App{
			{ID: "chat-assistant", KeySHA256: sha(keyChat), Providers: all, FailMode: FailOpen},
			{ID: "credit-scoring", KeySHA256: sha(keyStrict), Providers: []string{"openai", "vllm"}, FailMode: FailClosed},
			{ID: "limited", KeySHA256: sha(keyLimited), Providers: all, FailMode: FailClosed, RPM: 3, UserRPM: 2, TokensPerDay: 200},
			{ID: "canary-app", KeySHA256: sha(keyCanary), Providers: all, FailMode: FailClosed, Canary: true},
		},
		Providers: providers, Decide: decide, Emit: e.events.emit, Key: (&KeyFiles{}).Key,
		Count: MemoryCounter(func() time.Time { return e.now }), Upstream: http.DefaultClient,
		Pepper: []byte("test-pepper-0123456789"), TenantID: "6f1c1d1e-2a7b-4c3d-9e8f-0a1b2c3d4e5f",
		Now: func() time.Time { return e.now }, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	mux := http.NewServeMux()
	e.gw.Routes(mux)
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

type result struct {
	status int
	header http.Header
	body   map[string]any
	raw    []byte
}

// do calls the gateway as an app SDK would: key in the provider's usual header.
func (e *env) do(provider, path, key string, body any, hdr ...string) result {
	e.t.Helper()
	b, _ := json.Marshal(body)
	if s, ok := body.(string); ok {
		b = []byte(s)
	}
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/"+provider+"/"+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	switch provider {
	case "anthropic":
		req.Header.Set("x-api-key", key)
		req.Header.Set("anthropic-version", "2023-06-01")
	case "gemini":
		req.Header.Set("x-goog-api-key", key)
	default:
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("Cookie", "session=app-cookie")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	r := result{status: resp.StatusCode, header: resp.Header}
	r.raw, _ = io.ReadAll(resp.Body)
	_ = json.Unmarshal(r.raw, &r.body)
	return r
}

func golden(t *testing.T, name string) (req, resp []byte) {
	t.Helper()
	req, err := os.ReadFile(filepath.Join("testdata", name+".req.json"))
	if err == nil {
		resp, err = os.ReadFile(filepath.Join("testdata", name+".resp.json"))
	}
	if err != nil {
		t.Fatal(err)
	}
	return req, resp
}

func jsonEqual(a, b []byte) bool {
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && reflect.DeepEqual(x, y)
}

// --- contract ---

// TestContract: a clean golden request per provider API reaches the provider unchanged, with the provider key from
// the vault file in the provider's header and nothing of the app's credentials or cookies; the golden response
// comes back unchanged with the decision headers, and both directions are recorded (ticket 13 AC: contract tests).
func TestContract(t *testing.T) {
	e := newEnv(t)
	for _, c := range []struct {
		golden, provider, path, authHeader, authValue string
		directions                                    []string
	}{
		{"openai-chat", "openai", "v1/chat/completions", "Authorization", "Bearer sk-provider-openai", []string{"request", "response"}},
		{"openai-responses", "openai", "v1/responses", "Authorization", "Bearer sk-provider-openai", []string{"request", "response"}},
		{"openai-embeddings", "openai", "v1/embeddings", "Authorization", "Bearer sk-provider-openai", []string{"request"}},
		{"openai-chat", "vllm", "v1/chat/completions", "Authorization", "Bearer sk-provider-vllm", []string{"request", "response"}},
		{"anthropic-messages", "anthropic", "v1/messages", "X-Api-Key", "sk-provider-anthropic", []string{"request", "response"}},
		{"gemini-generate", "gemini", "v1beta/models/gemini-2.5-flash:generateContent", "X-Goog-Api-Key", "sk-provider-gemini", []string{"request", "response"}},
	} {
		t.Run(c.golden+"/"+c.provider, func(t *testing.T) {
			req, resp := golden(t, c.golden)
			u := e.ups[c.provider]
			u.reply = resp
			before := len(e.events.all())
			r := e.do(c.provider, c.path, keyChat, string(req), "traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
			if r.status != 200 || !jsonEqual(r.raw, resp) {
				t.Fatalf("status %d body %s", r.status, r.raw)
			}
			got, body := u.last(t)
			if b, _ := json.Marshal(body); !jsonEqual(b, req) {
				t.Errorf("provider got %s", b)
			}
			if got.URL.Path != "/base/"+c.path || got.Header.Get(c.authHeader) != c.authValue {
				t.Errorf("provider request %s %v", got.URL.Path, got.Header)
			}
			for _, h := range []string{"Cookie", "X-Goog-Api-Key", "X-Api-Key", "Authorization"} {
				if v := got.Header.Get(h); v != "" && h != c.authHeader {
					t.Errorf("header %s forwarded: %q", h, v)
				}
			}
			if c.provider == "anthropic" && got.Header.Get("Anthropic-Version") != "2023-06-01" {
				t.Error("anthropic-version not forwarded")
			}
			if r.header.Get("X-Wantimpres26-Action") != "allow" || r.header.Get("X-Wantimpres26-Decision-Id") == "" || r.header.Get("X-Request-Id") != "req_upstream_1" || r.header.Get("Set-Cookie") != "" {
				t.Errorf("response headers %v", r.header)
			}
			evs := e.events.all()[before:]
			var dirs []string
			for _, ev := range evs {
				dirs = append(dirs, ev.Direction)
				if ev.Channel != "ai_gateway" || ev.SourceApp != "chat-assistant" || ev.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || ev.Action != "allow" {
					t.Errorf("event %+v", ev)
				}
			}
			if !slices.Equal(dirs, c.directions) {
				t.Errorf("event directions %v", dirs)
			}
		})
	}
}

// TestBlockInProviderFormat: a block is HTTP 403 in each provider's own error format with the decision headers,
// and nothing reaches the provider (ticket 13 AC: SDKs do not crash on a block).
func TestBlockInProviderFormat(t *testing.T) {
	e := newEnv(t)
	secret := "deploy with aws_access_key_id=AKIAIOSFODNN7EXAMPLE and aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY please"
	for _, c := range []struct {
		provider, path string
		body           any
		check          func(map[string]any) bool
	}{
		{"openai", "v1/chat/completions", map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": secret}}},
			func(b map[string]any) bool {
				er, _ := b["error"].(map[string]any)
				return er["type"] == "wantimpres26_policy_violation" && er["code"] == "wantimpres26_policy_block" && strings.Contains(er["message"].(string), "SECRET")
			}},
		{"anthropic", "v1/messages", map[string]any{"model": "m", "max_tokens": 10, "messages": []any{map[string]any{"role": "user", "content": secret}}},
			func(b map[string]any) bool {
				er, _ := b["error"].(map[string]any)
				return b["type"] == "error" && er["type"] == "permission_error"
			}},
		{"gemini", "v1beta/models/g:generateContent", map[string]any{"contents": []any{map[string]any{"parts": []any{map[string]any{"text": secret}}}}},
			func(b map[string]any) bool {
				er, _ := b["error"].(map[string]any)
				return er["status"] == "PERMISSION_DENIED" && er["code"] == float64(403)
			}},
	} {
		r := e.do(c.provider, c.path, keyChat, c.body)
		if r.status != 403 || !c.check(r.body) || r.header.Get("X-Wantimpres26-Action") != "block" || r.header.Get("X-Wantimpres26-Decision-Id") == "" {
			t.Errorf("%s: %d %s %v", c.provider, r.status, r.raw, r.header)
		}
		if strings.Contains(string(r.raw), "AKIA") {
			t.Errorf("%s: refusal echoes the secret", c.provider)
		}
		if e.ups[c.provider].calls() != 0 {
			t.Errorf("%s: blocked request reached the provider", c.provider)
		}
	}
}

// TestResidency is ADR-0001 on this channel (ticket 13 AC): restricted content to an offshore provider is blocked;
// confidential content is redacted before it leaves, with the request still valid; an onshore sanctioned model gets
// confidential content as it is.
func TestResidency(t *testing.T) {
	e := newEnv(t)
	var niks []string
	for i := range 12 {
		niks = append(niks, fmt.Sprintf("NIK 3171012310900%03d", i+1))
	}
	restricted := "Daftar debitur: " + strings.Join(niks, ", ")
	r := e.do("openai", "v1/chat/completions", keyChat, map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": restricted}}})
	if r.status != 403 || !strings.Contains(r.body["error"].(map[string]any)["message"].(string), "RESIDENCY_RESTRICTED_OFFSHORE") {
		t.Fatalf("restricted offshore: %d %s", r.status, r.raw)
	}

	_, resp := golden(t, "openai-chat")
	e.ups["openai"].reply = resp
	confidential := "Tolong rangkum: nasabah Budi, NIK 3171012310900001, HP 0812-3456-7890, minta restrukturisasi."
	body := map[string]any{"model": "m", "messages": []any{
		map[string]any{"role": "system", "content": "You are helpful."},
		map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": confidential}}},
	}}
	r = e.do("openai", "v1/chat/completions", keyChat, body)
	if r.status != 200 || r.header.Get("X-Wantimpres26-Action") != "redact" {
		t.Fatalf("confidential offshore: %d %s", r.status, r.raw)
	}
	_, got := e.ups["openai"].last(t)
	msgs := got["messages"].([]any)
	text := msgs[1].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if len(msgs) != 2 || strings.Contains(text, "3171012310900001") || strings.Contains(text, "3456") ||
		!strings.Contains(text, "[REDACTED:PII_ID.NIK]") || !strings.HasPrefix(text, "Tolong rangkum: nasabah Budi") {
		t.Errorf("redacted request: %v", got)
	}

	e.ups["vllm"].reply = resp
	r = e.do("vllm", "v1/chat/completions", keyChat, map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": confidential}}})
	_, got = e.ups["vllm"].last(t)
	if r.status != 200 || r.header.Get("X-Wantimpres26-Action") != "allow" || !strings.Contains(fmt.Sprint(got["messages"]), "3171012310900001") {
		t.Errorf("onshore: %d %v", r.status, got)
	}
}

// TestResponseInspected: card numbers in a model's answer are redacted before the app sees them (FR-POL-8).
func TestResponseInspected(t *testing.T) {
	e := newEnv(t)
	e.ups["anthropic"].reply = []byte(`{"id":"msg_2","type":"message","role":"assistant","content":[{"type":"text","text":"Kartu yang terdaftar: 4111 1111 1111 1111."}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":9}}`)
	r := e.do("anthropic", "v1/messages", keyChat, map[string]any{"model": "m", "max_tokens": 50, "messages": []any{map[string]any{"role": "user", "content": "Kartu apa yang terdaftar?"}}})
	text := r.body["content"].([]any)[0].(map[string]any)["text"].(string)
	if r.status != 200 || strings.Contains(text, "4111") || !strings.Contains(text, "[REDACTED:PCI.PAN]") || r.header.Get("X-Wantimpres26-Action") != "redact" || r.body["type"] != "message" {
		t.Errorf("%d %s", r.status, r.raw)
	}
}

// TestFailMode is the chaos case (ticket 13 AC): with the PDP down, a fail_closed app is refused (503, provider
// format) without reaching the provider; a fail_open app is forwarded, recorded, and counted in fail_open_total.
// Detection L1 runs in-process, so it cannot be down apart from the gateway itself.
func TestFailMode(t *testing.T) {
	e := newEnv(t)
	e.pdpUp = false
	_, resp := golden(t, "openai-chat")
	e.ups["openai"].reply = resp
	chat := map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": "hello"}}}

	r := e.do("openai", "v1/chat/completions", keyStrict, chat)
	if r.status != 503 || r.header.Get("X-Wantimpres26-Action") != "block" || r.body["error"].(map[string]any)["type"] != "server_error" || e.ups["openai"].calls() != 0 {
		t.Fatalf("fail closed: %d %s", r.status, r.raw)
	}
	r = e.do("openai", "v1/chat/completions", keyChat, chat)
	if r.status != 200 || e.ups["openai"].calls() != 1 {
		t.Fatalf("fail open: %d %s", r.status, r.raw)
	}
	var reasons []string
	for _, ev := range e.events.all() {
		reasons = append(reasons, ev.SourceApp+":"+ev.Direction+":"+ev.Action+":"+strings.Join(ev.ReasonCodes, ","))
	}
	want := []string{"credit-scoring:request:block:FAIL_CLOSED", "chat-assistant:request:allow:FAIL_OPEN", "chat-assistant:response:allow:FAIL_OPEN"}
	if !slices.Equal(reasons, want) {
		t.Errorf("events %v", reasons)
	}
	m := httptest.NewRecorder()
	e.gw.serveMetrics(m, nil)
	if !strings.Contains(m.Body.String(), `aigw_fail_open_total{app="chat-assistant"} 2`) || !strings.Contains(m.Body.String(), `aigw_fail_closed_total{app="credit-scoring"} 1`) {
		t.Errorf("metrics:\n%s", m.Body.String())
	}
}

// TestLimits: requests per minute per app and per user, and the daily token quota from provider-reported usage
// (FR-PSEC-9).
func TestLimits(t *testing.T) {
	e := newEnv(t)
	_, resp := golden(t, "openai-chat") // reports 59 tokens
	e.ups["openai"].reply = resp
	chat := map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": "hello"}}}
	codes := func(users ...string) (out []int) {
		for _, u := range users {
			out = append(out, e.do("openai", "v1/chat/completions", keyLimited, chat, UserHeader, u).status)
		}
		return out
	}
	// Refused requests count too: ana's third is over her 2 per minute, budi's first is the app's fourth.
	if got := codes("ana", "ana", "ana", "budi"); !slices.Equal(got, []int{200, 200, 429, 429}) {
		t.Errorf("rate limits: %v", got)
	}
	e.now = e.now.Add(time.Minute)
	// Two calls billed 2 x 59 = 118 of 200 tokens; two more reach 236, so the next is refused on the quota.
	if got := codes("cici", "dedi"); !slices.Equal(got, []int{200, 200}) {
		t.Errorf("within quota: %v", got)
	}
	r := e.do("openai", "v1/chat/completions", keyLimited, chat, UserHeader, "eka")
	if r.status != 429 || r.body["error"].(map[string]any)["code"] != "token_quota_exceeded" {
		t.Errorf("quota refusal %d %s", r.status, r.raw)
	}
	e.now = e.now.Add(24 * time.Hour)
	if got := codes("ana"); got[0] != 200 {
		t.Errorf("next day: %v", got)
	}
}

// TestRefusals: authentication, provider allow-list, unknown API, streaming (ticket 14), and the Gemini ?key=
// never reaching the provider.
func TestRefusals(t *testing.T) {
	e := newEnv(t)
	chat := map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": "hi"}}}
	for name, c := range map[string]struct {
		provider, path, key string
		body                any
		status              int
		code                string
	}{
		"no key":           {"openai", "v1/chat/completions", "", chat, 401, "invalid_gateway_key"},
		"wrong key":        {"openai", "v1/chat/completions", "sk-real-openai-key", chat, 401, "invalid_gateway_key"},
		"provider denied":  {"anthropic", "v1/messages", keyStrict, chat, 403, "provider_not_allowed"},
		"unknown API":      {"openai", "v1/files", keyChat, chat, 404, "unsupported_endpoint"},
		"stream responses": {"openai", "v1/responses", keyChat, map[string]any{"model": "m", "stream": true, "input": "hi"}, 400, "streaming_unavailable"},
		"gemini not sse":   {"gemini", "v1beta/models/g:streamGenerateContent", keyChat, map[string]any{"contents": []any{}}, 400, ""},
		"not JSON":         {"openai", "v1/chat/completions", keyChat, "not json", 400, "invalid_json"},
	} {
		r := e.do(c.provider, c.path, c.key, c.body)
		code, _ := r.body["error"].(map[string]any)["code"].(string)
		if c.provider == "anthropic" {
			code = map[int]string{403: "provider_not_allowed"}[r.status]
		}
		if r.status != c.status || code != c.code {
			t.Errorf("%s: %d %s", name, r.status, r.raw)
		}
	}
	_, resp := golden(t, "gemini-generate")
	e.ups["gemini"].reply = resp
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/gemini/v1beta/models/g:generateContent?key="+keyChat+"&alt=json",
		strings.NewReader(`{"contents":[{"parts":[{"text":"hi"}]}]}`))
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("gemini ?key=: %v %v", res, err)
	}
	got, _ := e.ups["gemini"].last(t)
	if got.URL.RawQuery != "alt=json" || got.Header.Get("X-Goog-Api-Key") != "sk-provider-gemini" {
		t.Errorf("gemini upstream %s %v", got.URL.RawQuery, got.Header)
	}
}

func TestKeyRotation(t *testing.T) {
	f := filepath.Join(t.TempDir(), "k")
	_ = os.WriteFile(f, []byte("old\n"), 0o600)
	k, p := &KeyFiles{}, Provider{KeyFile: f}
	if v, _ := k.Key(p); v != "old" {
		t.Fatal(v)
	}
	_ = os.WriteFile(f, []byte("new"), 0o600)
	_ = os.Chtimes(f, time.Now().Add(time.Minute), time.Now().Add(time.Minute))
	if v, _ := k.Key(p); v != "new" {
		t.Errorf("rotated key not picked up: %s", v)
	}
}

func TestParseConfig(t *testing.T) {
	ok := `{"apps":[{"id":"a","key_sha256":"` + sha("k") + `","providers":["p"]}],
		"providers":[{"name":"p","kind":"openai","upstream":"https://api.openai.com/","key_file":"/vault/openai","app_id":"chatgpt","sanction":"unsanctioned","region":"unknown"}]}`
	c, err := ParseConfig([]byte(ok))
	if err != nil || c.Apps[0].FailMode != FailClosed || c.Providers[0].Auth != "bearer" || c.Providers[0].Upstream != "https://api.openai.com" {
		t.Fatalf("%+v %v", c, err)
	}
	for _, bad := range []string{
		strings.Replace(ok, `"kind":"openai"`, `"kind":"cohere"`, 1),
		strings.Replace(ok, `"providers":["p"]`, `"providers":["q"]`, 1),
		strings.Replace(ok, sha("k"), "plaintext-key", 1),
		strings.Replace(ok, `"providers":["p"]`, `"providers":["p"],"fail_mode":"maybe"`, 1),
		strings.Replace(ok, `"key_file":"/vault/openai",`, ``, 1),
		strings.Replace(ok, `"id":"a"`, `"id":"a","api_key":"x"`, 1),
	} {
		if _, err := ParseConfig([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// TestOverhead measures what the gateway adds to a ~8K-token request (spec §13.1: p95 ≤ 80 ms, p99 ≤ 200 ms):
// gateway round trip minus direct round trip to the same fake provider, with the real policy evaluated.
func TestOverhead(t *testing.T) {
	if testing.Short() {
		t.Skip("load measurement")
	}
	e := newEnv(t)
	_, resp := golden(t, "openai-chat")
	e.ups["openai"].reply = resp
	var b strings.Builder
	for b.Len() < 32<<10 { // ≈ 8K tokens of ordinary prose
		b.WriteString("Kantor cabang akan menyesuaikan jam layanan selama periode libur nasional, mohon sampaikan kepada nasabah. ")
	}
	body, _ := json.Marshal(map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": b.String()}}})
	direct := func() {
		res, err := http.Post(e.gw.Providers["openai"].Upstream+"/v1/chat/completions", "application/json", bytes.NewReader(body))
		if err == nil {
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
		}
	}
	const n = 300
	var over []time.Duration
	for range n {
		t0 := time.Now()
		direct()
		d := time.Since(t0)
		t0 = time.Now()
		r := e.do("openai", "v1/chat/completions", keyChat, string(body))
		g := time.Since(t0)
		if r.status != 200 {
			t.Fatalf("%d %s", r.status, r.raw)
		}
		over = append(over, g-d)
	}
	sort.Slice(over, func(i, j int) bool { return over[i] < over[j] })
	p50, p95, p99 := over[n/2], over[n*95/100], over[n*99/100]
	t.Logf("gateway overhead, %d KB prompt, %d requests: p50 %v, p95 %v, p99 %v", len(body)>>10, n, p50, p95, p99)
	if !raceEnabled && (p95 > 80*time.Millisecond || p99 > 200*time.Millisecond) {
		t.Errorf("over budget: p95 %v p99 %v", p95, p99)
	}
}

// TestServeForSDK serves the test gateway on AIGW_SDK_ADDR for AIGW_SDK_SECONDS so the official SDKs can be run
// against it (testdata/sdk_smoke.py, ticket 13 AC). Skipped otherwise.
func TestServeForSDK(t *testing.T) {
	addr := os.Getenv("AIGW_SDK_ADDR")
	if addr == "" {
		t.Skip("AIGW_SDK_ADDR not set")
	}
	e := newEnv(t)
	_, oa := golden(t, "openai-chat")
	_, an := golden(t, "anthropic-messages")
	e.ups["openai"].reply, e.ups["anthropic"].reply = oa, an
	// Streams that leak the canary app's marker halfway: the SDKs must see a filtered end, not an error.
	canary := e.gw.canary("canary-app")
	leak := []string{strings.Repeat("Branches open at eight. ", 60), "My reference is " + canary + ".", " More text."}
	e.ups["vllm"].sse, e.ups["anthropic"].sse = sseOf(KindOpenAI, leak), sseOf(KindAnthropic, leak)
	mux := http.NewServeMux()
	e.gw.Routes(mux)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.ListenAndServe() }()
	secs, _ := time.ParseDuration(os.Getenv("AIGW_SDK_SECONDS") + "s")
	time.Sleep(secs)
	_ = srv.Close()
}
