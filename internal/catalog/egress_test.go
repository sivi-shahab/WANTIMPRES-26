package catalog

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"wantimpres26/internal/authz"
	"wantimpres26/internal/authz/authztest"
)

// Ticket 43 AC: the provider domain export, from the seed catalog.
func TestProviderDomains(t *testing.T) {
	entries := ProviderDomains(SeedApps())
	var domains []string
	for _, e := range entries {
		domains = append(domains, e.Domain)
	}
	for _, want := range []string{"api.openai.com", "chatgpt.com", "api.anthropic.com", "generativelanguage.googleapis.com", "api.deepseek.com", "dashscope.aliyuncs.com", "api.mistral.ai"} {
		if !slices.Contains(domains, want) {
			t.Errorf("missing %s", want)
		}
	}
	if !slices.IsSorted(domains) || len(slices.Compact(slices.Clone(domains))) != len(domains) {
		t.Error("not sorted and unique")
	}
	if !slices.Contains(domains, "perplexity.ai") || slices.Contains(domains, "www.perplexity.ai") {
		t.Error("a subdomain covered by its parent is listed")
	}
	// Apps without an API (image tools, meeting bots…) are the SWG's business, not this egress rule.
	for _, e := range entries {
		if e.AppID == "midjourney" {
			t.Errorf("app without API endpoints exported: %+v", e)
		}
	}
	if e, ok := ProviderFor(entries, "EU.api.openai.com."); !ok || e.AppID != "chatgpt" {
		t.Errorf("subdomain: %+v %v", e, ok)
	}
	if _, ok := ProviderFor(entries, "notapi.openai.com.evil.example"); ok {
		t.Error("suffix trick matched")
	}
}

func TestGatewayBypassAPI(t *testing.T) {
	s, _, db := setup(t)
	ctx := context.Background()
	auth, _ := authztest.New(map[string]authztest.User{"admin": authztest.Role("security_admin"), "ciso": authztest.Role("ciso")}, time.Now,
		func(context.Context, string, string, map[string]any) error { return nil })
	rt := authz.NewRouter(auth)
	Routes(rt, s, nil, time.Now)
	hs := httptest.NewServer(rt)
	defer hs.Close()
	do := func(method, path, user, body string) (int, string) {
		req, _ := http.NewRequest(method, hs.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+user)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	code, txt := do("GET", "/catalog/egress?format=txt", "admin", "")
	lines := strings.Split(strings.TrimSpace(txt), "\n")
	if code != 200 || !slices.Contains(lines, "api.anthropic.com") || slices.Contains(lines, "www.perplexity.ai") || strings.Contains(txt, "midjourney") {
		t.Errorf("egress txt: %d %s", code, txt)
	}
	if code, body := do("GET", "/catalog/egress", "admin", ""); code != 200 || !strings.Contains(body, `"domain":"api.openai.com","app_id":"chatgpt"`) {
		t.Errorf("egress json: %d %s", code, body)
	}
	if code, _ := do("GET", "/catalog/egress", "ciso", ""); code != 403 {
		t.Errorf("ciso (no config.read): %d", code)
	}

	report := `{"gateway_bypass": [{"server": "10.20.3.7", "domain": "api.openai.com", "app_id": "chatgpt", "requests": 3,
		"first_seen": "2026-10-05T08:00:00Z", "last_seen": "2026-10-05T08:02:00Z"}]}`
	if code, body := do("POST", "/catalog/gateway-bypass", "admin", report); code != 200 || !strings.Contains(body, `"new":1`) {
		t.Fatalf("report: %d %s", code, body)
	}
	// The same pair again merges: no new audit event.
	if code, body := do("POST", "/catalog/gateway-bypass", "admin", report); code != 200 || !strings.Contains(body, `"new":0`) {
		t.Errorf("again: %d %s", code, body)
	}
	if code, _ := do("POST", "/catalog/gateway-bypass", "admin", `{"gateway_bypass": [{"server": "alice", "domain": "x", "requests": 1}]}`); code != 400 {
		t.Errorf("not an IP: %d", code)
	}
	bs, err := s.Bypasses(ctx, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || len(bs) != 1 || bs[0].Requests != 6 || bs[0].ReportedBy != "admin" {
		t.Errorf("stored: %+v %v", bs, err)
	}
	if n := strings.Count(auditActions(t, db), ":catalog.gateway_bypass:"); n != 1 {
		t.Errorf("%d bypass audit events, want 1", n)
	}
}
