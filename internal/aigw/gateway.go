// Package aigw is the AI gateway (ticket 13, spec §4.6, §5.4, §7.1, §8.7): internal apps call LLM providers through
// it with a gateway key, in the providers' own API formats. Each request is inspected (detection L1 over the text a
// model reads), decided by the PDP, and allowed, redacted or blocked; the response is inspected the same way before
// the app sees it. Provider keys come from vault files and never reach apps. Streaming is ticket 14.
package aigw

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"wantimpres26/internal/detect"
	"wantimpres26/internal/events"
	"wantimpres26/internal/inspect"
	"wantimpres26/internal/mcpgw"
	"wantimpres26/internal/tokvault"
)

const (
	maxRequest  = 4 << 20
	maxResponse = 16 << 20
	// UserHeader carries the end user an app acts for; it is HMAC'd before it is used or stored.
	UserHeader = "X-Wantimpres26-User"
)

// Gateway serves /<provider>/<api path>.
type Gateway struct {
	Apps      []App
	Providers map[string]Provider
	Decide    func(ctx context.Context, input map[string]any) (mcpgw.Decision, error)
	Emit      func(ctx context.Context, e events.Event) error
	Key       func(p Provider) (string, error) // provider key from the vault (KeyFiles.Key)
	Count     Counter
	Vault     *tokvault.Client // tokenize/detokenize (ticket 24); nil = tokenize redacts
	Upstream  *http.Client
	Pepper    []byte
	TenantID  string
	Now       func() time.Time
	Log       *slog.Logger
	Metrics   func(io.Writer) // more counters for /metrics (the event producer's)
	Detection *Detection      // L2 shadow report in decision events (ticket 49); nil = none

	mu      sync.Mutex
	metrics map[[2]string]int64 // {name, app} → count
}

func (g *Gateway) Routes(mux *http.ServeMux) {
	mux.Handle("/", g)
	mux.HandleFunc("GET /metrics", g.serveMetrics)
}

// call is one request in flight.
type call struct {
	g        *Gateway
	w        http.ResponseWriter
	app      *App
	p        Provider
	ep       endpoint
	user     string // HMAC of the end user, "" when the app sent none
	trace    string
	decision string // last decision id, for X-Wantimpres26-Decision-Id
	action   string // strictest action applied
	leak     leakCheck
	tokens   map[string]issued // FPE tokens put in this request, by their digits
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	p, ok := g.Providers[name]
	if !ok {
		writeJSON(w, http.StatusNotFound, errorBody(KindOpenAI, 404, "unknown_provider", "Unknown provider route."))
		return
	}
	c := &call{g: g, w: w, p: p, trace: traceID(r), action: "allow", tokens: map[string]issued{}}
	ep, ok := findEndpoint(p.Kind, r.Method, rest)
	if !ok {
		c.refuse(http.StatusNotFound, "unsupported_endpoint", "This API is not available through the WANTIMPRES-26 gateway.")
		return
	}
	c.ep = ep
	if c.app = lookup(g.Apps, appKey(r)); c.app == nil {
		c.refuse(http.StatusUnauthorized, "invalid_gateway_key", "Invalid or missing WANTIMPRES-26 gateway key.")
		return
	}
	if !slices.Contains(c.app.Providers, p.Name) {
		c.refuse(http.StatusForbidden, "provider_not_allowed", fmt.Sprintf("App %s may not use provider %s.", c.app.ID, p.Name))
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequest))
	if err != nil {
		c.refuse(http.StatusRequestEntityTooLarge, "request_too_large", "Request body too large.")
		return
	}
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		c.refuse(http.StatusBadRequest, "invalid_json", "Request body must be a JSON object.")
		return
	}
	stream := ep.alwaysStream
	if s, _ := body["stream"].(bool); s {
		stream = true
	}
	switch {
	case stream && !ep.streamable:
		c.refuse(http.StatusBadRequest, "streaming_unavailable", "Streaming is not available for this API through the WANTIMPRES-26 gateway; send the request without stream.")
		return
	case stream && p.Kind == KindGemini && r.URL.Query().Get("alt") != "sse":
		c.refuse(http.StatusBadRequest, "streaming_unavailable", "Stream with alt=sse through the WANTIMPRES-26 gateway.")
		return
	}
	if u := r.Header.Get(UserHeader); u != "" {
		c.user = g.hmac("user:" + u)
	}
	ctx := r.Context()
	if !c.withinLimits(ctx) {
		return
	}

	// Request: inspect what the model will read, decide, apply.
	in := c.content(body, ep.reqRoots)
	tokens := (len(in.Text) + 3) / 4
	if !c.withinQuota(ctx, int64(tokens)) {
		return
	}
	if !c.enforce(ctx, "request", body, ep.reqRoots, in, 0) {
		return
	}
	// FR-PSEC-5: remember the system prompt to spot it in the answer, and plant the app's canary in it.
	sys, canary := systemPrompt(body), ""
	if c.app.Canary && sys != "" {
		canary = g.canary(c.app.ID)
		addCanary(body, canary)
	}
	c.leak = newLeak(sys, canary)
	if raw, err = json.Marshal(body); err != nil {
		c.refuse(http.StatusInternalServerError, "internal_error", "Request could not be re-encoded.")
		return
	}
	resp, err := c.forward(ctx, r, rest, raw)
	if err != nil {
		g.Log.Error("upstream", "provider", p.Name, "err", err)
		c.refuse(http.StatusBadGateway, "upstream_unavailable", "The model provider could not be reached.")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if stream && resp.StatusCode/100 == 2 && strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		c.stream(ctx, resp, tokens)
		return
	}
	out, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil || len(out) > maxResponse {
		c.refuse(http.StatusBadGateway, "upstream_response_invalid", "The model provider's response could not be read.")
		return
	}

	// Response: provider errors pass through as they are; a successful body is inspected before the app sees it.
	var rb map[string]any
	if resp.StatusCode/100 == 2 && json.Unmarshal(out, &rb) == nil {
		used := usage(p.Kind, rb)
		if used == 0 {
			used = int64(tokens)
		}
		c.charge(ctx, used)
		if ep.respRoots != nil {
			rin := c.content(rb, ep.respRoots)
			if !c.enforce(ctx, "response", rb, ep.respRoots, rin, c.leak.score(rin.Text)) {
				return
			}
			if c.app.Detokenize && len(c.tokens) > 0 {
				back := c.content(rb, ep.respRoots)
				back.Replace(c.detokenizer(ctx, back.Text))
				for _, k := range ep.respRoots {
					if v, ok := back.sub[k]; ok {
						rb[k] = v
					}
				}
			}
			if out, err = json.Marshal(rb); err != nil {
				c.refuse(http.StatusInternalServerError, "internal_error", "Response could not be re-encoded.")
				return
			}
		}
	}
	for k, vs := range resp.Header {
		if forwardResponseHeader(k) {
			w.Header()[k] = vs
		}
	}
	c.headers()
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(out)
}

// content collects the inspectable roots of a body. String roots ("input": "…") are wrapped so a redaction can be
// written back.
func (c *call) content(body map[string]any, roots []string) text {
	sub := map[string]any{}
	for _, k := range roots {
		if v, ok := body[k]; ok {
			sub[k] = v
		}
	}
	return text{inspect.New(sub, skip), sub}
}

// text is the inspected part of a body; sub holds its roots, where redactions land.
type text struct {
	*inspect.Content
	sub map[string]any
}

// scan is what was found in one inspected text.
type scan struct {
	res    detect.Result
	text   string
	tokens int
	exfil  float64 // system prompt leak (FR-PSEC-5), responses only
	// A stream's record keeps no text: its content hash and first snippet are carried instead.
	hash, snippet string
}

func scanOf(in *inspect.Content, exfil float64) scan {
	return scan{res: in.Res, text: in.Text, tokens: (len(in.Text) + 3) / 4, exfil: exfil}
}

// enforce decides one direction and applies the decision to body. false = a refusal has been written.
func (c *call) enforce(ctx context.Context, direction string, body map[string]any, roots []string, in text, exfil float64) bool {
	sc := scanOf(in.Content, exfil)
	d, err := c.decide(ctx, direction, sc)
	if err != nil {
		return c.failMode(ctx, direction, sc)
	}
	eid := c.record(ctx, direction, sc, d)
	c.decision = eid
	c.action = strictest(c.action, d.Action)
	what := "Request blocked"
	if direction == "response" {
		what = "Response withheld"
	}
	switch d.Action {
	case "allow", "warn":
		return true
	case "redact", "tokenize":
		c.protect(ctx, d, in.Content)
		for _, k := range roots {
			if v, ok := in.sub[k]; ok {
				body[k] = v
			}
		}
		// ADR-0001: when redaction cannot be applied the PEP blocks. Check that nothing it had to remove is left
		// (tokens it issued may look like identifiers: they are what it put there).
		globs := obligationClasses(d)
		if left := c.content(body, roots); slices.ContainsFunc(left.Findings(), func(f inspect.Finding) bool {
			_, issued := c.tokens[digitsOf(f.Value)]
			return inspect.Wanted(globs, f.Type) && !issued
		}) {
			c.g.Log.Warn("redaction incomplete, blocking", "decision", eid)
			c.action = "block"
			c.refuse(http.StatusForbidden, "wantimpres26_redaction_failed", blockMessage(what, []string{"REDACTION_FAILED"}, eid))
			return false
		}
		return true
	}
	c.action = "block" // block, quarantine, require_approval: no human approval loop on this channel
	c.refuse(http.StatusForbidden, "wantimpres26_policy_block", blockMessage(what, d.ReasonCodes, eid))
	return false
}

// failMode applies the app's fail mode when the PDP cannot decide (spec §13.3).
func (c *call) failMode(ctx context.Context, direction string, sc scan) bool {
	open := c.failOpen(ctx, direction, sc)
	if !open {
		c.action = "block"
		c.refuse(http.StatusServiceUnavailable, "wantimpres26_policy_unavailable", "The WANTIMPRES-26 policy service is unavailable and this app fails closed. Retry later. Decision ID: "+c.decision+".")
	}
	return open
}

// failOpen records an undecided inspection and reports whether the app's fail mode lets it through.
func (c *call) failOpen(ctx context.Context, direction string, sc scan) bool {
	g := c.g
	open := c.app.FailMode == FailOpen
	action, reason := "block", "FAIL_CLOSED"
	if open {
		action, reason = "allow", "FAIL_OPEN"
		g.Log.Warn("PDP unavailable, failing open", "app", c.app.ID, "direction", direction)
	}
	g.count(strings.ToLower(reason)+"_total", c.app.ID)
	c.decision = c.record(ctx, direction, sc, mcpgw.Decision{Action: action, ReasonCodes: []string{reason}, PolicyVersion: "unavailable", RiskVersion: "unavailable"})
	return open
}

func (c *call) decide(ctx context.Context, direction string, sc scan) (mcpgw.Decision, error) {
	classes := make([]any, 0, len(sc.res.Classes))
	for _, cl := range sc.res.Classes {
		classes = append(classes, map[string]any{"type": cl.Type, "count": cl.Count, "confidence": cl.Confidence})
	}
	content := map[string]any{"sensitivity": sc.res.Sensitivity, "classes": classes, "injection_score": sc.res.Injection.Score, "tokens": sc.tokens}
	if sc.exfil > 0 {
		content["exfil_score"] = sc.exfil
	}
	ptype, pid := c.principal()
	d, err := c.g.Decide(ctx, map[string]any{
		"channel":     "ai_gateway",
		"direction":   direction,
		"principal":   map[string]any{"type": ptype, "id": pid},
		"destination": map[string]any{"app_id": c.p.AppID, "sanction": c.p.Sanction, "region": c.p.Region},
		"content":     content,
	})
	if err != nil {
		c.g.Log.Error("PDP", "direction", direction, "err", err)
	}
	return d, err
}

// record emits the decision event for one inspection and returns its id (the decision id apps see).
func (c *call) record(ctx context.Context, direction string, sc scan, d mcpgw.Decision) string {
	return c.recordAs(ctx, uuid.NewString(), direction, sc, d)
}

func (c *call) recordAs(ctx context.Context, id, direction string, sc scan, d mcpgw.Decision) string {
	g := c.g
	ptype, pid := c.principal()
	score := sc.res.Injection.Score
	cls := make([]events.Class, 0, len(sc.res.Classes))
	for _, cl := range sc.res.Classes {
		cls = append(cls, events.Class{Type: cl.Type, Count: cl.Count, Confidence: cl.Confidence})
	}
	e := events.Event{
		EventID: id, TenantID: g.TenantID, TS: g.Now().UTC().Format(time.RFC3339Nano), TraceID: c.trace,
		Channel: "ai_gateway", Direction: direction, PrincipalID: pid, PrincipalType: ptype, AppID: c.p.AppID, SourceApp: c.app.ID,
		Classes: cls, ContentHash: g.hmac(sc.text), Sensitivity: sc.res.Sensitivity, InjectionScore: &score, Tokens: &sc.tokens,
		Action: d.Action, ReasonCodes: nonNil(d.ReasonCodes), MatchedRules: d.MatchedRules, PolicyVersion: d.PolicyVersion,
		RiskScore: d.RiskScore, RiskOverrides: d.RiskOverrides, RiskVersion: d.RiskVersion,
		Sanction: d.Destination.Sanction, Region: d.Destination.Region, TrainsOnData: d.Destination.TrainsOnData,
	}
	if sc.exfil > 0 {
		e.ExfilScore = &sc.exfil
	}
	if len(sc.res.Matches) > 0 || len(sc.res.Injection.Evidence) > 0 {
		e.Snippet = detect.Snippet(sc.text, append(slices.Clone(sc.res.Matches), sc.res.Injection.Evidence...))
	}
	if sc.hash != "" {
		e.ContentHash, e.Snippet = sc.hash, sc.snippet
	}
	if g.Detection != nil && sc.text != "" {
		// After the decision and off the request path: the event waits for L2, the app does not (ticket 49).
		go func() {
			e.L2 = g.Detection.Shadow(context.WithoutCancel(ctx), sc.text, direction, c.p.AppID)
			if e.L2.Status != "ok" && e.L2.Status != "skipped" {
				g.count("detection_fallback_total", c.app.ID)
			}
			c.emit(context.WithoutCancel(ctx), e)
		}()
		return e.EventID
	}
	c.emit(ctx, e)
	return e.EventID
}

func (c *call) emit(ctx context.Context, e events.Event) {
	if err := c.g.Emit(ctx, e); err != nil {
		c.g.Log.Error("decision event", "err", err) // ponytail: logged, not retried, as in the MCP gateway
	}
}

// principal: the end user when the app named one, else the app itself as a service (its name is in source_app).
func (c *call) principal() (string, string) {
	if c.user != "" {
		return "user", c.user
	}
	return "service", c.g.hmac("app:" + c.app.ID)
}

// forward sends the (possibly redacted) request to the provider with the provider key from the vault.
func (c *call) forward(ctx context.Context, r *http.Request, rest string, body []byte) (*http.Response, error) {
	key, err := c.g.Key(c.p)
	if err != nil {
		return nil, fmt.Errorf("provider key: %w", err)
	}
	q := r.URL.Query()
	q.Del("key") // the app's gateway key, Gemini style
	u := c.p.Upstream + "/" + rest
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for _, h := range forwardRequestHeaders {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	setAuth(req.Header, c.p, key)
	return c.g.Upstream.Do(req)
}

// --- limits (FR-PSEC-9) ---------------------------------------------------------------------------------------

func (c *call) withinLimits(ctx context.Context) bool {
	minute := c.g.Now().UTC().Format("200601021504")
	for _, l := range []struct {
		key   string
		limit int64
	}{{"rpm:" + c.app.ID + ":" + minute, c.app.RPM}, {"urpm:" + c.app.ID + ":" + c.user + ":" + minute, c.app.UserRPM}} {
		if l.limit == 0 || strings.Contains(l.key, "::") {
			continue // no limit, or no user to limit
		}
		n, err := c.g.Count(ctx, l.key, 1, 2*time.Minute)
		if err != nil {
			c.g.Log.Error("rate counter unavailable, not limiting", "err", err) // availability control, not a data control
			return true
		}
		if n > l.limit {
			c.g.count("rate_limited_total", c.app.ID)
			c.w.Header().Set("Retry-After", "60")
			c.refuse(http.StatusTooManyRequests, "rate_limit_exceeded", "WANTIMPRES-26 gateway rate limit reached for this app or user.")
			return false
		}
	}
	return true
}

func (c *call) quotaKeys() []struct {
	key   string
	limit int64
} {
	day := c.g.Now().UTC().Format("20060102")
	ks := []struct {
		key   string
		limit int64
	}{{"tok:" + c.app.ID + ":" + day, c.app.TokensPerDay}}
	if c.user != "" {
		ks = append(ks, struct {
			key   string
			limit int64
		}{"utok:" + c.app.ID + ":" + c.user + ":" + day, c.app.UserTokensPerDay})
	}
	return ks
}

// withinQuota refuses a request whose input alone would pass the daily token quota.
func (c *call) withinQuota(ctx context.Context, tokens int64) bool {
	for _, q := range c.quotaKeys() {
		if q.limit == 0 {
			continue
		}
		used, err := c.g.Count(ctx, q.key, 0, 48*time.Hour)
		if err != nil {
			c.g.Log.Error("quota counter unavailable, not limiting", "err", err)
			return true
		}
		if used+tokens > q.limit {
			c.g.count("quota_exceeded_total", c.app.ID)
			c.refuse(http.StatusTooManyRequests, "token_quota_exceeded", "Daily WANTIMPRES-26 token quota reached for this app or user.")
			return false
		}
	}
	return true
}

// charge adds what the provider billed to the quotas.
func (c *call) charge(ctx context.Context, tokens int64) {
	for _, q := range c.quotaKeys() {
		if q.limit > 0 {
			if _, err := c.g.Count(ctx, q.key, tokens, 48*time.Hour); err != nil {
				c.g.Log.Error("quota counter unavailable", "err", err)
			}
		}
	}
}

// --- responses ----------------------------------------------------------------------------------------------

func (c *call) headers() {
	if c.decision != "" {
		c.w.Header().Set("X-Wantimpres26-Decision-Id", c.decision)
	}
	c.w.Header().Set("X-Wantimpres26-Action", c.action)
}

// refuse answers in the provider's error format.
func (c *call) refuse(status int, code, msg string) {
	c.headers()
	writeJSON(c.w, status, errorBody(c.p.Kind, status, code, msg))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// precedence is FR-POL-4, strictest first.
var precedence = []string{"block", "quarantine", "require_approval", "tokenize", "redact", "warn", "allow"}

func strictest(a, b string) string {
	if i, j := slices.Index(precedence, a), slices.Index(precedence, b); j >= 0 && (i < 0 || j < i) {
		return b
	}
	return a
}

func obligationClasses(d mcpgw.Decision) []string {
	var globs []string
	for _, o := range d.Obligations {
		if o.Type == "redact" || o.Type == "tokenize" {
			globs = append(globs, o.Classes...)
		}
	}
	return globs
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (g *Gateway) hmac(s string) string {
	m := hmac.New(sha256.New, g.Pepper)
	m.Write([]byte(s))
	return hex.EncodeToString(m.Sum(nil))
}

// traceID takes the W3C traceparent's trace id when the app sent one.
func traceID(r *http.Request) string {
	if parts := strings.Split(r.Header.Get("traceparent"), "-"); len(parts) == 4 && len(parts[1]) == 32 {
		return parts[1]
	}
	return strings.ReplaceAll(uuid.NewString(), "-", "")
}

// --- metrics ------------------------------------------------------------------------------------------------

func (g *Gateway) count(name, app string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.metrics == nil {
		g.metrics = map[[2]string]int64{}
	}
	g.metrics[[2]string{name, app}]++
}

// serveMetrics is the Prometheus text exposition. Hand-written: a few counters do not need client_golang.
func (g *Gateway) serveMetrics(w http.ResponseWriter, _ *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	keys := make([][2]string, 0, len(g.metrics))
	for k := range g.metrics {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b [2]string) int { return strings.Compare(a[0]+a[1], b[0]+b[1]) })
	for _, k := range keys {
		_, _ = fmt.Fprintf(w, "aigw_%s{app=%q} %d\n", k[0], k[1], g.metrics[k])
	}
	if g.Metrics != nil {
		g.Metrics(w)
	}
}
