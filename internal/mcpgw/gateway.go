// Package mcpgw is the MCP gateway (spec §4.8 FR-AGT-3..5, FR-AGT-8; §7.2): the PEP between AI agents and MCP
// tool servers over Streamable HTTP.
//
// Per request: verify the agent's access token for this server's resource URI, map its workload identity to the
// registry entry, inspect tools/call arguments (DLP + injection, scopes, rate, delegation depth), ask the PDP,
// swap the token for a short-lived downstream one (RFC 8693; the agent's token never leaves the gateway),
// forward, then inspect tool results and resource reads the same way before the agent sees them. Every decision
// is a decision_event carrying the trace_id, which is the session audit (prompt → tool_call → result).
package mcpgw

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"wantimpres26/internal/events"
	"wantimpres26/internal/inspect"
	"wantimpres26/internal/mcptools"
	"wantimpres26/internal/toolscope"
)

// Server is one MCP tool server behind the gateway, reached at /mcp/{name}.
type Server struct {
	Name     string `json:"name"`
	Upstream string `json:"upstream"` // the tool server's MCP endpoint
	Audience string `json:"audience"` // audience of the exchanged downstream token
	AppID    string `json:"app_id"`   // destination for the PDP (catalog id when the server is in the app catalog)
	Sanction string `json:"sanction"` // used when the app is not in the catalog
	Region   string `json:"region"`
}

type Gateway struct {
	BaseURL string // public origin; a server's resource URI is BaseURL + "/mcp/" + name
	Issuer  string // authorization server advertised in protected resource metadata
	Servers map[string]Server

	Verify   func(ctx context.Context, raw, resource string) (Token, error)
	Exchange func(ctx context.Context, subject, audience string) (string, error)
	Agent    func(ctx context.Context, identity string) (*RegistryAgent, error)
	Decide   func(ctx context.Context, input map[string]any) (Decision, error)
	Emit     func(ctx context.Context, e events.Event) error
	// Observe reports a server's tools/list to the registry (ticket 29) and returns which tools may be called;
	// Pins is the fallback when the registry cannot be reached: the bundle's statuses and pinned hashes.
	Observe func(ctx context.Context, server string, tools []map[string]any) (map[string]ToolState, error)
	Pins    func(ctx context.Context, server string) (map[string]Pin, error)
	// HITL (ticket 30): Claim uses a human approval of exactly this call; RequestApproval opens one. Both nil =
	// no HITL, require_approval is a deny.
	Claim           func(ctx context.Context, key ApprovalKey) (id string, ok bool, err error)
	RequestApproval func(ctx context.Context, req ApprovalRequest) (Ticket, error)
	// Kill switch (ticket 30): Kills reads the active switches from the bundle; Purge drops cached downstream
	// credentials when they change.
	Kills    func(ctx context.Context) (KillSet, error)
	Purge    func()
	Upstream *http.Client

	Pepper      []byte // tenant HMAC key for principal ids and content hashes (spec §10.2)
	TenantID    string
	DefaultRate int // tools/call per minute per agent and tool when the registry sets no rate_per_minute
	// Behavior: per-agent tool-call baselines (ticket 39); nil = no behaviour analytics.
	Behavior *Behavior
	Now      func() time.Time
	Log      *slog.Logger

	mu    sync.Mutex
	taint map[string]taint
	srcs  map[string]sources
	rates map[string]window
	seen  map[string]string // "server/tool" → hash of the definition last served in tools/list

	killMu sync.Mutex
	kills  KillSet
	active map[*active]struct{}
}

const (
	maxRequest = 4 << 20
	maxResult  = 16 << 20
	// taintTTL: how long injection seen by an agent keeps its high-risk tools behind approval.
	taintTTL = 30 * time.Minute
)

func (g *Gateway) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp/{server}", g.metadata)
	for _, m := range []string{"POST", "GET", "DELETE"} {
		mux.HandleFunc(m+" /mcp/{server}", g.serve)
	}
}

func (g *Gateway) resource(name string) string { return g.BaseURL + "/mcp/" + name }

// metadata is RFC 9728 protected resource metadata: where an MCP client gets a token for this server.
func (g *Gateway) metadata(w http.ResponseWriter, r *http.Request) {
	srv, ok := g.Servers[r.PathValue("server")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 g.resource(srv.Name),
		"authorization_servers":    []string{g.Issuer},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            srv.Name,
	})
}

// challenge is the MCP authorization 401: the client discovers the authorization server from resource_metadata.
func (g *Gateway) challenge(w http.ResponseWriter, srv Server, errCode string) {
	v := fmt.Sprintf(`Bearer resource_metadata=%q`, g.BaseURL+"/.well-known/oauth-protected-resource/mcp/"+srv.Name)
	if errCode != "" {
		v += fmt.Sprintf(`, error=%q`, errCode)
	}
	w.Header().Set("WWW-Authenticate", v)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// call is one agent request through the gateway.
type call struct {
	act        *active
	approvalID string // human approval this tools/call used
	g          *Gateway
	srv        Server
	agentID    string
	tools      map[string]*toolEntry
	depth      int
	trace      string
	taintKey   string
}

type toolEntry struct {
	Risk         string
	Scopes       map[string]any
	WritesMemory bool
}

// pending is the request a response answers: which tool, or a resource read.
type pending struct {
	id   json.RawMessage
	tool string // "resources/read" for resource reads
	seen bool
}

var traceparent = regexp.MustCompile(`^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$`)

func (g *Gateway) serve(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context()) // a kill switch cancels it: the session is cut mid-stream
	defer cancel()
	srv, ok := g.Servers[r.PathValue("server")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || raw == "" {
		g.challenge(w, srv, "")
		return
	}
	tok, err := g.Verify(ctx, raw, g.resource(srv.Name))
	if err != nil {
		g.Log.Info("token rejected", "server", srv.Name, "err", err)
		g.challenge(w, srv, "invalid_token")
		return
	}
	reg, err := g.Agent(ctx, tok.Identity)
	if err != nil {
		g.Log.Error("registry lookup", "err", err)
		http.Error(w, "policy unavailable", http.StatusServiceUnavailable)
		return
	}
	c := &call{g: g, srv: srv, agentID: tok.Identity, tools: map[string]*toolEntry{}, depth: tok.ChainDepth}
	if reg != nil {
		c.agentID = reg.ID
		for _, t := range reg.Tools {
			c.tools[t.Name] = &toolEntry{t.Risk, t.Scopes, t.WritesMemory}
		}
	}
	// A killed agent or app gets nothing through, not even tools/list: its token is as good as revoked.
	a := &active{agent: c.agentID, app: srv.AppID, cancel: cancel}
	if !g.track(a) {
		http.Error(w, "stopped by kill switch", http.StatusForbidden)
		return
	}
	defer g.untrack(a)
	c.act = a
	// Taint follows the agent's trace when it propagates one (one task across tool servers); otherwise the agent.
	c.taintKey = c.agentID
	if m := traceparent.FindStringSubmatch(r.Header.Get("Traceparent")); m != nil {
		c.trace = m[1]
		c.taintKey += "|" + c.trace
	} else {
		c.trace = randomHex(16)
	}

	var body []byte
	var pend *pending
	if r.Method == http.MethodPost {
		if body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequest)); err != nil {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		var msg message
		if bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) || json.Unmarshal(body, &msg) != nil {
			http.Error(w, "one JSON-RPC message per request", http.StatusBadRequest)
			return
		}
		switch msg.Method {
		case "tools/call":
			out, deny := c.toolCall(ctx, &msg)
			if deny != nil {
				writeJSON(w, http.StatusOK, deny)
				return
			}
			body = out
			pend = &pending{id: msg.ID, tool: toolName(msg.Params)}
		case "resources/read", "tools/list":
			pend = &pending{id: msg.ID, tool: msg.Method}
		}
	}

	down, err := g.Exchange(ctx, raw, srv.Audience)
	if err != nil {
		g.Log.Error("token exchange", "server", srv.Name, "err", err)
		http.Error(w, "downstream credential unavailable", http.StatusBadGateway)
		return
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, srv.Upstream, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "bad upstream", http.StatusBadGateway)
		return
	}
	// Allow-list, not deny-list: the agent's Authorization, cookies and anything else never reach the tool server.
	for _, h := range []string{"Accept", "Content-Type", "Mcp-Session-Id", "Mcp-Protocol-Version", "Last-Event-Id"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	req.Header.Set("Authorization", "Bearer "+down)
	req.Header.Set("Traceparent", "00-"+c.trace+"-"+randomHex(8)+"-01")
	resp, err := g.Upstream.Do(req)
	if err != nil {
		g.Log.Error("upstream", "server", srv.Name, "err", err)
		http.Error(w, "tool server unavailable", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// The downstream credential is the gateway's business; its challenge means nothing to the agent.
		g.Log.Error("tool server refused the exchanged token", "server", srv.Name, "status", resp.StatusCode)
		http.Error(w, "tool server refused the gateway credential", http.StatusBadGateway)
		return
	}
	for _, h := range []string{"Mcp-Session-Id", "Mcp-Protocol-Version"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch mt {
	case "application/json":
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxResult+1))
		if err != nil || len(b) > maxResult {
			http.Error(w, "tool result too large", http.StatusBadGateway)
			return
		}
		out := c.inspectPayload(ctx, b, pend)
		if pend != nil && !pend.seen {
			// A result the gateway could not read must not reach the agent unread.
			out, _ = json.Marshal(rpcError(pend.id, "tool server response not inspectable", nil))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(out)
	case "text/event-stream":
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(resp.StatusCode)
		c.stream(ctx, w, resp.Body, pend)
	default:
		if resp.StatusCode < 300 && resp.StatusCode != http.StatusAccepted && resp.ContentLength != 0 {
			http.Error(w, "unsupported tool server response", http.StatusBadGateway)
			return
		}
		// Acks and HTTP errors: status only. An error page is uninspected text and never reaches the agent.
		if resp.StatusCode == http.StatusAccepted {
			w.WriteHeader(resp.StatusCode)
			return
		}
		http.Error(w, http.StatusText(resp.StatusCode), resp.StatusCode)
	}
}

// stream relays an SSE response event by event, inspecting each JSON-RPC message before the agent sees it.
func (c *call) stream(ctx context.Context, w http.ResponseWriter, body io.Reader, pend *pending) {
	fl, _ := w.(http.Flusher)
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64<<10), maxResult)
	var lines []string
	flush := func() {
		if len(lines) == 0 {
			return
		}
		var data, other []string
		for _, l := range lines {
			if v, ok := strings.CutPrefix(l, "data:"); ok {
				data = append(data, strings.TrimPrefix(v, " "))
			} else {
				other = append(other, l)
			}
		}
		if len(data) > 0 {
			lines = append(other, "data: "+string(c.inspectPayload(ctx, []byte(strings.Join(data, "\n")), pend)))
		}
		_, _ = io.WriteString(w, strings.Join(lines, "\n")+"\n\n")
		if fl != nil {
			fl.Flush()
		}
		lines = nil
	}
	for sc.Scan() {
		if sc.Text() == "" {
			flush()
		} else {
			lines = append(lines, sc.Text())
		}
	}
	flush()
}

// --- JSON-RPC ---

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

func rpcError(id json.RawMessage, msg string, data any) message {
	e, _ := json.Marshal(map[string]any{"code": -32001, "message": msg, "data": data})
	return message{JSONRPC: "2.0", ID: id, Error: e}
}

func toolName(params json.RawMessage) string {
	var p struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(params, &p)
	return p.Name
}

func sameID(a, b json.RawMessage) bool {
	var x, y bytes.Buffer
	return json.Compact(&x, a) == nil && json.Compact(&y, b) == nil && bytes.Equal(x.Bytes(), y.Bytes())
}

// toolCall inspects a tools/call request. It returns the (possibly redacted) body to forward, or the JSON-RPC
// error to answer with instead.
func (c *call) toolCall(ctx context.Context, msg *message) ([]byte, *message) {
	var params map[string]any
	if json.Unmarshal(msg.Params, &params) != nil {
		m := rpcError(msg.ID, "invalid tools/call params", nil)
		return nil, &m
	}
	name, _ := params["name"].(string)
	args, _ := params["arguments"].(map[string]any)
	if args == nil {
		args = map[string]any{}
	}
	t := c.tools[name]
	agent := map[string]any{"tool": name, "tool_risk": "high", "scope_violations": 0, "mcp_server": c.srv.Name} // unknown tools count as high
	if h, ok := c.g.seenHash(c.srv.Name + "/" + name); ok {
		agent["tool_hash"] = h
	}
	limit := c.g.DefaultRate
	if t != nil {
		agent["tool_risk"] = t.Risk
		agent["writes_memory"] = t.WritesMemory
		agent["scope_violations"] = len(toolscope.Violations(t.Scopes, args))
		limit = toolscope.RatePerMinute(t.Scopes, limit)
	}
	agent["rate_exceeded"] = c.g.overRate(c.agentID+"|"+name, limit)
	if c.g.Behavior != nil { // every attempt counts, allowed or not: a rogue agent shows in what it tries
		if an := c.g.Behavior.Observe(c.agentID, c.taintKey, name, c.g.Now()); len(an) > 0 {
			agent["behavior_anomalies"] = an
		}
	}
	if c.g.setTool(c.act, name) {
		m := rpcError(msg.ID, "stopped by kill switch", map[string]any{"reason_codes": []string{"KILL_SWITCH"}})
		return nil, &m
	}

	// An approval binds to this agent, server, tool and these exact arguments, and is used once.
	key := ApprovalKey{AgentID: c.agentID, Server: c.srv.Name, Tool: name, ArgsDigest: digest(args)}
	if c.g.Claim != nil {
		id, ok, err := c.g.Claim(ctx, key)
		if err != nil {
			c.g.Log.Error("approval claim", "err", err) // no approval: require_approval stays a deny
		}
		if ok {
			c.approvalID, agent["approval_granted"] = id, true
		}
	}

	in := inspect.New(args, nil)
	d, eid, err := c.decide(ctx, "tool_call", name, in, agent)
	if err != nil {
		m := rpcError(msg.ID, "policy unavailable", nil)
		return nil, &m
	}
	switch d.Action {
	case "allow", "warn":
		return mustJSON(msg), nil
	case "redact", "tokenize": // ponytail: tokenize redacts until the token vault (ticket 24)
		in.Redact(obligationClasses(d))
		params["arguments"] = args
		msg.Params = mustJSON(params)
		return mustJSON(msg), nil
	case "require_approval":
		if c.g.RequestApproval == nil {
			break
		}
		// The approver sees the call with secrets and card data redacted; the raw arguments stay here.
		in.Redact([]string{"SECRET.*", "PCI.*"})
		t, err := c.g.RequestApproval(ctx, ApprovalRequest{ApprovalKey: key, Preview: args, ReasonCodes: d.ReasonCodes, TraceID: c.trace})
		if err != nil {
			c.g.Log.Error("approval request", "err", err)
			m := rpcError(msg.ID, "approval required but unavailable", map[string]any{"decision_id": eid, "action": d.Action, "reason_codes": d.ReasonCodes})
			return nil, &m
		}
		m := rpcError(msg.ID, "approval required: call again with the same arguments once approved", map[string]any{"decision_id": eid,
			"action": d.Action, "reason_codes": d.ReasonCodes, "approval_id": t.ID, "state": t.State, "expires_at": t.ExpiresAt})
		return nil, &m
	}
	// block, quarantine, and require_approval without HITL: deny.
	m := rpcError(msg.ID, "blocked by policy", map[string]any{"decision_id": eid, "action": d.Action, "reason_codes": d.ReasonCodes})
	return nil, &m
}

// inspectPayload inspects one JSON-RPC message from the tool server and returns what to relay. Responses to
// tools/call and resources/read, error messages, and (on GET streams) anything shaped like tool content or
// prompt messages are untrusted text on its way to a model.
func (c *call) inspectPayload(ctx context.Context, b []byte, pend *pending) []byte {
	var msg message
	if json.Unmarshal(b, &msg) != nil || len(msg.Result) == 0 && len(msg.Error) == 0 {
		return b // requests and notifications from the server
	}
	matched := pend != nil && sameID(msg.ID, pend.id)
	if matched {
		pend.seen = true
	}
	isErr := len(msg.Result) == 0
	field := &msg.Result
	if isErr {
		field = &msg.Error
	}
	var obj map[string]any
	if json.Unmarshal(*field, &obj) != nil {
		return mustJSON(rpcError(msg.ID, "tool server response not inspectable", nil)) // MCP results are objects
	}
	if !isErr && (matched && pend.tool == "tools/list" || !matched && obj["tools"] != nil) {
		obj["tools"] = c.callableTools(ctx, obj["tools"])
		msg.Result = mustJSON(obj)
		return mustJSON(msg)
	}
	tool := ""
	switch {
	case matched:
		tool = pend.tool
	case isErr || obj["content"] != nil || obj["contents"] != nil || obj["messages"] != nil:
	default:
		return b // initialize, tools/list, …: tool descriptions are ticket 29's
	}
	in := inspect.New(obj, nil)
	agent := map[string]any{"tool": tool}
	if t := c.tools[tool]; t != nil {
		agent["tool_risk"] = t.Risk
	}
	d, eid, err := c.decide(ctx, "tool_result", tool, in, agent)
	if err == nil && tool != "" && (d.Action == "allow" || d.Action == "warn" || d.Action == "redact" || d.Action == "tokenize") {
		c.g.addSource(c.taintKey, c.srv.Name+"/"+tool) // the agent sees it: provenance of what it writes to memory next
	}
	switch {
	case err != nil:
		return mustJSON(rpcError(msg.ID, "policy unavailable", nil))
	case d.Action == "allow" || d.Action == "warn":
		return b
	case d.Action == "redact" || d.Action == "tokenize":
		in.Redact(obligationClasses(d))
		*field = mustJSON(obj)
		return mustJSON(msg)
	}
	data := map[string]any{"decision_id": eid, "action": d.Action, "reason_codes": d.ReasonCodes}
	if isErr || tool == "resources/read" {
		return mustJSON(rpcError(msg.ID, "blocked by policy", data))
	}
	// A tool execution error the model can read (MCP isError), carrying no byte of the blocked content.
	msg.Result = mustJSON(map[string]any{"isError": true, "content": []any{map[string]any{
		"type": "text", "text": fmt.Sprintf("[WANTIMPRES-26] tool result blocked by policy %v (decision %s)", d.ReasonCodes, eid)}}})
	return mustJSON(msg)
}

// --- inspection ---

// obligationClasses are the class globs of the decision's redact/tokenize obligations.
func obligationClasses(d Decision) []string {
	var globs []string
	for _, o := range d.Obligations {
		if o.Type == "redact" || o.Type == "tokenize" {
			globs = append(globs, o.Classes...)
		}
	}
	return globs
}

// decide builds the canonical PDP input, asks the PDP, records the session taint and emits the decision event.
// The event id doubles as the decision id the agent sees.
func (c *call) decide(ctx context.Context, direction, tool string, in *inspect.Content, agent map[string]any) (Decision, string, error) {
	g := c.g
	taint := g.taintOf(c.taintKey)
	g.addTaint(c.taintKey, in.Res.Injection.Score)
	agent["agent_id"] = c.agentID
	agent["hitl_available"] = g.RequestApproval != nil
	agent["session_injection_max"] = taint
	agent["chain_depth"] = c.depth
	classes := make([]any, 0, len(in.Res.Classes))
	evClasses := make([]events.Class, 0, len(in.Res.Classes))
	for _, cl := range in.Res.Classes {
		classes = append(classes, map[string]any{"type": cl.Type, "count": cl.Count, "confidence": cl.Confidence})
		evClasses = append(evClasses, events.Class{Type: cl.Type, Count: cl.Count, Confidence: cl.Confidence})
	}
	principal := g.hmac("agent:" + c.agentID)
	input := map[string]any{
		"channel":     "mcp_gateway",
		"direction":   direction,
		"principal":   map[string]any{"type": "agent", "id": principal},
		"destination": map[string]any{"app_id": c.srv.AppID, "sanction": c.srv.Sanction, "region": c.srv.Region},
		"content":     map[string]any{"sensitivity": in.Res.Sensitivity, "classes": classes, "injection_score": in.Res.Injection.Score},
		"agent":       agent,
	}
	d, err := g.Decide(ctx, input)
	if err != nil {
		g.Log.Error("PDP", "direction", direction, "err", err)
		return Decision{}, "", err
	}
	eid := uuid.NewString()
	score, hitl := in.Res.Injection.Score, false
	e := events.Event{
		EventID: eid, TenantID: g.TenantID, TS: g.Now().UTC().Format(time.RFC3339Nano), TraceID: c.trace,
		Channel: "mcp_gateway", Direction: direction, PrincipalID: principal, AppID: c.srv.AppID, AgentID: c.agentID,
		Action: d.Action, ReasonCodes: nonNil(d.ReasonCodes), MatchedRules: d.MatchedRules, PolicyVersion: d.PolicyVersion,
		RiskScore: d.RiskScore, RiskOverrides: d.RiskOverrides, RiskVersion: d.RiskVersion, Classes: evClasses,
		ContentHash: g.hmac(string(in.Raw)), PrincipalType: "agent", Sanction: d.Destination.Sanction, Region: d.Destination.Region,
		TrainsOnData: d.Destination.TrainsOnData, Sensitivity: in.Res.Sensitivity, InjectionScore: &score, AgentTool: tool,
		SessionInjectionMax: &taint, HITLAvailable: &hitl, ChainDepth: &c.depth,
	}
	if r, ok := agent["tool_risk"].(string); ok {
		e.ToolRisk = r
	}
	if n, ok := agent["scope_violations"].(int); ok {
		e.ScopeViolations = &n
	}
	if x, ok := agent["rate_exceeded"].(bool); ok {
		e.RateExceeded = &x
	}
	e.MCPServer, _ = agent["mcp_server"].(string)
	if direction == "tool_call" {
		e.ApprovalID = c.approvalID
	}
	// FR-AGT-9 provenance of a memory write: agent and trace are on every event; add where its content can come from.
	if wm, _ := agent["writes_memory"].(bool); wm && direction == "tool_call" {
		e.MemoryWrite, e.ContentOrigin, e.ContentSources = &wm, "user", g.sourcesOf(c.taintKey)
		if len(e.ContentSources) > 0 {
			e.ContentOrigin = "tool_result"
		}
	}
	e.ToolHash, _ = agent["tool_hash"].(string)
	e.BehaviorAnomalies, _ = agent["behavior_anomalies"].([]string)
	if err := g.Emit(ctx, e); err != nil {
		g.Log.Error("decision event", "err", err) // ponytail: logged, not retried; a local spool if Kafka outages bite
	}
	return d, eid, nil
}

// --- tool definitions (ticket 29) ---

// ToolState is the registry's answer for one observed tool.
type ToolState struct {
	Status   string `json:"status"`
	Callable bool   `json:"callable"`
}

// Pin is a tool's status and approved definition hash in the policy bundle.
type Pin struct {
	Status string `json:"status"`
	Hash   string `json:"hash"`
}

// callableTools pins what tools/list served, reports it to the registry, and keeps only the tools that may be
// called: a new tool still under review, or a definition changed since approval (rug pull), never reaches the
// model's context. If neither the registry nor the bundle can answer, no tool is shown.
func (c *call) callableTools(ctx context.Context, v any) []any {
	list, _ := v.([]any)
	var defs []map[string]any
	hashes := map[string]string{}
	for _, d := range list {
		if m, ok := d.(map[string]any); ok && mcptools.Name(m) != "" {
			defs = append(defs, m)
			hashes[mcptools.Name(m)] = mcptools.Hash(m)
		}
	}
	c.g.mu.Lock()
	if c.g.seen == nil {
		c.g.seen = map[string]string{}
	}
	for name, h := range hashes {
		c.g.seen[c.srv.Name+"/"+name] = h
	}
	c.g.mu.Unlock()

	callable := map[string]bool{}
	states, err := c.g.Observe(ctx, c.srv.Name, defs)
	if err == nil {
		for name, st := range states {
			callable[name] = st.Callable
		}
	} else {
		c.g.Log.Error("registry observe; falling back to the bundle", "server", c.srv.Name, "err", err)
		pins, err := c.g.Pins(ctx, c.srv.Name)
		if err != nil {
			c.g.Log.Error("bundle pins", "server", c.srv.Name, "err", err)
		}
		for name, p := range pins {
			callable[name] = p.Status == "approved" && p.Hash == hashes[name]
		}
	}
	out := []any{}
	for _, d := range defs {
		if callable[mcptools.Name(d)] {
			out = append(out, d)
		}
	}
	if hidden := len(list) - len(out); hidden > 0 {
		c.g.Log.Info("tools hidden pending review", "server", c.srv.Name, "hidden", hidden)
	}
	return out
}

func (g *Gateway) seenHash(key string) (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	h, ok := g.seen[key]
	return h, ok
}

// --- HITL approvals (ticket 30) ---

// ApprovalKey is what an approval allows: this agent calling this tool on this server with these arguments.
type ApprovalKey struct {
	AgentID    string `json:"agent_id"`
	Server     string `json:"server"`
	Tool       string `json:"tool"`
	ArgsDigest string `json:"args_digest"`
}

type ApprovalRequest struct {
	ApprovalKey
	Preview     map[string]any `json:"preview"`
	ReasonCodes []string       `json:"reason_codes"`
	TraceID     string         `json:"trace_id"`
}

// Ticket is the open approval request the agent is told about.
type Ticket struct {
	ID        string    `json:"approval_id"`
	State     string    `json:"state"`
	ExpiresAt time.Time `json:"expires_at"`
}

// digest is the SHA-256 of the arguments' canonical JSON (sorted keys).
func digest(args map[string]any) string {
	sum := sha256.Sum256(mustJSON(args))
	return hex.EncodeToString(sum[:])
}

// --- kill switch (ticket 30) ---

// KillSet is data.wantimpres26.kills: active switches by scope (target → reason).
type KillSet struct {
	Global bool              `json:"global"`
	Agent  map[string]string `json:"agent"`
	Tool   map[string]string `json:"tool"`
	App    map[string]string `json:"app"`
}

func (k KillSet) hits(a *active) bool {
	_, agent := k.Agent[a.agent]
	_, app := k.App[a.app]
	_, tool := k.Tool[a.tool]
	return k.Global || agent || app || (a.tool != "" && tool)
}

// active is one request in flight, cancelled when a kill switch covers it.
type active struct {
	agent, app, tool string
	cancel           context.CancelFunc
}

// track registers a request; false if a kill switch already covers it.
func (g *Gateway) track(a *active) bool {
	g.killMu.Lock()
	defer g.killMu.Unlock()
	if g.kills.hits(a) {
		return false
	}
	if g.active == nil {
		g.active = map[*active]struct{}{}
	}
	g.active[a] = struct{}{}
	return true
}

func (g *Gateway) untrack(a *active) {
	g.killMu.Lock()
	defer g.killMu.Unlock()
	delete(g.active, a)
}

// setTool records which tool a request calls; true if a kill switch covers it (the request is then cancelled).
func (g *Gateway) setTool(a *active, tool string) bool {
	g.killMu.Lock()
	defer g.killMu.Unlock()
	a.tool = tool
	if g.kills.hits(a) {
		a.cancel()
		return true
	}
	return false
}

// ApplyKills installs a kill set: every request it covers is cancelled at once (its stream to the agent ends),
// and cached downstream credentials are dropped.
func (g *Gateway) ApplyKills(k KillSet) {
	g.killMu.Lock()
	changed := !reflect.DeepEqual(k, g.kills)
	g.kills = k
	for a := range g.active {
		if k.hits(a) {
			a.cancel()
		}
	}
	g.killMu.Unlock()
	if changed && g.Purge != nil {
		g.Purge()
	}
}

// WatchKills polls the PDP's kill switches every interval until ctx ends. Kill latency for live sessions is the
// bundle's propagation plus at most one interval. A failed read keeps the last known set.
func (g *Gateway) WatchKills(ctx context.Context, interval time.Duration) {
	for t := time.NewTicker(interval); ; {
		if k, err := g.Kills(ctx); err != nil {
			g.Log.Error("kill switch poll", "err", err)
		} else {
			g.ApplyKills(k)
		}
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// --- per-replica state (ponytail: in memory; shared store when replicas must agree on rates and taint) ---

type taint struct {
	max float64
	at  time.Time
}

// sources: the tool outputs a session read (server/tool), for memory-write provenance; same TTL as taint.
type sources struct {
	list []string
	at   time.Time
}

type window struct {
	start time.Time
	n     int
}

func (g *Gateway) taintOf(key string) float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	if t, ok := g.taint[key]; ok && g.Now().Sub(t.at) < taintTTL {
		return t.max
	}
	return 0
}

func (g *Gateway) addTaint(key string, score float64) {
	if score <= 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.Now()
	if g.taint == nil || len(g.taint) > 100000 {
		g.taint = map[string]taint{}
	}
	t := g.taint[key]
	if now.Sub(t.at) >= taintTTL {
		t.max = 0
	}
	g.taint[key] = taint{max(t.max, score), now}
}

func (g *Gateway) addSource(key, src string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.Now()
	if g.srcs == nil || len(g.srcs) > 100000 {
		g.srcs = map[string]sources{}
	}
	s := g.srcs[key]
	if now.Sub(s.at) >= taintTTL {
		s.list = nil
	}
	if !slices.Contains(s.list, src) && len(s.list) < 32 {
		s.list = append(s.list, src)
	}
	g.srcs[key] = sources{s.list, now}
}

func (g *Gateway) sourcesOf(key string) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if s, ok := g.srcs[key]; ok && g.Now().Sub(s.at) < taintTTL {
		return slices.Clone(s.list)
	}
	return nil
}

func (g *Gateway) overRate(key string, limit int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.Now()
	if g.rates == nil || len(g.rates) > 100000 {
		g.rates = map[string]window{}
	}
	w := g.rates[key]
	if now.Sub(w.start) >= time.Minute {
		w = window{start: now}
	}
	w.n++
	g.rates[key] = w
	return w.n > limit
}

// --- helpers ---

func (g *Gateway) hmac(s string) string {
	m := hmac.New(sha256.New, g.Pepper)
	m.Write([]byte(s))
	return hex.EncodeToString(m.Sum(nil))
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // only ever called on values decoded from JSON or built here
	}
	return b
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
