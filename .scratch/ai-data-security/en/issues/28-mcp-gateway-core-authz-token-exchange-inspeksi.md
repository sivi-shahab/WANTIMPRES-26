<!-- source-sha256: 4daf542525520422 -->
# 28: MCP Gateway core: authz, token exchange, inspection

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M3
Blocked by: 27, 08, 11
Spec: `../spec.md` §4.8 FR-AGT-3..5, FR-AGT-8; §7.2; §8.6

## Context
PEP for agent → tool.

## Scope
- MCP Streamable HTTP proxy.
- Token validation per the MCP 2026-07-28 spec: OAuth 2.1, RFC 9728, RFC 8707 `resource`, audience.
- No token passthrough: RFC 8693 token exchange to downstream credentials with TTL ≤ 15 minutes.
- Per-client consent (anti confused deputy).
- DLP + injection scan on tool-call args, tool results, and resource reads.
- Tool allow-list + parameter constraints + rate limit + agent chain depth limit.
- Session audit `prompt → tool_call → result` with `trace_id`.

## Acceptance criteria
- [x] Test: a token with the wrong audience is rejected. *(`TestTokenValidation`: aud of another MCP server, aud of the tool server, aud of the gateway origin, no aud, expired, other issuer, ID token, foreign key, not a JWT → 401 + `WWW-Authenticate: Bearer resource_metadata=…` (`error="invalid_token"` if a token is present). The tool server and STS are untouched. Real RS256 JWTs verified by go-oidc; a mutation test (aud check disabled) makes the test fail.)*
- [x] Test: the upstream token never appears in downstream requests. *(`TestNoTokenPassthrough`: all requests to the tool server (initialize, tools/call, notification) carry the exchanged `Bearer down-N`; the agent token is in no header or body, including when smuggled via `Cookie`/`X-Forwarded-Authorization`/`Proxy-Authorization`. The exchange is cached per (subject token, audience) and not used across tokens; a downstream token > 15 minutes is rejected (502, not forwarded). A mutation test (forwarding Authorization) makes the test fail.)*
- [x] Test: indirect injection in a tool result is detected and blocked/redacted per policy. *(`TestIndirectInjection`, JSON and SSE: a result containing injection → `isError` without a single character of the original text, `tool_result` event block `INDIRECT_INJECTION` with the same trace_id as the `tool_call`; the next high tool in that trace → `INJECTION_THEN_HIGH_TOOL`, other traces unaffected; PAN in a result → `[REDACTED:PCI.PAN]`; `resources/read` is inspected too. `TestHostileToolServer`: result as string/array, injection in the JSON-RPC error message, another id, `prompts/get`, HTML error page, foreign content type: nothing gets through; these seven leaks were all caught in the version before the fix.)*
- [x] AgentDojo-style suite: ASR drops ≥ 70% vs baseline. *(`TestAgentDojoASR`: 160 cases = 4 user tasks × 5 attacker goals × 8 payload styles (AgentDojo important_instructions, ignore_previous, Indonesian, tool_knowledge, fake system turn, base64, HTML comment, stealth), a worst-case agent that obeys any instruction it reads. Baseline ASR 100% → through the gateway 5.0%: **down 95%**. The remaining 8 successes = the stealth style (does not address the AI) × 2 goals deliberately inside the registry scope (overpay an allowed payee, email an allowed address). The three out-of-scope goals 0%. Utility without attack 4/4; utility under attack 16.2% (baseline 100%) because results containing injection are blocked entirely.)*

## Decisions
- New `mcp-gateway` service (`internal/mcpgw`) with its own OPA sidecar, one path per tool server: `/mcp/{server}` (POST/GET/DELETE Streamable HTTP) and the RFC 9728 PRM at `/.well-known/oauth-protected-resource/mcp/{server}`. Server configuration (upstream, downstream audience, app_id/sanction/region for the PDP) comes from the `mcp-servers` ConfigMap.
- **Token**: signature (Keycloak realm JWKS via discovery), `iss`, `exp`, and `aud` must contain this server's resource URI (RFC 8707); `typ` other than `Bearer` (ID token) is rejected. Workload identity = `azp` → `client_id` → `sub`. Agent chain depth = nesting of the `act` claim (RFC 8693) in the AS-signed token, not a header the agent could forge.
- **No passthrough**: headers to the tool server are allow-listed (Accept, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-Id) + the `Authorization` resulting from the RFC 8693 token exchange (`subject_token` = agent token, `audience` = server audience, gateway client authentication). The exchanged token must be Bearer, not the subject token, and `expires_in` ≤ 900 seconds (FR-AGT-5), or the request fails with 502 without being forwarded. 401/403 from the tool server → 502 (downstream challenges are not the agent's business).
- **Per-client consent (confused deputy)**: the gateway does not proxy the authorization flow and does not perform dynamic client registration; MCP clients obtain tokens directly from Keycloak via the PRM. Downstream credentials are always derived from that client's own token and cached per subject token, so they are never used across clients. Per-client consent for a tool = the registry allow-list (created by the owner, audited). Delegation on behalf of a user relies on Keycloak's "Consent Required" per agent client (realm configuration).
- **Registry in the bundle**: the `data.wantimpres26.agents` release now carries `identity` and `tools[{name, risk, scopes}]`. The new package `wantimpres26/mcp` maps identity → agent. `wantimpres26/agent` computes `tool_allowed` and uses the tool risk from the registry, not the PEP's claim. An unregistered agent has no allow-list, so its `tools/call` is blocked, but the event is still recorded with its identity so it enters the shadow agent queue (ticket 27). Also fixed: `risk_tier` for unknown agents used to make the agent object undefined.
- **Scope format** (`internal/toolscope`, validated by the registry on write, enforced by the gateway): `{"<arg|a.b>": {"max", "min", "in"}, "rate_per_minute": n}`. A constrained argument that is missing or of the wrong type = violation (fail closed); numbers given as strings are accepted, NaN/Inf are not.
- **New rules** (data, changeable via the ticket 12 lifecycle): `tpl.tool-not-allowed`, `tpl.tool-scope-violation`, `tpl.tool-rate-limit`, `tpl.agent-chain-depth` (≥ 4 hops), `tpl.indirect-injection` (`tool_result` with injection ≥ 0.7 → block), `tpl.injection-then-high-tool` (injection ≥ 0.5 in the session and then a high tool → `require_approval`). The gateway sends `hitl_available=false`, so `require_approval` = deny until ticket 30. The PDP input and `decision_event` gain `scope_violations`, `rate_exceeded`, `chain_depth` (also in the OpenSearch mapping) so policy simulation can replay these decisions.
- **Session taint**: injection that is seen (in arguments or results) raises `session_injection_max` for 30 minutes, per trace if the agent propagates `traceparent` (one task across tool servers), otherwise per agent. `Mcp-Session-Id` is not used because it differs per tool server.
- **Inspection**: all leaf strings of arguments/results are joined for one `detect.Scan` pass, then redactions are mapped back per field. Inspected: `tools/call` and `resources/read` results, JSON-RPC error messages, and (on the GET/SSE stream) messages shaped like content/contents/messages. A non-object result or an unreadable response → error (fail closed). HTTP error bodies are not forwarded. JSON-RPC batches are rejected. PDP unavailable → deny.
- **L1 injection detection** (`internal/detect/injection.go`, part of `detect.Scan` and the `POST /scan/text` response): anchored EN/ID rules for instruction override (0.85), role markers (0.7), greetings/directives to the AI including AgentDojo phrases (0.6), exfil via markdown image (0.6), ASCII smuggling via Unicode tags (0.6), and tool steering (0.35, below all thresholds on its own). Score = 1 − Π(1 − w) per type, with an evidence span. Also applies under base64/hex/URL/ROT13 decoding and homoglyphs. L1 latency p95 stays ≤ 10 ms (±4.6 ms for 8K tokens).
- **Session audit (FR-AGT-8)**: every `tool_call`/`tool_result` decision = a `decision_event` (schema-validated before sending) with `trace_id` from the agent's `traceparent` (or generated) and forwarded to the tool server. Contents are metadata + content HMAC, no content. `event_id` = the `decision_id` the agent sees.

## Local verification results (2026-10-03)
- `go test -race ./...` green; Rego tests 46/46 (via `policysvc`); Postgres integration agents/lifecycle/identity/catalog green; golangci-lint 0 issues; `mcp-gateway` image built. Not yet run against real Keycloak/Kafka/OPA (needs a GitLab/cluster environment).

## Remaining / follow-up
- **Utility under attack** is low (16%) because results containing injection are blocked entirely. Alternative: redact/spotlight the evidence span (FR-PSEC-8) so the task can continue; needs a "redact injection" policy and an ASR retest.
- The stealth style (instructions that do not address the AI) inside the scope gets through: needs an L2 classifier (ticket 10) and/or HITL for high tools (ticket 30).
- ~~HITL approval and kill switch~~ (ticket 30: done).
- ~~Tool description scan / rug-pull on `tools/list`~~ (ticket 29: done); filtering `tools/list` to the agent's allow-list is not done yet.
- Server→client requests (sampling/elicitation) on the stream are not yet inspected; `resources/read` is not yet limited by an allow-list.
- Rate limit and taint are stored in memory per replica (deploy 1 replica); a shared store is needed for HA. Event send failures are only logged (no local spool yet).
- Keycloak: the `mcp-gateway` client with token exchange permission per tool server audience, a resource URI audience mapper for agent clients, and "Consent Required" for clients acting on behalf of users, as realm-as-code together with the IAM team.
- STDIO via local wrapper (P2).