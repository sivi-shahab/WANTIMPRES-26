<!-- source-sha256: 2c71f8da41fdaca2 -->
# 29: MCP: tool description scan & rug-pull detection

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M3
Blocked by: 28
Spec: `../spec.md` §4.8 FR-AGT-3 (tool poisoning); §15 Adversarial

## Context
Tool poisoning through tool descriptions or silent changes after approval.

## Scope
- Scan tool descriptions, metadata, and schemas at registration (injection detector + rules).
- Pin the description hash; a change triggers `under_review` status and re-approval.
- Risky-tool report per MCP server.

## Acceptance criteria
- [x] Test with MCPTox-style samples. *(`internal/mcptools` `TestScanMCPToxStyle`: 25 poisoned definitions covering the three MCPTox paradigms (explicit trigger–function hijacking, implicit trigger–function hijacking, implicit trigger–parameter tampering) with the goals of privacy leakage, message hijacking, data tampering, and unauthorized action, the Invariant Labs `<IMPORTANT>` pattern, EN/ID, and obfuscation (homoglyph, zero-width, base64, payload only in the schema, embedded secret). **25/25 flagged (14 high)**. 20 benign definitions in the style of popular MCP servers (filesystem, GitHub, Slack, Postgres, fetch) and bank tools: **0 flagged**. Note: the samples were written in-house to imitate the dataset; they are not the real MCPTox dataset. Re-measure against the real dataset when available.)*
- [x] Description change → tool cannot be called until re-approved. *(Postgres `TestToolPinning`: clean v1 → pinned/approved; v2 (rug pull) → `under_review` and the latest-release PDP blocks with `TOOL_NOT_APPROVED` regardless of which hash the replica saw; approving with a stale hash is rejected, risky definitions require a note; even an honest fix from the vendor needs explicit approval; after approval → allow. Gateway `TestRugPull` (JSON and SSE): the changed tool immediately disappears from `tools/list` (the poisoned text never reaches the model) and `tools/call` is blocked **before** the bundle release arrives (observed hash ≠ pin), including on replicas that have not yet seen it after the release; other tools keep working; re-approval restores it. A mutation test (Rego hash check disabled) makes the test fail.)*

## Decisions
- **Pin** = SHA-256 of the canonical JSON of the whole tool object from `tools/list` (`mcptools.Hash`): name, description, input/output schema, annotations, `_meta`. Any change is a new definition.
- **Inventory** in the agent registry (`agents.mcp_tools`, Postgres): last definition seen, scan result (score, risk, signals), status `approved | under_review | rejected`, `approved_hash`. A new clean definition (risk low) is pinned and approved immediately by `mcp-gateway`; flagged ones go to `under_review`. Any definition change (rug pull or honest update) → `under_review` until re-approved. Approval requires the definition hash that the reviewer saw (prevents TOCTOU). Risky definitions and rejections require a note. Every registration, change, approval, and rejection is audited and cuts a policy release in the same transaction. An unchanged observation only updates `last_seen`.
- **Reporting**: the gateway sends every `tools/list` response to `POST /mcp/tools/observed` on the control-plane. This is a public route with its own bearer token (stored as SHA-256, SCIM pattern), so the public route matrix grows. A per-server advisory lock prevents two replicas from recording the same change twice.
- **Two-layer enforcement**: (1) the gateway forwards only tools that are callable according to the registry's answer, falling back to the pin in the bundle (`wantimpres26/mcp.tools`) when the registry is unreachable; with neither, no tools are shown. (2) PDP: `tpl.mcp-tool-not-approved` blocks `tools/call` whose status is not approved or whose `tool_hash` last seen by the gateway ≠ pin (`data.wantimpres26.mcp_tools`). The second layer closes the bundle release gap. It applies only when `agent.mcp_server` is present, so tool calls outside the gateway are unaffected.
- **Scanner** (`internal/mcptools`): all definition strings (including schema property names, enums, defaults) are scanned with the ticket 28 injection detectors (except `tool_steering`, because tool documentation legitimately mentions other tools) plus metadata-specific rules: `sensitive_path`, `cross_tool` (shadowing/hijacking other tools), `param_tamper`, `concealment`, `directive_tag` (`<IMPORTANT>`), and embedded secrets. Score = 1 − Π (1 − w): ≥ 0.7 high, > 0 medium, 0 low.
- The `decision_event` event (and the OpenSearch mapping) gains `mcp_server` and `tool_hash` so policy simulation can replay this decision.
- Also fixed in detection: the rule `before answer…` now requires "before you…", because "Before answering policy questions, prefer…" is ordinary prose (false positive in content and tool descriptions).

## API
- `GET /mcp/tools?server=&status=` and `GET /mcp/tools/report` (report per server: tools, callable, under_review, rejected, changed, high/medium risk), with the `agent.read` permission.
- `POST /mcp/tools/{server}/{name}/approve {hash, note}` and `.../reject {note}`, with the `config.write` permission (security_admin, break_glass).

## Local verification results (2026-10-03)
- `go test -race ./...` including Postgres integration green; Rego 48/48; AgentDojo suite still 100% → 5.0%; golangci-lint 0 issues; `control-plane` and `mcp-gateway` images build.

## Remaining / follow-up
- Measure the scanner on the real MCPTox dataset; L2 classifier (ticket 10) for poisoned descriptions that do not use known patterns (auto-approve at registration depends on the scanner).
- Notification to reviewers (SOC/security_admin) when a tool is `under_review`; metric `mcp_tools_under_review`.
- A tool that was never listed before being called is blocked (`TOOL_NOT_APPROVED`) until `tools/list` + bundle release; standard MCP clients always list first.
- Prompts and resource templates (`prompts/list`, `resources/list`) are not pinned yet.
- The per-agent tool allow-list is still by name; definitions are bound per server, not per agent.