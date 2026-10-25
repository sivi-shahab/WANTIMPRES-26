<!-- source-sha256: e4a763c0fc0673f8 -->
# 44: Inspect writes to agent memory / vector store (FR-AGT-9)

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M2
Blocked by: 28
Spec: `../spec.md` §4.8 FR-AGT-9; OWASP ASI06, LLM08; `docs/threat-model.md` G5

## Context
Threat model (ticket 02) G5: there is no control yet for ASI06 (memory & context poisoning). Injected content stored in long-term memory or a vector store will be read back by the agent as trusted context.

## Scope
- The MCP gateway recognizes memory/vector store write tools (marked in the tool registry, for example `writes_memory: true`) and inspects their arguments with the injection detector + DLP before forwarding.
- Provenance: the write source (agent, trace, content origin: user/tool result/web) is recorded in the decision event.
- Content from a session tainted by injection must not be written to memory without approval.

## Acceptance criteria
- [x] A memory write containing injection is blocked or requires approval (gateway test). *(`mcpgw.TestMemoryPoisoning`: a write containing injection 0.6 is blocked with `MEMORY_POISONING` and does not reach the tool server. A session that has already read an injected email and writes a clean note → `require_approval` `MEMORY_WRITE_TAINTED_SESSION`; after human approval, the write goes through once and the event carries `approval_id`. `decision_test.test_registry_decides_writes_memory`: the marker comes from the effective registry, not a PEP claim.)*
- [x] A memory write event carries provenance. *(Every `tool_call` event to a `writes_memory` tool carries `memory_write: true`, `content_origin` (`user` = only the agent's own input in that session, `tool_result` = the session has read tool output), and `content_sources` (e.g. `bank/read_inbox`), in addition to the existing `agent_id` and `trace_id`. The test checks all three; ordinary tool calls do not carry them.)*
- [x] A synthetic poisoning scenario (write → read back in another session) is caught. *(Poison already in the store, for example written before the gateway or through another path, is read back by another session via `recall_memory`: the result is blocked with `INDIRECT_INJECTION` without a single byte reaching the agent. That session becomes tainted, so `send_money` requires approval and that session cannot write the poison back to memory without approval.)*

## Decisions
- **Marker in the agent registry**: `agents.Tool.writes_memory` (optional, default false) is part of `data.wantimpres26.agents`. `wantimpres26.agent` overrides `agent.writes_memory` from the PEP input with the registry value, the same as `tool_risk`. A tool not in the allow-list is already blocked with `tpl.tool-not-allowed`.
- **Inspection**: tool call arguments are already inspected (DLP + injection) by the gateway. What is new is two rule templates:
  - `tpl.memory-write-injection`: a memory write with `injection_score ≥ 0.5` → block. The threshold is lower than `tpl.injection-high` (0.9) because what is stored will be read back as trusted context.
  - `tpl.memory-write-tainted`: a session with `session_injection_max ≥ 0.5` writing memory → `require_approval` (without HITL = deny). Approval only lifts this rule; a block because of the content still applies.
  - DLP on arguments uses the existing rules (secret block, PAN redact, etc.).
- **Provenance**: the gateway records, per session (taint key: agent + trace), the tool output that was *forwarded* to the agent (allow/warn/redact). Blocked output is not counted because the agent did not see it. The validity period is the same as taint (30 minutes). The "web" origin is not distinguished from other tools because it is visible from its name in `content_sources` (e.g. `bank/web_fetch`).
- **New event fields** (optional, additions to `decision_event` v1 like `tool_hash`/`approval_id` before them): `memory_write`, `content_origin`, `content_sources`. The OpenSearch mapping was also extended.

## Local verification results (2026-10-10)
- `go build`, `go vet ./...`, gofmt clean. golangci-lint v2.5.0: 0 issues.
- `go test` (without race) for `mcpgw`, `policysvc` (54 Rego tests), `events`, and `agents` green.
- `go test -race ./...` green except three tests that use time thresholds: `agents.TestKillSwitchPropagation` (10.3 seconds > 10 seconds), `mcpgw.TestKillSwitch` (session cut-off > 2 seconds, including the Rego query compile), and `policysvc.TestRegoPolicies` (`test_residency_matrix` exceeded the 1-minute limit). At the time the host load average was 56–85 on 16 cores because several forks were running the race suite in parallel. On rerun, `TestKillSwitchPropagation` passed with `-race`; the other two passed without race. This ticket's changes do not touch the kill switch path. Confirmation on GitLab CI (an idle host) is needed.

## Remaining
- The new rule templates are only activated automatically in an empty database (`builtin` policy). Deployments that are already running need to add these two rules through the policy lifecycle.
- Taint and provenance are stored in memory per gateway replica, the same as taint and rate limits. A shared store is needed if replicas must agree.
- Writes to a vector store that do not go through the MCP gateway (SDK directly to the vector database) are not visible. They need to be forced through the gateway, similar to ticket 43 for LLMs.
- Rescanning the contents of existing memory/vector stores (old poison) has not been done. For now, old poison is caught when it is read.
