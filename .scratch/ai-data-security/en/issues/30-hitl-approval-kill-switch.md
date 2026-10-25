<!-- source-sha256: 83a09fefa0447797 -->
# 30: HITL approval & kill switch

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M3
Blocked by: 28
Spec: `../spec.md` §4.8 FR-AGT-6, FR-AGT-7; §8.6

## Context
High-risk agent actions need a human, and there must be an emergency button.

## Scope
- `APPROVAL_REQUEST` with a preview of the action and parameters (redacted according to entitlement); timeout → deny.
- Approval channels: UI + notification (email/chat).
- Kill switch per agent/tool/app/global: revoke tokens, cut sessions, push a policy block.

## Acceptance criteria
- [x] Kill switch effective in ≤ 10 s (measured). *(Two parts, both measured. `agents.TestKillSwitchPropagation` (Postgres + releaser + bundle server + real OPA via SDK long-poll, 10 agent/global kills): kill commit → OPA blocks p50 171 ms, max 187 ms. `mcpgw.TestKillSwitch`: kill at the PDP → a running SSE session is cut within ±0.99 s (poll 1 s), new requests get 403. Worst-case total ±1.2 s.)*
- [x] Expired approval → action rejected. *(`agents.TestApprovals`: an approval that was granted but not used by the deadline cannot be claimed; approving after the deadline → 410 and the request becomes `expired`; a retry afterwards opens a new request. `mcpgw.TestApprovalFlow`: an approval older than 15 minutes → the call is still rejected, the tool is not executed.)*
- [x] An approver cannot approve a request from their own agent. *(The store rejects with `errSelf`; API `TestHITLAndKillAPI`: owner → 403, approver outside their binding's business unit → 403, role without `agent.approve` → 403, duplicate decision → 409.)*

## Decisions
- **HITL flow without holding the connection**: when the PDP decides `require_approval`, the gateway opens an approval request on the control-plane and then answers the agent with a JSON-RPC error containing `approval_id`, `state`, and `expires_at`. The agent calls again with the same arguments. The approval is bound to (agent, server, tool, SHA-256 of canonical arguments) and is single-use. The gateway *claims* it before asking the PDP, then sends `agent.approval_granted`. The PDP treats it as a one-time exception only for the `require_approval` rule, which is reported in `exempted_rules`. Stricter rules (scope, kill, secret) and redaction still apply. The `tool_call` event carries `approval_id`. An approval that is claimed but then blocked by another rule is also burned.
- An identical request while one is still open returns the same request, so agent retries do not flood approvers. Default TTL 15 minutes (`APPROVAL_TTL`). Timeout = deny, both for requests that have not been decided and for approvals that have not been used.
- **Preview "redacted according to entitlement"**: the approver sees the full parameters except `SECRET.*` and `PCI.*`, which are redacted by the gateway. Raw arguments never leave the gateway and are not stored; the control-plane receives only the preview and the digest. Rationale: the right to approve includes seeing what is being approved (e.g. the destination bank account number), but no decision needs a secret or a card number.
- **Approver**: new permission `agent.approve`, role `agent_approver` (plus break_glass), limited to a business unit via ABAC. The agent's owner cannot approve its agent's actions. Approve/reject are audited.
- **Notification**: chat webhook (`APPROVAL_WEBHOOK_URL`, `{"text"}` format for Teams/Slack/Mattermost) after commit, containing the agent, tool, reason, deadline, and link; no arguments. UI = API `GET /approvals`, `GET /approvals/{id}`, `POST /approvals/{id}/approve|reject`.
- **Kill switch**: the `agents.kills` table (one active per scope/target, history retained) is released as `data.wantimpres26.kills`; the rule `tpl.kill-switch` (`KILL_SWITCH`) blocks all agent actions for an agent, tool (name), app (destination app_id), or global. An approval cannot lift a kill. The gateway polls the kill set every 1 s and:
  - cuts running requests that are covered (context cancelled, the SSE stream to the agent ends);
  - rejects all requests from the killed agent/app with 403, including `initialize`/`tools/list` (the agent token is effectively revoked at the gateway);
  - drops the downstream exchanged-token cache every time the kill set changes.
- **Kill rights**: an owner can kill their own agent (`POST /agents/{id}/kill`, `agent.write` + unit); the SOC can kill any agent/tool/app (`POST /kills`, `incident.write`); global only via `POST /kills/global` with `agent.kill.global` (sensitive: step-up + justification). Lift via `POST /kills/{id}/lift`, and for global `POST /kills/global/{id}/lift`. All are audited and cut a policy release in the same transaction. Spec §8.6 puts `scope` in the body; here it is split per route because the permissions differ.
- Gateway service endpoints (own token): `POST /mcp/approvals/request` and `POST /mcp/approvals/claim`, alongside `/mcp/tools/observed`.

## Local verification results (2026-10-04)
- `go test -race ./...` including Postgres integration green; Rego 50/50; AgentDojo suite still 100% → 5.0%; golangci-lint 0 issues; `control-plane` and `mcp-gateway` images build.

## Remaining / follow-up
- Revocation at the IdP: disable the agent client in Keycloak (admin API) on agent kill, so the token cannot be used anywhere other than the gateway. Currently revocation is effective at the gateway (the only path to tools).
- Console UI for approvers (currently API + link in the notification). Email notification (SMTP) does not exist yet; the webhook is best-effort with no outbox.
- Second-level approver (4-eyes) for very large amounts; rules for who approves per tool/amount.
- Kill per tool by tool name across all servers; kill per MCP server via the app scope (the server's `app_id`).
- Rate limit, taint, and kill set are per gateway replica; the kill set is consistent across replicas via the bundle.