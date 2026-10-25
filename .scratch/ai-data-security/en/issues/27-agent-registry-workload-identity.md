<!-- source-sha256: 31f17cd860c865f3 -->
# 27: Agent registry & workload identity

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M3
Blocked by: 06, 11
Spec: `../spec.md` §4.8 FR-AGT-1, FR-AGT-2; §6

## Context
Foundation for agent governance.

## Scope
- Registry: owner, purpose, model, tools+scopes, data scopes, risk tier, status.
- An agent without an owner is automatically `quarantined`.
- Workload identity (SPIFFE/OIDC client/managed identity); shared user credentials are forbidden.
- Review queue for shadow agents (from MCP traffic and OAuth grants).

## Acceptance criteria
- [x] The metric 'agents without owner & policy' = 0 can be measured. *(`GET /agents/summary` → `active_without_owner_or_policy`; used by posture (ticket 20) as a §1.5 metric that is now measurable. Policy = tool allow-list (FR-AGT-4); an active agent without an owner is automatically quarantined, so it is not counted as "active".)*
- [x] All registry changes are recorded in the audit log. *(`agent.register`, `agent.update` (before/after), `agent.status`, `agent.quarantine` (automatic), `agent.discovered.dismiss`, in the same transaction as the release.)*

## Decisions
- `internal/agents` module in the control-plane, schema `agents`. FR-AGT-1 fields + `business_unit` for ABAC: an agent owner can only change/register/move agents within their binding's unit (tested via the API).
- **Registry = PDP source of truth**: every change cuts a policy release containing `data.wantimpres26.agents`; `wantimpres26/agent` computes `registered` (= present in the registry and `active`) and `status`; the `registered` claim from the PEP is ignored. New template `tpl.agent-not-active`: a quarantined/suspended agent = block.
- No active owner (missing, not yet provisioned, or deactivated via SCIM) → `quarantined` with reason `no active owner`, on register/update/status and through the hourly reconcile; activation is rejected until there is an owner.
- Workload identity is mandatory (`spiffe` | `oidc_client` | `managed_identity`, format validated), one identity per agent (unique). Rejected: other types, email-shaped identities (except GCP service accounts), and identities identical to a user in the IdP (shared user credentials).
- Shadow agent queue: decision events with an unregistered `agent_id` (shared control-plane consumer); registering closes the entry, dismissing requires a note. The `events` count is approximate (redelivery is counted again).
- The control-plane now uses a single consumer group (`control-plane`) with fan-out to incident, catalog usage, and shadow agent (`events.Consume`), replacing two separate consumers.

## Local verification results (2026-10-03)
- `opa test` 41/41; Postgres integration (registry, quarantine, identity, shadow queue, summary, audit, ABAC via API, PDP decisions from a release); entire suite `-race`; golangci-lint clean; image built.

## Remaining / follow-up
- Shadow agent sources from OAuth grants (ticket 31) and endpoints (36): the `source` column already exists.
- Enforcement of the tool allow-list & parameter scope at the MCP gateway (ticket 28); runtime verification of the workload SVID/token (ticket 28).
- Hourly reconcile: a deactivated owner can remain active for up to 1 hour; speed it up if needed by triggering reconcile from SCIM changes.
