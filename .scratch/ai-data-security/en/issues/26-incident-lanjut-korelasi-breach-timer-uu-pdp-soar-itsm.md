<!-- source-sha256: 020ec87c662d4112 -->
# 26: Advanced incident: correlation, UU PDP breach timer, SOAR/ITSM

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M2
Blocked by: 18, 19
Spec: `../spec.md` §4.10 FR-INC-1, FR-INC-5, FR-INC-6; §11

## Context
Complete incidents for regulatory and automation needs.

## Scope
- `trace_id`/agent-session-based correlation into a single chain incident.
- Breach workflow: 3×24 hours (72 hours) timer + report draft (data exposed, when/how, handling) per Article 46 of Indonesia's Personal Data Protection Law (UU PDP, Law No. 27/2022).
- Containment actions API.
- ServiceNow/Jira SM integration + SOAR webhook.

## Acceptance criteria
- [x] A breach report draft can be generated ≤ 24 hours from detection (§1.5 metric). *(The draft is available from the moment the timer starts (at detection), built on demand from redacted evidence. The first draft is recorded (`breach_drafted_at`, audit `incident.breach.draft` with `hours_since_detection`) as a metric. `TestBreachWorkflow`: draft 1.5 hours after detection.)*
- [x] Escalation alert when the remaining timer < 24 hours. *(Sweep every minute: once per incident, severity → critical, audit `incident.breach.escalate` (SIEM severity 9) forwarded to the SIEM and the SOAR webhook. Metrics `breach_timer_remaining_hours` and `breach_timers_running`. Test: no escalation at 25 hours remaining, escalation at 23 hours remaining, not twice.)*
- [x] ITSM integration test. *(`TestITSM`: mock ServiceNow Table API and Jira SM request API servers check path, auth, fields, severity → urgency/impact mapping, id correlation, no raw content, one ticket per incident, and an ITSM error is not recorded so it can be retried.)*

## Decisions
- **Chain correlation (FR-INC-1):** an event with a `trace_id` that already has an open incident (its event within the 30-minute sliding window) joins that incident, whatever its dedup key. At the MCP gateway one trace = one agent session. An empty/zero trace is not correlated. An advisory lock per trace and then per key (fixed order) prevents duplicate incidents.
- **Automatic breach (FR-INC-6):** the timer starts on an *outbound* event carrying personal data: direction is not `response`, action `allow`/`warn`, and a `PII*`, `PCI.*`, `FIN.*`, or `PHI*` class is present. Events that were blocked/redacted/tokenized do not count, nor do secrets (not personal data). Start = detection time, deadline = +72 hours. Severity rises to at least `high`. "Confirmed" is interpreted conservatively: the timer runs automatically, then the DPO closes it as `notified` or `dismissed` (with a note, audited, `compliance.write`). The SOC can `declare` manually (with a note) for leaks outside a PEP.
- **Report draft** (`GET /incidents/{id}/breach/report`, JSON or `?format=md` in Indonesian following the letters of Article 46 paragraph (2)): (a) personal data classes, general/specific types (Article 4), number of values and events; (b) first/last exposed, detection time, channel, destination, number of users (pseudonymous), agents, and timeline; (c) status transitions and containment actions. Affected subjects: evidence only stores classes and counts, so what is reported is an upper bound, marked "cannot be determined", with a pointer to justified unmask.
- **Containment (FR-INC-5)** `POST /incidents/{id}/actions` (`incident.write`; also the entry point for SOAR playbooks via a service account). Every action is recorded on the incident and audited, and goes into the report draft.
  - `block_access`: block principal → app only for the pairs present in the incident's events (default 72 hours, max 30 days), via the `data.wantimpres26.containment` document in every policy release. The PDP enforces it outside the rule set, so it cannot be lifted by a policy edit or an exception. Lift: `POST /incidents/{id}/blocks/{bid}/lift`.
  - `kill_switch`: agent/tool/app (registry, ticket 30). This is the form of "revoke agent token": the PDP blocks all its actions and the MCP gateway cuts its session. Global kill still goes through `POST /kills/global`.
  - `revoke_share_link`: a data-at-rest remediation request (requires `data.remediate`, then 4-eyes approval FR-DATA-6).
  - `open_ticket`: ServiceNow (`ITSM_KIND=servicenow`) or Jira SM (`jira-sm`). One ticket per incident; contents are metadata only.
- **SOAR webhook:** an additional sink in siem-export (`SOAR_WEBHOOK_URL`, `SOAR_WEBHOOK_SECRET_FILE`) that only forwards `incident.*` audit records (open, escalate, breach, contain). Signed with HMAC-SHA256 over `timestamp.body`. Retry, DLQ, and cursor use the existing SIEM path, so no new outbox.

## Local verification results (2026-10-10)
- `go vet ./...` + `go test -race ./...` with Postgres 17 green (including the Rego tests via `policysvc`). golangci-lint v2.5.0: 0 issues.
- The `store_test` fixture now uses a random trace per event (previously constant, which would now chain all events together).
- Note: `opa test` CLI 1.4.2 fails `test_invalid_input_fails_closed` on HEAD as well (version differs from the pinned library). The authoritative checker remains `TestRegoPolicies`.

## Remaining
- Forced credential reset (FR-INC-5) does not exist yet because there is no IAM/secrets integration. For now via `open_ticket` to the IAM team.
- Data-at-rest connector events (public share links containing personal data) do not yet trigger the automatic timer. For now use `declare`.
- ITSM tickets are not synced back (ticket status → incident).
- The incident row stays locked during the ITSM call (≤ 30 seconds), marked `ponytail:` in `contain.go`.
- Test with the bank's real ServiceNow/Jira SM instance, including request types and mandatory fields that admins may have added.
