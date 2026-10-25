<!-- source-sha256: 5db412946489d7da -->
# 12: Policy lifecycle: versions, 4-eyes, simulation, rollback, exceptions

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 11, 15
Spec: `../spec.md` §4.7 FR-POL-5..7; §8.3

## Context
DLP admins must be able to change policy safely.

## Scope
- State `draft → simulated → pending_approval → active → retired`; author ≠ approver.
- Simulation against 7–30 days of events + the corpus, with a decision diff (`POST /policies/{id}/simulate`).
- Monitor-only mode per rule.
- Rollback to the previous version in 1 action.
- Exceptions with mandatory scope, approver, and expiry (default max 90 days), notification 7 days before expiry.

## Acceptance criteria
- [x] Publish/rollback propagation to all PEPs ≤ 60 s p99. *(`TestPropagation`: 2 replicas + OPA SDK (the same bundle plugin as the sidecar) long-polling replica B; 22 releases (publish, exception on/off, retire): p50 0.76 s, p99 0.80 s.)*
- [x] Publish without a second approver is rejected. *(Author = approver → 403, also with different letter case; exception: requester = approver rejected.)*
- [x] An exception without `expires_at` is rejected. *(Also: already past, > 90 days, empty/unknown scope, rule not in the active release, no reason.)*
- [x] All transitions are recorded in the audit log. *(Create, edit, simulate, simulate.done, submit, reject, approve, rollback, retire, exception request/approve/revoke/expire/expiring; in the same transaction.)*

## Decisions
- Policy = a rule set in the engine DSL (not raw Rego). Versions: `draft → simulated → pending_approval → active → retired`; editing after simulation returns to draft; submit only from `simulated`; reject returns to draft. One active version per policy (unique index).
- **Release**: every approve/rollback/retire/exception takes a snapshot of all active rules + active exceptions as a numbered release (`policy_version = release-N` in decisions and events). The release is validated by the engine before it exists (rule id conflicts across policies, unknown op → the whole change is canceled).
- Every control-plane replica builds the bundle from the latest release: Postgres `LISTEN/NOTIFY` + 15 s poll. Revision = content hash, so all replicas give the same ETag. Metric `policy_release_current` + alert if replicas differ for more than 1 minute.
- Approve/reject/rollback/retire/exception decisions = `policy.publish` (sensitive: step-up + justification). Rollback restores the previously approved version, without a second approver.
- Simulation (`POST /policies/{id}/simulate` → 202, `GET /simulations/{id}`): events from OpenSearch (default 7 days, max 30, cap 100k) are evaluated with the active vs candidate composition → diff `allow→block` etc. + 20 samples; labeled corpus (`policy/corpus/*.jsonl`, 9 template cases) → regression. For replay, `decision_event` v1 gains PDP input metadata fields (sanction, region, sensitivity, scores, principal/agent attributes); events without that metadata are counted but not replayed.
- Exceptions: scope `principal_id|group|app_id|agent_id` (AND), mandatory `expires_at` ≤ 90 days, 4-eyes, included in the bundle; Rego also checks expiry at decision time. Hourly sweep: mark expired + release, notification 7 days before = audit `policy.exception.expiring` (forwarded to SIEM, ticket 19) + metric/alert.
- Monitor-only per rule already exists in the engine (ticket 11); simulation reports it through the diff.
- PDP output adds `exempted_rules`.

## Local verification results (2026-10-03)
- `opa test` 37/37, `opa check --strict`; `go test -race ./...` with all integration services; golangci-lint clean; control-plane image built.

## Remaining / follow-up
- Self-service end user exceptions (`self.request`) and user scope by email (needs an HMAC pepper in the control-plane): not yet.
- Simulation runs on the replica that receives the request; if that replica dies, the status stays `running` (ponytail in the code).
- Direct notification to the owner (email/Slack) is waiting for a notification channel; for now it goes through audit/SIEM + alerts.
- PEPs must populate the new event metadata fields (ticket 13).
