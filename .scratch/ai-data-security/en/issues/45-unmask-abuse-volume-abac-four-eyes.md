<!-- source-sha256: ddbd37aee0107763 -->
# 45: Evidence unmask abuse controls: volume alert, ABAC, four-eyes

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M2
Blocked by: 18
Spec: `../spec.md` §10.1 AuthZ (ABAC); FR-INC-4; `docs/threat-model.md` §4.5, G6

## Context
Threat model (ticket 02) G6: unmask already requires a permission, step-up, justification, and is audited. However, there is no per-analyst volume/pattern detection, the check uses an empty `authz.Resource{}` (ABAC unit/region does not restrict), and there is no four-eyes for `restricted` evidence.

## Scope
- Alert when unmasks per analyst exceed a threshold per day, or repeatedly target the same principal.
- ABAC: the incident's business unit/region attributes are compared with the analyst's attributes.
- `restricted` evidence: unmask requires approval from a second analyst.

## Acceptance criteria
- [x] An analyst outside the incident's unit/region is rejected (test), and the rejection is audited. *(`TestUnmaskABACAndFourEyes`: a DPO with the binding `business_units: [treasury]` is rejected with 403 for an incident `bu:retail`/`region:jakarta`, whereas a retail DPO succeeds. A DPO with `confidential` clearance is rejected for a `restricted` incident. Every rejection is recorded as `evidence.unmask.denied` (or `.request.denied` / `.approve.denied`) along with the reason.)*
- [x] A volume alert for unmask in `deploy/cluster/alerts.yaml` with a metric test. *(`UnmaskVolumeHigh` (> 20 unmasks per analyst in 24 hours) and `UnmaskSamePrincipalRepeated` (≥ 5 unmasks about the same principal in 24 hours), from the gauges `evidence_unmasks_24h{analyst}` and `evidence_unmask_same_principal_24h{analyst}` on the control-plane `/metrics`. `TestUnmaskVolumeMetric`: 8 unmasks, 6 of them about the same person, produce gauges 8 / 6. Rejected unmasks are not counted. The test also ensures the alert expr reads those gauges. Also tested with `promtool test rules` (local, see below).)*
- [x] Unmasking `restricted` evidence without a second approver is rejected. *(Rejected without an approved request. A requester cannot approve their own request. An approver outside the unit is rejected. An approval that has already been used, an approval belonging to someone else, and an approval older than 1 hour are not valid. A granted unmask records the `request` and `approver` in the audit.)*

## Decisions
- **Incident ABAC attributes:** business unit and region are taken from the IdP groups of the principal included in the event, with the convention `bu:<unit>` and `region:<region>` (mapped by the IdP/SCIM admin). The first value seen is used for the incident. Incident sensitivity = the most sensitive content among its events. An incident without `bu:`/`region:` groups is not restricted on those attributes, following the semantics of `authz.Attrs.Covers` (an empty attribute on the resource = not applicable). Reason: the principal in the event is an HMAC, and no other directory in the platform maps principals to units.
- **Check:** `Unmask`, `RequestUnmask`, and `ApproveUnmask` use a single function `mayUnmask`: permission, then ABAC against the incident's `authz.Resource{BusinessUnit, Region, Sensitivity}` (the binding clearance also applies), then justification. The router still checks permission and step-up with an empty resource. The resource check is done in the store, because the incident is only known there.
- **`restricted` four-eyes** (`POST /incidents/{id}/evidence/{eid}/unmask-requests`, then `POST /incidents/{id}/unmask-requests/{rid}/approve`, both `evidence.unmask` with step-up and justification): one approval is valid for one unmask by the requester, at most 1 hour. The approval is consumed in the same transaction as the grant audit. "Restricted" is determined per incident, because raw evidence has no sensitivity label of its own.
- **Volume metric:** computed from the audit log (`evidence.unmask` granted, 24 hours), joined with the principal in the incident events. The threshold is in the alert rule, not in code.
- `authz.sensitivityOrder` is exported as `authz.Sensitivities` (also used by the incident sensitivity query).

## Local verification results (2026-10-10)
- `go vet ./...` clean. golangci-lint v2.5.0: 0 issues. `go test -race ./...` with Postgres 17: all packages green except `mcpgw TestKillSwitch`. That test failed on timing (session cut off in 4.9 seconds, test limit 2 seconds) when the host load average was ~54 (several parallel workers); the `mcpgw` package is not touched by this ticket. `policysvc` timed out once in the full run, but passed when rerun on its own.
- `promtool test rules` (prom/prometheus v3.5.0) for both alerts, with a copy of the rules in plain format: SUCCESS. CI does not run promtool yet.

## Remaining
- The `bu:`/`region:` group convention must be agreed with the IdP team. Without those groups, ABAC does not restrict incidents.
- A sensitivity label per evidence item (not per incident) if forensic capture later stores several kinds of content.
- Notifications to prospective approvers (chat/email) for four-eyes requests. For now the request is visible in the incident detail (`unmask_requests`).
- Rerun `mcpgw TestKillSwitch` in CI (a runner without parallel load).
