<!-- source-sha256: 8aca16522772132e -->
# 18: Basic incident management

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 15, 17
Spec: `../spec.md` §4.10 FR-INC-1..4, FR-INC-7; §8.5

## Context
The SOC needs a place to triage.

## Scope
- State machine (FR-INC-3) and severity from the score.
- Dedup `(principal, destination, class, policy_id)` within a 30-minute window.
- Redacted evidence; raw only if `forensic_capture` is active (encrypted per incident, unmask with justification).
- Acknowledge SLA timer (critical ≤ 15 minutes, high ≤ 1 hour).
- Incidents API + transition.

## Acceptance criteria
- [x] Tests for valid and invalid state transitions. *(All 36 state pairs; labeled edges (duplicate, false positive, reopen) require a note; via the API: 409 for invalid transitions, 403 without `incident.write`.)*
- [x] Dedup window tests. *(Postgres: ≤ 30 minutes from the last event joins, 31 minutes opens a new incident; other principal/class stays separate; a Resolved incident does not accept events; redelivery is a no-op; risk < 40 ignored.)*
- [x] Unmask access without permission/justification is rejected and recorded. *(403 + `evidence.unmask.denied` entry in the audit log; legitimate access is also recorded before decryption; audit chain remains verifiable.)*

## Decisions
- `internal/incident` module in the control-plane (DEC-3), Postgres schema `incident`, its own consumer group `incident` on the decision_event topic. Event validation is shared with event-ingest (`events.Decoder`).
- Incidents are created only from events with `risk_score ≥ 40`. Severity = FR-INC-2 from the highest risk, raised automatically when a riskier event arrives, raised manually via the API, cannot go down.
- Dedup key = principal (HMAC), app, set of classes, set of matched rules (replacing `policy_id`, which is constant). Sliding window: an event joins if it is within 30 minutes of the event of a still-open incident. A per-key advisory lock prevents duplicate incidents.
- Ack SLA: critical 15 minutes, high 1 hour, counted from opening or escalation (whichever is stricter). Ack = leaving New. Gauge `incident_ack_overdue` + alert.
- Evidence: the redacted event is stored as is. Raw (forensic_capture only) is encrypted with AES-256-GCM using a per-incident DEK wrapped by a KEK, bound to the incident/evidence id (AAD), deleted after 30 days.
- Transitions and severity changes are written to the audit log in the same transaction (`audit.AppendTx`). Unmask is audited before the plaintext is returned; if the audit fails, no plaintext is returned.
- Temporary auth: headers from an authenticated proxy, only when `AUTH_MODE=trusted-proxy`; other modes reject all requests.

## Local verification results (2026-10-03)
- Unit + Postgres integration pass with `-race`; the whole suite (audit, events, ingest, policysvc) also passes; golangci-lint and trivy config clean.
- E2E control-plane image + Kafka + Karapace + Postgres: 3 events (risk 72, 95, 50) → one critical incident, 3 events, ack deadline; the risk 10 event is ignored.

## Remaining / follow-up
- ~~SSO/RBAC and re-auth for `evidence.unmask` (ticket 06) replace the proxy header.~~ Done in ticket 06; raw evidence is now at `…/evidence/{eid}/raw`.
- No caller of `AddRawEvidence` yet: PEP with forensic_capture (ticket 13). Move ciphertext to object storage if volume is large.
- KEK from KMS/HSM; the `control-plane` and `incident-kek` Secrets are provisioned outside git.
- Kafka topics are created by the platform team (the client does not auto-create).
- MTTD/MTTR, containment actions (FR-INC-5), `trace_id` correlation: ticket 26.

## Out of scope
Cross-session agent correlation, breach timer, and SOAR/ITSM (ticket 26).
