<!-- source-sha256: cda5f65fa0b41687 -->
# 20: Posture dashboard v1

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 16, 17, 18
Spec: `../spec.md` §4.11 FR-COMP-5; §1.5

## Context
The CISO needs a view of posture and trends.

## Scope
- Posture score per domain (discovery, data, prompt, agent, policy hygiene) + 90-day trend.
- Top risks, top shadow AI apps, exceptions about to expire.
- Success metrics from §1.5 that can already be measured in M1.

## Acceptance criteria
- [x] Dashboard is accessible according to RBAC (CISO read-only). *(`GET /posture` requires `dashboard.read`; the route × role matrix (ticket 06) covers it; test: the `ciso` role holds only `*.read` permissions.)*
- [x] Dashboard figures match direct queries to the analytics store (reconciliation test). *(`TestReconciliation`: fixture events in OpenSearch + Postgres data; every domain numerator/denominator, the 90-day trend total, open incidents, MTTD, hygiene, shadow AI are matched against DSL/SQL queries written separately in the test, and against the fixture values. Mutation check: removing `redact` from the "protected" actions makes the test fail.)*

## Decisions
- `GET /posture` API (JSON); the UI follows together with the admin UI. Each domain score is returned together with its numerator, denominator, and definition, so it can be inspected. Denominator 0 = score `null` (unknown), not 100.
- Formulas (the spec gives none):
  - discovery = AI events in the last 30 days to apps whose status the bank has already decided / all AI events;
  - data = sensitive events (has a class, or confidential/restricted) that were block/redact/tokenize/quarantine/approval / all sensitive events;
  - prompt = injection/jailbreak attempts (score ≥ 0.8) that were block/quarantine/approval / all attempts;
  - agent = agent events from registered agents / all agent events (not sent = not registered);
  - policy hygiene = time-bound controls that are healthy / all (active exceptions not expiring within ≤ 7 days, catalog review not overdue, incident not past ack SLA).
  - overall = average of the domains that have data.
- 90-day trend per day from OpenSearch for the 4 event-based domains (same aggregation as the summary); hygiene is only a point-in-time value for now.
- Top risks: most severe open incidents + apps with the most sensitive events. Shadow AI: apps in use whose status has not been decided (including those outside the catalog). AI inventory: count per status, offshore-without-OJK flags, overdue reviews, apps outside the catalog.
- §1.5 metrics measurable in M1: top-100 apps that have been given a status; MTTD of critical incidents (first event → incident). The rest are reported as `not_measured` with the ticket that measures them.

## Local verification results (2026-10-03)
- Entire suite `-race` with all integration services; golangci-lint clean; image built.

## Remaining / follow-up
- Dashboard UI (admin UI) and daily snapshots for the policy hygiene trend.
- Score weights/thresholds need to be confirmed with the CISO; the formulas are in `internal/posture/posture.go` (`Def*`).
- The discovery domain uses the current set of "decided" apps for the whole trend (not historical status).
