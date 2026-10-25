<!-- source-sha256: e705bef528dca42b -->
# 49: Put detection-svc (L2) in the PEP path with a timeout and L1 fallback

Status: needs-triage
Type: task
Priority: P1
Milestone: M1
Blocked by: 09, 10
Spec: `../spec.md` §5.2; §9.2; §13.3 (detection timeout default 150 ms → L1 result only); finding from ticket 21 (`docs/nfr/m1-report.md`)

## Context
Chaos in ticket 21: shutting down detection-svc has no effect at all on the AI gateway (p95 24 ms, 100% 200). The reason is that the gateway (and the MCP gateway) runs L1 in-process through `internal/inspect` and does not call detection-svc at all. As a result, the L2 models of tickets 09/10 (NER, injection classifier, shadow mode) never see PEP traffic, the 150 ms timeout of §13.3 has never been tested, and shadow mode produces no data for the release gate of §9.4.

## Scope
- The PEP calls `POST /scan/text` on detection-svc (mTLS, ticket 40) with a 150 ms time limit; when it is exceeded or fails, the in-process L1 result still applies and `detection_fallback_total` increments.
- Compute the additional overhead against the §13.1 budget (p95 ≤ 80 ms) with `deploy/nfr/measure.sh` after the L2 model is mounted.
- The L2 shadow report goes into the decision event (for the §9.4 gate).

## Acceptance criteria
- [ ] Gateway traffic produces an L2 score (shadow) in the decision event.
- [ ] detection-svc down/slow: the gateway stays within the latency budget and uses L1 (chaos test).
