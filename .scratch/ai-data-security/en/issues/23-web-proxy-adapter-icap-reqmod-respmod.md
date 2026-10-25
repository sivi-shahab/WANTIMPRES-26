<!-- source-sha256: 9e89677c04648ccd -->
# 23: Web proxy adapter (ICAP REQMOD/RESPMOD)

Status: deferred
Type: task
Priority: P1
Milestone: M3+
Blocked by: 01, 08, 11, 35 (rilis produksi)
Spec: `../spec.md` §5.4; §11; §17 risiko TLS

## Context
Inline coverage without an extension, using the existing SWG (depends on the decision in ticket 01).

## Scope
- ICAP adapter for requests and responses to AI domains.
- Parsing of common GenAI API/web payloads.
- Policy to block QUIC/HTTP3 to AI domains.
- Device/network context from the SWG.

## Acceptance criteria
- [ ] Test with the bank's target SWG.
- [ ] Overhead within the §13.1 budget.
- [ ] Fail mode configured.
- [ ] DPIA requirement (ticket 35, R9): the adapter only processes AI catalog domains; the SWG bypasses TLS inspection for sensitive categories (personal banking, health).

## Notes on ADR-0001
Deferred to M3+ (DEC-5). Re-evaluated after [ASM-5] the SWG/CASB/DLP inventory is verified: proceed if the vendors lack this capability, cancel if they already have it (vendor events are consumed via ticket 15).
