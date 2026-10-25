<!-- source-sha256: 1582061099bc1f03 -->
# 22: Browser extension: prompt/paste/upload + coaching

Status: deferred
Type: task
Priority: P1
Milestone: M3+
Blocked by: 08, 11, 16, 35 (rilis produksi)
Spec: `../spec.md` §4.2 FR-SHADOW-2, FR-SHADOW-5; §4.6; §5.4

## Context
Capture public GenAI usage in managed browsers.

## Scope
- Chrome/Edge extension (managed deployment) to intercept prompt submit, paste, and file upload on catalog AI domains.
- Detection of corporate vs personal account context.
- Warn/coach (with justification), redact, and block actions, plus a sanctioned-alternatives page.
- Daily contract tests against the major vendor UIs.

## Acceptance criteria
- [ ] E2E test on at least the top 5 GenAI apps from the baseline (ticket 03).
- [ ] User justification is recorded as an event.
- [ ] The extension sends no raw content to anything other than the internal detection-svc.
- [ ] DPIA requirement (ticket 35, R3/R8): user justification is length-limited and passes through the detectors before being stored; personal accounts have no forensic capture unless the DPO approves otherwise.

## Notes on ADR-0001
Deferred to M3+ (DEC-5). Re-evaluated after [ASM-5] the SWG/CASB/DLP inventory is verified: proceed if the vendors lack this capability, cancel if they already have it (vendor events are consumed via ticket 15).
