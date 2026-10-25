<!-- source-sha256: efe44f926c892fc9 -->
# 36: Endpoint agent (Windows/macOS)

Status: deferred
Type: task
Priority: P2
Milestone: M4 (M3+ re-eval)
Blocked by: 08, 11, 35 (rilis produksi; DPIA harus di-review ulang untuk clipboard dan app desktop)
Spec: `../spec.md` §3.1 P2; §5.4

## Context
Off-network coverage, desktop AI applications, clipboard, and local agents.

## Scope
- Lightweight agent: detect desktop AI apps and local agents (including MCP STDIO wrappers), clipboard to AI apps, files to AI apps.
- Policy from the same OPA bundle.
- EDR context integration.

## Acceptance criteria
- [ ] OS compatibility matrix passes.
- [ ] CPU/memory overhead within the agreed limits (`unspecified`, set at the start of the ticket).

## Notes on ADR-0001
Deferred to M3+ (DEC-5). Re-evaluated after [ASM-5] SWG/CASB/DLP inventory is verified: proceed if the vendor lacks this capability, cancelled if it already exists (vendor events are consumed via ticket 15).
