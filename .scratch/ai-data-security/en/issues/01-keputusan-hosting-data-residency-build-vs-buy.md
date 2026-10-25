<!-- source-sha256: 66f34c08996a50a0 -->
# 01: Hosting decision, data residency & build-vs-buy

Status: done
Type: grilling
Priority: P0
Milestone: M0
Spec: `../spec.md` §18 U3, U4, U7, U11; §19 DEC-5; §10.2

## Context
Three things are still undecided: the hosting location, data residency, and whether the AI modules in the SWG/CASB/DLP the bank already owns are sufficient (build vs buy). All three lock in the M1 architecture.

## Scope
- Inventory the SWG/CASB/DLP products the bank already uses, with the capabilities of their AI modules (prompt/response inspection, MCP, shadow AI).
- Decide on-prem DC vs an Indonesian cloud region (U3) and confirm there are no offshore components (U4, POJK 11 Article 35).
- Decide the build scope: full, or focused on AI Gateway + MCP Gateway + local detectors + compliance (DEC-5).
- Confirm single-tenant internal (ASM-4).

## Acceptance criteria
- [x] The decision is recorded as an ADR in `docs/adr/`.
- [x] Spec §18 (U3, U4, U7, U11) and §19 are updated with the decision outcome.
- [x] Tickets affected by build-vs-buy are annotated (kept, merged, or canceled).

## Results
Decided on 2026-10-02, see `docs/adr/0001-hosting-residency-build-scope.md`: ASM-5 (the vendor inventory is assumed to have no active AI modules, must be verified), DEC-5 core focus, U3 on-prem DC + the bank's DRC (cloud-portable), U4 no offshore components and offshore LLMs governed via the catalog + policy, U11 single-tenant tenant-aware.
