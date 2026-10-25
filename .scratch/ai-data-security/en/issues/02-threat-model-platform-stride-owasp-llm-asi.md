<!-- source-sha256: 24bfd78db6427c1e -->
# 02: Platform threat model (STRIDE + OWASP LLM/ASI)

Status: needs-signoff
Type: task
Priority: P0
Milestone: M0
Blocked by: 01
Spec: `../spec.md` §3.2 DoD #4; §4.5; §4.8; §14

## Context
The DoD requires a threat model per feature. A baseline threat model for the whole platform is needed before M1.

## Scope
- STRIDE per component in §5.2: PEP, detection, OPA, control plane, analytics.
- Map threats to OWASP LLM01–LLM10 and ASI01–ASI10, together with the spec controls that address them.
- Dedicated threat models: gateway bypass, forged policy bundle, leakage through logs/telemetry, tenant crossover, and evidence unmask abuse.

## Acceptance criteria
- [x] The threat model document exists in `docs/`. *(`docs/threat-model.md`: assets and trust boundaries, STRIDE per component in §5.2, mapping of LLM01–LLM10 and ASI01–ASI10 to controls with their status in the code, and five dedicated threat models.)*
- [x] Every high threat has a control or a mitigation ticket. *(Table in §5 of the document.)*
- [x] Gaps are recorded as new tickets. *(G1–G6 → tickets 40–45.)*

## Results
Status `needs-signoff`: the document needs review by the bank's CISO/security architect. Main findings:
- The MCP/agent controls (28–30, 39), signed bundles (11), audit (07), and log privacy are already in the code.
- Gaps without tickets: service-to-service auth + public bundle + bundle key not in an HSM (40), Kafka/OpenSearch without TLS/SASL (41), the RLS promised by ADR-0001 does not exist yet (42), AI gateway bypass (43), ASI06 memory poisoning (44), unmask abuse (45).
