<!-- source-sha256: 2803635e0351bd91 -->
# 35: DPIA & communication to employees before inline rollout

Status: needs-signoff
Type: task
Priority: P1
Milestone: M2
Spec: `../spec.md` §10.2 minimization; §17 monitoring risk

## Context
The inline proxy and extension systematically monitor employee activity.

## Scope
- DPIA together with DPO/Legal/HR.
- Internal AI usage policy + monitoring transparency.
- Minimization configuration (snippets, forensic capture) approved by the DPO.

## Acceptance criteria
- [ ] DPIA signed before tickets 22/23 are released to production. *(Draft ready: `docs/dpia-pemantauan-ai-karyawan.md`. DPO/Legal/HR/CISO signatures not yet. Gate: tickets 22 and 23 are now `Blocked by: 35` for production release, and the DPIA conditions R3/R8/R9 went into the AC of both.)*

## Results (2026-10-10)
- **DPIA draft v0.1**: processing description, legal basis (proposed legal obligation + legitimate interest, not employee consent), necessity/proportionality test against alternatives, 10 risks with mitigations referenced to code, data subject rights, consultation and signature table.
- **Appendix A**: draft AI usage policy + monitoring notice, including a prohibition on using risk scores for performance/HR assessment.
- **Appendix B**: the minimization configuration in force in the code (forbidden fields, snippet ≤ 200 + reject digit sequences, HMAC of principal/content, opt-in forensic capture, raw TTL 30 days, audited unmask, retention) with a DPO approval column per row.
- The signed DPIA is attached as evidence via `POST /compliance/evidence` (CTL-DLP).
- Spec §10.2: "consider a DPIA" → DPIA is mandatory before inline rollout.

## Remaining
- Legal: check the quotes of Indonesia's Personal Data Protection Law (UU PDP, Law No. 27/2022) Art. 20 and 34 against the official text, find the DPIA article in Government Regulation PP 33/2026, decide the processing basis (and a balancing test if legitimate interest).
- HR: whether consultation with employee representatives/the collective labor agreement (PKB) is needed; send Appendix A ≥ 14 days before rollout.
- DPO: residual risk decision and approval of each row of Appendix B.
