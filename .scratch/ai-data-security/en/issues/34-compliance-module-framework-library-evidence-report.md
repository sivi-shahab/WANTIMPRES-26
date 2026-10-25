<!-- source-sha256: add3feec04efe254 -->
# 34: Compliance module: framework library, evidence, report

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M3
Blocked by: 07, 18
Spec: `../spec.md` §4.11 FR-COMP-1..3; §14

## Context
Compliance evidence for OJK (Indonesia's Financial Services Authority), Indonesia's Personal Data Protection Law (UU PDP, Law No. 27/2022), and ISO 42001.

## Scope
- Versioned framework library (OWASP LLM/ASI, NIST AI RMF/600-1, ISO 42001, UU PDP + Government Regulation PP 33/2026, OJK Regulation 11/POJK.03/2022 (POJK 11), OJK's AI Governance Guide for Indonesian Banking (2025)).
- Control ↔ requirement mapping; verification of subcategory/clause numbers by the compliance team.
- Automatic evidence from configuration, active policy, enforcement statistics, and test results.
- Control status history + export per audit period.
- AI inventory/register for OJK/ISO 42001 needs.

## Acceptance criteria
- [ ] §14 mapping verified against the official text. *(**Half done: research pre-verification is complete, compliance team sign-off is not.** Every §14 cell was checked against the official texts that could be retrieved on 2026-10-05: OWASP LLM 2025 (genai.owasp.org), NIST AI RMF Core (airc.nist.gov), UU 27/2022 (peraturan.bpk.go.id), POJK 11/POJK.03/2022 and OJK's AI Guide (ojk.go.id), PP 33/2026 (government copy). Corrections went into the library and spec §14, among them: GOVERN 4/MEASURE 4 for the audit log was **wrong** and was replaced; GOVERN 6 → GOVERN 1.1; ASI07 → ASI02; POJK articles made specific; **POJK 11 Article 60 (incident notification to OJK within 24 hours) added**. Each mapping stores a verdict, source, and notes. What could not be verified from free sources: **all ISO/IEC 42001 cells** (paywalled) and the ASI01–ASI10 titles (OWASP PDF locked behind a form). This AC is done when the compliance team signs off each mapping via `POST /compliance/mappings/verify` (the report shows `mappings_verified` n/m).)*
- [x] Report export for one sample audit period. *(`TestExportAndVersions`: period Q3 2026 (1 Jul–1 Oct) with control status at start/end, transitions (injection rule disabled 11 Jul → partial), automatic evidence summary, attachments (AgentDojo report), mapping per requirement with the research verdict and sign-off; JSON with SHA-256 and CSV; every export is audited.)*
- [x] A framework version change does not delete old history. *(New version = new row; the old version, its mappings, and its sign-offs remain; a stored version document cannot be changed without a new version number; an export of an old period after a new version still uses the old version with the same sign-off numbers; all compliance tables are append-only (a trigger rejects UPDATE/DELETE). A mutation test (always use the latest version) makes the test fail.)*

## Decisions
- **Versioned library** (`internal/compliance/library`): OWASP LLM 2025, OWASP Agentic 2026, NIST AI RMF 1.0, ISO/IEC 42001:2023 Annex A (IDs only; titles "to be confirmed"), UU PDP 27/2022, PP 33/2026, POJK 11/POJK.03/2022, OJK's AI Governance Guide for Indonesian Banking (OJK, 29 April 2025). Only IDs and short titles/short quotes, no licensed text. The embedded library is imported at start; a new version adds rows, the old version is never deleted or changed. The EU AI Act is not included (the bank's scope is `unspecified`).
- **Mappings** carry research (`supported` | `weak` | `unverifiable`, source, notes). Cells that are `wrong` are not included and are replaced. Research is **not sign-off**: the `verified`/`rejected` status comes only from the compliance team (`compliance.write`, DPO) with an official source required (URL, article/paragraph, clause); audited; a sign-off is bound to the framework version in which it was made.
- **Platform controls** = the §14 rows, plus `CTL-DATA` (data-at-rest, tickets 31–33) marked *proposed*. The library rejects a control without a mapping (FR-COMP-2).
- **Automatic evidence** every hour (and `POST /compliance/collect`), from:
  - rules enforced in the active policy release (DLP, injection, agent, MCP, rate, residency);
  - posture metrics (inventory, offshore apps without OJK approval);
  - the agent registry (agents without owner/allow-list, active kill switches) and MCP tools under review;
  - incident SLA;
  - audit hash chain verification for the last 24 hours;
  - data-at-rest scans and exposure, and the remediations that were run.

  Status rules are simple and can be recomputed by an auditor. A failed source → `unknown` with the reason. Attachments (hash + note) for test results or documents. Parts that do not exist yet are declared `partial`: AI gateway token quota (ticket 13) and the UU PDP breach timer (ticket 26).
- **History**: one evidence row per collection, one status row only when the status or its reason changes; all append-only.
- **Export** (`GET /compliance/report?from=&to=[&format=csv]`): the framework version in effect at the end of the period (other versions in effect within the period are mentioned), start/end status and transitions per control, evidence summary and hash, attachments, mapping with research and sign-off as of period end, report SHA-256; built from a read-only snapshot; audited.
- **AI register** (`GET /compliance/ai-register[?format=csv]`): AI apps (catalog: sanction, hosting region, OJK approval reference, training), agents (owner, unit, purpose, risk tier, status), MCP tools, and enterprise AI services monitored through the Compliance API.
- API: read with `compliance.read` (CISO, DPO, auditor); write (sign-off, attachments, collect) with `compliance.write` (DPO).

## Local verification results (2026-10-05)
- `go test -race ./...` with Postgres, MinIO, and Azurite green; golangci-lint 0 issues; `control-plane` image builds.

## Remaining / follow-up
- **Compliance team sign-off** on every mapping (first AC), including confirming ISO/IEC 42001 against a licensed copy and the ASI titles from the official OWASP PDF; identifying the transfer article in PP 33/2026; the effective date of PP 33/2026 (secondary source: 16 Jan 2027).
- Subcategories stricter than the research (MAP 1.1, MANAGE 1.3, GOVERN 1.5, MANAGE 3.1, GOVERN 6.1, MAP 4.1) and the official text of MEASURE 2.8 and MANAGE 4.1 are not yet cited: release in the next library version after checking.
- The 24-hour OJK notification timer (POJK 11 Art. 60) needs to go into the incident flow (ticket 26) together with the UU PDP 3×24 hours (72 hours).
- Annual IT condition report (POJK 11 Art. 59) as an export template.