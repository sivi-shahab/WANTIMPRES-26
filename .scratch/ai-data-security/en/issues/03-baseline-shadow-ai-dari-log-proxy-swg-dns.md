<!-- source-sha256: 4bf203b50e5d215f -->
# 03: Shadow AI baseline from proxy/SWG/DNS logs

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M0
Spec: `../spec.md` §4.1 FR-DISC-2, FR-DISC-3; §4.2 FR-SHADOW-1, FR-SHADOW-4; §11

## Context
Measure AI usage baseline before enforcement. This baseline is used for the success metrics in §1.5.

## Scope
- Ingest batches of existing SWG/proxy/firewall/DNS logs (syslog/file).
- Fingerprint domain/SNI + URL patterns against the AI catalog seed (top ~200 GenAI apps).
- Confidence scoring `1 − Π(1 − c_i)` and a review queue for confidence < 0.6.
- Report: top apps, top users/units (pseudonymized), and weekly trend.

## Acceptance criteria
- [ ] A shadow AI baseline report for ≥ 30 days of logs is available. *(The tool is ready and tested on 35 days of synthetic logs (`TestBaseline35Days`) and a 31-day `.gz` smoke run. The real report is waiting for an export of ≥ 30 days of SWG/proxy/DNS logs from the bank; the report flags itself when logs cover < 30 days.)*
- [x] Unit tests for the confidence formula and the fingerprint matcher. *(Already present from ticket 16 (`internal/catalog`); plus `TestSeedCatalog`: unique domain per app in the 199-app seed, regional Bedrock/Vertex/Azure OpenAI endpoints resolve, generic SaaS does not match.)*
- [x] No plaintext user identity in the output (HMAC). *(User/IP are HMACed with `TENANT_PEPPER` at read time; a pepper < 16 bytes is rejected. Tests verify that no user name or client IP appears in the JSON or Markdown.)*

## Out of scope
Inline enforcement and personal/corporate account context (needs an inline proxy, tickets 22/23).

## Notes from ticket 16
- Already in place: catalog seed (15 apps, `internal/catalog/seed.json`), fingerprint matcher + confidence formula (`internal/catalog/match.go`, tested), and `APP_USAGE_DAILY`. This ticket only has to ingest batch logs, expand the seed to ~200 apps, and produce the baseline report.


## Decisions
- **Batch CLI `cmd/shadow-baseline`**, not a service: the phase 0 baseline is taken before the inline platform runs, from existing log files (plain or `.gz`, or stdin). Output: `shadow-baseline.json` (for tools) and `shadow-baseline.md` (for humans).
- **Formats:** Squid native access log, BIND query log (also behind an RFC 5424 syslog prefix), and JSON lines with field mapping (`-fields time=ts,user=login,...`) for Zscaler NSS/Netskope/Palo Alto/Fortinet exports. BSD syslog lines without a year are counted as unreadable. CSV and native vendor formats follow if the bank uses them.
- **Fingerprinting** uses the ticket 16 catalog matcher as is. Hosts outside the catalog whose names suggest AI (`.ai`, `gpt`, `llm`, `chatbot`, `copilot`, `genai`) go into the review queue with confidence 0.3. This is how uncataloged shadow AI becomes visible.
- **Review queue** = a section of the report (host, confidence, signals, candidates, user/request counts). It is resolved through the existing catalog (`POST /apps` or an app correction); there is no new endpoint.
- **Catalog seed 15 → 199 apps** (version 2), public domains only. Generic SaaS that embeds AI (Notion, Canva, Zoom, Bing) is deliberately left out: matching their whole domain would count all of their usage as AI.
- **Unit** comes from an optional `user,unit` CSV (can also map client IP → unit). A unit is organizational, not a personal identity.

## Remaining
- Run on a bank log export of ≥ 30 days, then review the review queue and assign sanction status to the top apps (metric in §1.5).
