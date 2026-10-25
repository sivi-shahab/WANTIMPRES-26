<!-- source-sha256: cad844d203bb65b4 -->
# 07: Append-only audit log with hash chain & WORM anchor

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 05
Spec: `../spec.md` §4.11 FR-COMP-4; §10.2

## Context
Auditors need an audit trail that cannot be modified.

## Scope
- `audit_log` table with `hash = SHA-256(prev_hash ‖ canonical_json(entry))`.
- Daily anchor signed by KMS and stored in object storage with object lock.
- Chain verification endpoint/CLI for a given time range.

## Acceptance criteria
- [x] Test: changing a single entry makes verification fail at the exact position. *(Unit: edit content → that seq; edit + rehash → the next seq; delete → the missing seq. Postgres integration: bypass trigger, change seq 3 → fails at 3.)*
- [x] Test: the daily anchor matches the last hash of that day.
- [x] Retention ≥ 5 years is configured. *(COMPLIANCE object lock until the end of the day + `AUDIT_RETENTION_YEARS` calendar years, a minimum of 5 is enforced and lower values are rejected; the table cannot be UPDATEd/DELETEd/TRUNCATEd.)*

## Decisions
- Module `internal/audit` in the control-plane (DEC-3), Postgres schema `audit`, a single global chain; appends are serialized with an advisory lock, `seq` has no gaps, `ts` comes from the DB `clock_timestamp()` after the lock.
- `canonical_json` = JSON with sorted keys, no HTML escaping, `ts` in UTC RFC 3339 µs; `target` is normalized to its JSON-decoded form before hashing (same as what is read back from jsonb).
- Anchor = the chain head at the end of the WIB day (also for days without entries), ECDSA P-256 via `crypto.Signer` (file key now, PKCS#11/HSM later), stored at `audit-anchors/YYYY-MM-DD.json`. An existing anchor cannot be replaced with a different head.
- Verification via the CLI `control-plane audit verify --from D --to D` (chain + the anchor of every completed day; a missing anchor = failure). The HTTP endpoint waits for authn/authz (ticket 06).
- CronJob `audit-anchor` at 00:15 WIB; alert `AuditAnchorMissing` if >26 hours pass without a success.

## Local verification results (2026-10-03)
- Unit + integration (Postgres 17, MinIO object lock) pass with `-race`; golangci-lint, trivy config, gitleaks clean.
- Integration: UPDATE/DELETE/TRUNCATE rejected; anchor = last entry of that day; retention < 5 years rejected; a locked object cannot be deleted; deleting tail entries is only detected through the anchor (fails at seq 5).
- CLI e2e: verify fails before an anchor exists, the current day's anchor is rejected, re-anchoring is idempotent, verify passes.

## Remaining / follow-up
- There is no caller of `Append` yet: audit events (policy changes, unmask, kill switch, detokenization) are added in their respective tickets (12, 24, 30).
- RLS `tenant_id` is not yet applied to this table (global chain); decide together with ticket 06.
- HSM/PKCS#11 signer; the `audit-anchor` and `audit-anchor-key` Secrets and the bucket with object lock are provisioned outside git.
- A Postgres superuser can still disable the trigger; what catches this is the WORM anchor.
