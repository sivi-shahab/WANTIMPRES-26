<!-- source-sha256: 3c4ae306187cff6b -->
# 50: File scan only checks the first 2 MiB of text

Status: needs-triage
Type: bug
Priority: P1
Milestone: M2
Blocked by: -
Spec: `../spec.md` §13.1 (sync file scan ≤ 5 MB, async ≤ 50 MB); FR-DATA; finding from ticket 21 (`docs/nfr/m1-report.md`)

## Context
Ticket 21 measurement (`deploy/nfr/nfr filescan`): a zip of a CSV containing NIK (national ID number), 5 MB or 49 MB, produces the **same** number of L1 findings (2,804) and the same time (~0.37 seconds p95). `extract.Default.MaxText` = 2 MiB truncates the text handed to the detectors (`Result.Truncated`). File content after 2 MiB is not checked at all, so sensitive data placed at the end of a file gets through. The file scan latency figures meet the target precisely because of this truncation.

## Scope
- Windowed scan over the entire text (streaming per chunk with overlap) for the async path up to the 50 MB file limit. For sync, set a limit that still meets p95 ≤ 2 seconds.
- If truncation remains, `Truncated` must become a policy signal (e.g. `content.truncated` → `require_approval`/`block` for `restricted` apps), not silently pass.
- Remeasure with `deploy/nfr/.bin/nfr filescan -mb 5` and `-mb 49`.

## Acceptance criteria
- [ ] A NIK in the last bytes of a 49 MB file is detected (test).
- [ ] Sync p95 for 5 MB ≤ 2 seconds, async 50 MB ≤ 60 seconds with all text checked.
