<!-- source-sha256: 84a396378baa33a6 -->
# 31: Connector SDK + M365 connector + oversharing analysis

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M3
Blocked by: 06, 08, 15
Spec: `../spec.md` §4.3 FR-DATA-1..5; §4.4 FR-CLS-5, FR-CLS-6; §11

## Context
Data-at-rest posture consumed by Copilot/RAG.

## Scope
- Connector SDK contract (`list_containers`, `list_items`, `get_item`, `get_acl`, `apply_remediation`) + cursor checkpoint.
- M365 connector (SharePoint/OneDrive/Teams) with delta query + reading Purview labels.
- Sandboxed file extraction service (Tika) with zip bomb limits.
- Adaptive sampling + ACL analysis: anonymous links, external shares, broad groups, orphan permissions.
- Output `DATA_ASSET`, `CLASSIFICATION_RESULT`, `exposure_score` with no raw content.

## Acceptance criteria
- [x] Incremental scan does not repeat unchanged items. *(`datascan.TestScan` (Postgres + fake Graph): the second run with no changes processes 0 items and reads neither content nor ACLs. After one content change, one sharing change, and one deletion, exactly three items are touched: content is re-read only for the item whose cTag changed, and the item whose sharing alone changed has only its ACL read. At bootstrap, every file is read exactly once even if the container switches from sample to full. A mutation test (cTag ignored) makes the test fail.)*
- [x] File parser fuzz test. *(`extract.FuzzExtract`: 90 seconds, ±1.19 million executions, clean; text never exceeds the limit. Unit tests: zip bomb (20 MB of zeros), depth 4, entry count, input size, text limit.)*
- [x] Graph API rate limit respected (backoff). *(`m365.TestThrottling`: 429 with `Retry-After: 7` → waits 7 s twice then succeeds with a single fetch; 503 without Retry-After → exponential 1/2/4 s; the wait is capped by `MaxBackoff`; after `MaxRetries` → `StatusError{Throttled}` which is never treated as "no label". `TestScan` passes through a 429 in the middle of a scan.)*

## Decisions
- **Connector SDK** (`internal/connector`): `Containers`, `Items(container, cursor)`, `Get`, `ACL`, `Labels`, `Remediate`, which map to `list_containers`, `list_items(cursor, since)`, `get_item`, `get_acl`, `apply_remediation`. Plus `Labels` for FR-CLS-6. Connectors are stateless; the cursor and checkpoint live in Postgres (`data.containers`), saved on every page.
- **M365** (`internal/connector/m365`): Entra client credentials (read-only: Sites.Read.All, Files.Read.All, User.Read.All). Container = every document library of all sites (SharePoint and Teams) plus each user's OneDrive. Delta query per drive with `Prefer: deltashowsharingchanges, hierarchicalsharing`, so sharing changes appear in the feed with the same cTag. Permissions are mapped to grants: `anonymous`/`organization`/`users` links, user (external = `#EXT#` guest or a domain outside `M365_DOMAINS`), and group. Purview labels via `extractSensitivityLabels`. `nextLink`/`deltaLink` links are followed only if they stay on the Graph host. Content downloads follow the pre-authenticated redirect without carrying the token.
- **Extraction** (`internal/extract`, per the "Go native + optional Tika" choice): text, CSV, HTML/XML (script/style removed, comments kept because that is where injection hides), docx/xlsx/pptx (only content-bearing parts), and nested zip are handled in Go, in memory, without disk. Limits §13: 50 MB, depth 3, decompression ratio 100× of the size actually read (not the header), 10,000 entries, 2 MB of text for classification. PDF, OLE2 (.doc/.xls), and RTF go through a Tika server (tested with the real `apache/tika:3.2.3.0` image); without `TIKA_URL`, such items are assessed from label and ACL only. Tika is rebuilt and signed by CI (`build/tika.Dockerfile`, digest pinned), runs in gVisor with no egress (NetworkPolicy), and only the worker can reach it. The worker itself also runs in gVisor because it parses files too.
- **Incremental**: content is read only if the item is new, its cTag changed, or it was never classified although it is now selected. Items that appear in the feed only because of sharing or name have only their ACL read. Labels are re-read only when content changes.
- **Adaptive sampling** (FR-DATA-3): every file is still recorded with its ACL and label; content is read only for a deterministic 5% sample (hash of id, stable across runs, max 10,000). After the bootstrap pass, a container switches to `full` if it is small (< 1,000 files) or dense (≥ 5% sensitive out of ≥ 20 samples), then walked once more to read what was missed (without re-reading ACLs or content that already exist). Items that were not sampled are recorded with `scan_note = 'not sampled'`.
- **Oversharing** (FR-DATA-4): `anyone_link`; `external_share`; `broad_group` (Everyone/All company/All employees, and so on) on confidential or restricted content; `orphan_permission` (inactive user in the SCIM directory of ticket 06; users unknown to the directory are not considered orphans).
- **Sensitivity** = the highest level from the L1 detectors and the external label (the label acts as a lower bound; label → sensitivity map from `M365_LABELS`). **Exposure score** 0–100 = 100 × sensitivity (0/.3/.6/1) × reach (anyone 1, external .8, broad group .6, orphan .3, private .1).
- **Output** (FR-DATA-5): `data.assets` (external_id, HMAC path, cTag, label, sensitivity, exposure, flags, scan note), `data.classifications` (class, count, confidence, model version), `data.acl_entries` (grantee stored for the remediation of ticket 33). No raw content or path; a test inspects all rows in all tables. Files that fail extraction (zip bomb, unsupported format) get a note and are not fetched again until their version changes.
- **API** (control-plane, `dashboard.read`): `GET /data/assets?min_exposure=&flag=&sensitivity=&source=&limit=` (ordered by exposure, including classes and ACL) and `GET /data/summary` (per source: count, classified, per sensitivity, per flag, exposure ≥ 60).
- New service `connector-worker` (interval `SCAN_INTERVAL`, default 1 hour). Replicas share work via an advisory lock per container.

## Local verification results (2026-10-04)
- `go test -race ./...` including Postgres integration green; 90-second fuzz clean; PDF extraction through real Tika; golangci-lint 0 issues; `connector-worker` and `control-plane` images build. Not yet tested against a real M365 tenant (needs the bank's app registration).

## Remaining / follow-up
- Flag "sensitive items indexed by Copilot/RAG": Graph does not give per-item index status. Needs Restricted Content Discovery/Restricted SharePoint Search per site, or Copilot interaction logs (§11).
- Scheduled full rescan (e.g. monthly) to refresh inherited ACLs that do not appear in the feed; density that changes after bootstrap does not yet trigger a switch to `full`.
- Image OCR (P1); classification only covers the first 2 MB of text per file.
- Data-at-rest posture metrics (high exposure per domain) on the ticket 20 dashboard.
- Extraction still runs in the worker process (in gVisor), not yet a separate queue-based service like the §5 table.
- Remediation (ticket 33): `Remediate` is still `ErrNotSupported`.