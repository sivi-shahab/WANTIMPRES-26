<!-- source-sha256: 8bb30809fc61a1bf -->
# 32: Google Workspace & cloud storage connectors

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M3
Blocked by: 31
Spec: `../spec.md` §4.3; §11

## Context
Expanding data-at-rest coverage.

## Scope
- Google Drive connector (changes API) + audit of AI app OAuth grants.
- S3/GCS/Azure Blob connectors (event notification).
- ChatGPT Enterprise / Claude Enterprise Compliance API connector if the bank uses them.

## Acceptance criteria
- [x] Contract test per connector using the SDK from ticket 31. *(`internal/connector/connectortest`: one suite for all connectors, covering container exists, paged bootstrap with content tag (and size when reported), `Get` and its size limit, no change = no items, content changes and deletions appear in the feed and nothing else does, ACL/label/remediation, and anonymous sharing visible in the ACL (and in the feed if the source reports it). Append-only mode for logs and derived mode for transcripts. Run for M365 (fake Graph), Google Drive (fake Drive/Directory/Reports), S3 (**real MinIO**), GCS (MinIO via XML interop + Pub/Sub notification format), Azure Blob (**Azurite emulator** with real SAS), Claude Enterprise, and ChatGPT Enterprise (fake server following the documentation).)*

## Decisions
- Scope as chosen: all four connector types were built. All implement `connector.Connector` so the ticket 31 scanner (incremental, sampling, oversharing, exposure) applies unchanged. Retry/backoff was lifted into `connector.Backoff` (Retry-After, exponential, wait and retry limits) and is used by all HTTP connectors, including M365, which was refactored without changing behavior.
- **Google Drive** (`internal/connector/gdrive`): service account with domain-wide delegation, read-only scopes (drive, directory user, reports audit). Container = every shared drive (as the scanning admin) + the My Drive of every active user (impersonating that user; files owned by others are skipped because they are reported by the owner's drive). The changes start token is taken before listing, so no change is lost during bootstrap; afterwards the changes API. Content tag = MD5 for binary files, `modifiedTime` for Google documents (changes because of edits, not sharing). Docs/Sheets/Slides are exported as text/plain and text/csv. Permissions: `anyone` = anonymous link, bank domain = org, other domain/external = external. Google quotas (429 or 403 `rateLimitExceeded`) are backed off. Drive labels are not read yet because the per-tenant label IDs need to be configured.
- **OAuth grant audit** (`datascan.OAuthAudit`): Admin SDK Reports (token/authorize) → `data.oauth_grants` (app, combined scopes, AI or not) and `data.oauth_grant_users` (email HMAC'd). AI apps are recognized by keywords (ChatGPT, Claude, Gemini, Copilot, etc.) or by app name in the AI catalog (ticket 16; not the vendor, so "Google Drive for desktop" is not counted). AI apps enter the shadow agent queue of ticket 27 (`agents.discovered`, source `oauth_grant`, id `oauth:<client_id>`). Google reports are delayed, so every pass re-reads the last 24 hours; recording is idempotent.
- **Object storage** (`internal/connector/objstore`): one connector with two backends, S3-compatible (minio-go: on-prem MinIO per ADR-0001, AWS S3, GCS via the XML API with HMAC) and Azure Blob (REST + account SAS list/read, no new SDK). Bucket = container. The first pass lists (the latest event id is recorded first), then the feed = a notification queue in Postgres (`data.object_events`) filled by the `Receiver` in the worker: `POST /events/{s3|gcs|azure}` with a token (header or query), for S3/MinIO Records format, GCS Pub/Sub push, and Azure Event Grid (including the validation handshake). Details that were tested:
  - S3 keys in events are URL-encoded (verified with a **real MinIO webhook payload**: `laporan q3/a b+c.txt`);
  - GCS md5Hash (base64) is converted to hex to match the ETag of the XML listing;
  - a GCS DELETE belonging to an overwritten generation is ignored.

  ACL: a bucket policy that allows Principal `*` to read (S3/MinIO) or a container with public access `blob`/`container` (Azure) counts as an anonymous link. Per-object ACLs and GCS `allUsers` IAM are not visible yet. Events older than 7 days are discarded.
- **Compliance API** (`internal/connector/compliance`), only the parts verified in the official documentation (research 2026-10-04):
  - **Claude Enterprise**: Compliance Access Key (`x-api-key`, `anthropic-version`). Incremental chats with `order_by=updated_at&updated_at.gt` + `after_id`; deleted chats via `deleted_at`. Content = message transcript + text of uploaded files (binary files are mentioned by name only). Throttling 429/529 with `retry-after`.
  - **ChatGPT Enterprise**: only **Compliance Logs** (`/workspaces/{id}/logs?event_type=conversation_message&after=` with `last_end_time`, JSONL download) are verified, because the OpenAI conversation/file endpoint reference was blocked (403) during research. The connector reads log files (append-only) and classifies their entire contents.
- `connector-worker` is now multi-source and env-driven (each source is active when its variables are present) and runs the OAuth audit and the event receiver; a Service was added for the events endpoint. CI adds an Azurite service.

## Local verification results (2026-10-04)
- `go test -race ./...` green with Postgres, MinIO, and Azurite; real MinIO webhook test passes; golangci-lint 0 issues; `connector-worker` image builds. Not yet tested against real Google Workspace, AWS, GCS, Azure, or AI vendor APIs (needs the bank's credentials).

## Remaining / follow-up
- ChatGPT Enterprise: the conversation/file endpoints and more detailed log fields need to be verified from the OpenAI Admin API reference (Enterprise admin browser session / OpenAPI export).
- Claude: binary uploaded files (docx/pdf) are not extracted yet; sharing is only visible in the Activity Feed (`claude_chat_snapshot_*`), not read yet.
- Google Drive labels; per-object ACLs for S3/GCS and GCS `allUsers` IAM; S3 notifications from AWS via SNS (raw delivery format is supported, the SNS confirmation handshake is not).
- Missed bucket notifications (endpoint down > 7 days) require a rescan (`cursor` cleared).
- OAuth grants from Entra ID (Microsoft 365 app consent) are not read yet; the `connector.OAuthGrant` type is already generic.