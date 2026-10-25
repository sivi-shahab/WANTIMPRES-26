<!-- source-sha256: 8a061787ac46bb39 -->
# 16: AI app catalog & sanction status

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 03, 15
Spec: `../spec.md` §4.1 FR-DISC-1..5; §8.4

## Context
The catalog is used as the `destination` input in policy and for shadow AI reports.

## Scope
- `AI_APP` + `AI_APP_FINGERPRINT` data model (§6).
- Status `sanctioned | tolerated | unsanctioned | blocked | under_review` along with owner, reason, and `review_at`.
- Versioned catalog feed + local overrides without redeploy; the feed is signed.
- `GET/PATCH /apps` API and `APP_USAGE_DAILY` aggregation.
- Risk attributes: `trains_on_data`, retention, `hosting_region`, `ojk_approval_ref`, certifications.
- `hosting_region` and `ojk_approval_ref` become inputs to the residency policy (ADR-0001, spec §10.2).

## Acceptance criteria
- [x] Status changes are recorded in the audit log. *(`catalog.app.update` with before/after, in the same transaction as the release; also `catalog.app.add`, `catalog.feed.import`, `catalog.feed.rejected`.)*
- [x] Status changes are reflected in OPA decisions ≤ 60 s. *(OPA SDK (bundle sidecar plugin) long-polls the releaser: 3 status changes → decisions changed within 0.85–1.05 s.)*
- [x] Feeds without a valid signature are rejected. *(Modified feed, different key, missing/garbage signature → rejected and audited; same/older version feed → 409, cannot be replayed.)*
- [x] Apps with `hosting_region` outside Indonesia and no `ojk_approval_ref` are flagged in the report. *(Flag `offshore_without_ojk_approval` in `GET /apps` and `GET /apps/report/residency`; region `unknown` counts as offshore; filling in `ojk_approval_ref` removes the flag.)*

## Decisions
- `internal/catalog` module in the control-plane, schema `catalog`. Effective catalog = highest-version feed + local overrides (sanction, owner, reason, review_at, region/OJK/training corrections) + local apps (`POST /apps`) — without redeploy (FR-DISC-5).
- **The PDP uses the catalog**: every change cuts a policy release (ticket 12) carrying `data.wantimpres26.catalog`; `wantimpres26/dest` replaces the sanction/region/trains_on_data sent by the PEP with the catalog values for known apps; the PDP output contains the effective `destination` to be recorded in the event. New template `tpl.blocked-app`: an app with status blocked = block (previously only residency blocked).
- Feed: versioned JSON + detached signature (ECDSA P-256 over the SHA-256 of the feed bytes), publisher key from `CATALOG_FEED_PUBKEY_FILE`; hourly pull from `CATALOG_FEED_URL` (+`.sig`) or `POST /catalog/feed`. The seed (15 common GenAI apps, uncertain attributes left null/unknown) is embedded in the cosign-signed image, so it is imported without a feed signature.
- Default app status from the feed: `unsanctioned` until the bank decides; sanction changes require a `reason`.
- `APP_USAGE_DAILY` from decision events (consumer group `catalog-usage`, idempotent per event_id): events, sensitive_events, blocked, users (pseudonymous). Apps in traffic that are not in the catalog appear as `observed` (shadow AI).
- Fingerprint matcher (domain/SNI, API signature, header, payload shape, UA) with `confidence = 1 − Π(1 − c_i)`; headers are weighted 0.7 (the spec gives no weight). Signals that match several vendors at once (OpenAI-compatible endpoints) → candidate + review, not a guess.
- Permissions: read = `dashboard.read`; change status/local app/import feed = `config.write`.

## Local verification results (2026-10-03)
- `opa test` 40/40; unit (formula, matcher, feed signature) and Postgres + OPA SDK integration; entire suite `-race`; golangci-lint clean; image built.

## Remaining / follow-up
- Seed is only 15 apps for now; ticket 03 expands it to ~200 and fills the baseline from proxy/DNS logs (the matcher is already available).
- The matcher is not yet called by the PEP (ticket 13) or log ingest (ticket 03).
- Review queue for detections with confidence < 0.6 / ambiguous: the data exists (`Detection.NeedsReview`), UI/endpoint wait for ticket 03.
