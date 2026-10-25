# 16: AI app catalog & status sanction

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 03, 15
Spec: `../spec.md` §4.1 FR-DISC-1..5; §8.4

## Konteks
Katalog dipakai sebagai input `destination` di policy dan untuk laporan shadow AI.

## Scope
- Model data `AI_APP` + `AI_APP_FINGERPRINT` (§6).
- Status `sanctioned | tolerated | unsanctioned | blocked | under_review` beserta owner, alasan, dan `review_at`.
- Feed katalog berversi + override lokal tanpa redeploy; feed ditandatangani.
- API `GET/PATCH /apps` dan agregasi `APP_USAGE_DAILY`.
- Atribut risiko: `trains_on_data`, retensi, `hosting_region`, `ojk_approval_ref`, sertifikasi.
- `hosting_region` dan `ojk_approval_ref` menjadi input residency policy (ADR-0001, spec §10.2).

## Acceptance criteria
- [x] Perubahan status tercatat di audit log. *(`catalog.app.update` dengan before/after, dalam transaksi yang sama dengan release; juga `catalog.app.add`, `catalog.feed.import`, `catalog.feed.rejected`.)*
- [x] Perubahan status ter-reflect di keputusan OPA ≤ 60 s. *(OPA SDK (plugin bundle sidecar) long-poll ke releaser: 3 perubahan status → keputusan berubah dalam 0,85–1,05 s.)*
- [x] Feed tanpa signature valid ditolak. *(Feed diubah, key lain, tanpa/garbage signature → ditolak dan diaudit; feed versi sama/lebih lama → 409, tidak bisa replay.)*
- [x] App dengan `hosting_region` di luar Indonesia tanpa `ojk_approval_ref` ditandai di laporan. *(Flag `offshore_without_ojk_approval` di `GET /apps` dan `GET /apps/report/residency`; region `unknown` dihitung offshore; mengisi `ojk_approval_ref` menghapus flag.)*

## Keputusan
- Modul `internal/catalog` di control-plane, schema `catalog`. Katalog efektif = feed versi tertinggi + override lokal (sanction, owner, reason, review_at, koreksi region/OJK/training) + app lokal (`POST /apps`) — tanpa redeploy (FR-DISC-5).
- **PDP memakai katalog**: setiap perubahan memotong policy release (ticket 12) yang membawa `data.wantimpres26.catalog`; `wantimpres26/dest` mengganti sanction/region/trains_on_data dari PEP dengan nilai katalog untuk app yang dikenal; output PDP memuat `destination` efektif untuk dicatat di event. Template baru `tpl.blocked-app`: app berstatus blocked = block (sebelumnya hanya residency yang memblokir).
- Feed: JSON berversi + detached signature (ECDSA P-256 atas SHA-256 byte feed), key publisher dari `CATALOG_FEED_PUBKEY_FILE`; pull per jam dari `CATALOG_FEED_URL` (+`.sig`) atau `POST /catalog/feed`. Seed (15 app GenAI umum, atribut yang tidak pasti dibiarkan null/unknown) di-embed di image yang ditandatangani cosign, jadi diimpor tanpa signature feed.
- Status default app dari feed: `unsanctioned` sampai bank memutuskan; perubahan sanction wajib `reason`.
- `APP_USAGE_DAILY` dari event keputusan (consumer group `catalog-usage`, idempoten per event_id): events, sensitive_events, blocked, users (pseudonim). App di traffic yang tidak ada di katalog muncul sebagai `observed` (shadow AI).
- Matcher fingerprint (domain/SNI, API signature, header, payload shape, UA) dengan `confidence = 1 − Π(1 − c_i)`; header diberi bobot 0,7 (spec tidak memberi bobot). Sinyal yang cocok ke beberapa vendor sekaligus (endpoint OpenAI-compatible) → kandidat + review, bukan tebakan.
- Izin: baca = `dashboard.read`; ubah status/app lokal/import feed = `config.write`.

## Hasil verifikasi lokal (2026-10-03)
- `opa test` 40/40; unit (rumus, matcher, signature feed) dan integrasi Postgres + OPA SDK; seluruh suite `-race`; golangci-lint bersih; image ter-build.

## Sisa / follow-up
- Seed baru 15 app; ticket 03 memperluas ke ~200 dan mengisi baseline dari log proxy/DNS (matcher sudah tersedia).
- Matcher belum dipanggil PEP (ticket 13) atau ingest log (ticket 03).
- Antrean review untuk deteksi confidence < 0,6 / ambigu: datanya ada (`Detection.NeedsReview`), UI/endpoint menunggu ticket 03.
