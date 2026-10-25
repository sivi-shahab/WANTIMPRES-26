# 15: Event pipeline: Kafka schema, OpenSearch, retensi

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 05
Spec: `../spec.md` §5.1 Analytics; §6 catatan; §10.2; §12.3

## Konteks
Semua PEP menulis `decision_event` ke satu pipeline.

## Scope
- Skema event berversi di schema registry (metadata + HMAC hash + snippet redacted ≤ 200 karakter).
- Consumer ke OpenSearch (index per tenant bila diperlukan) + partisi harian + TTL (90 hari hot, 400 hari total).
- Propagasi `trace_id` dari PEP.
- Validator pipeline yang menolak event berisi field konten mentah.

## Acceptance criteria
- [x] Event muncul di search ≤ 60 s p95. *(Integrasi Kafka 3.9 + Karapace + OpenSearch 2.19: p50 3,4 s, p95 5,5 s untuk 200 event; dominan `refresh_interval` 5 s. Histogram `event_index_delay_seconds` + alert SLO.)*
- [x] Test privasi: event dengan raw content ditolak dan dihitung di metrik. *(`events_rejected_total{reason}`: `raw_content`, `unredacted_snippet`, `schema`, `wire_format`, `unknown_schema`; diuji unit + integrasi, tidak ada yang masuk index.)*
- [x] Metrik `kafka_consumer_lag` tersedia. *(Per partisi dari offset group yang di-commit, refresh 10 s; `/metrics` di event-ingest.)*

## Keputusan
- Apache Kafka 3.9 (KRaft) + **Karapace** (Apache-2.0, API Confluent) sebagai schema registry. Confluent SR (lisensi community) dan Redpanda (BSL) tidak memenuhi "OSS standar" ADR-0001.
- Kontrak `internal/events`: JSON Schema `decision_event.v1.json` (tertutup: `additionalProperties: false`), subject `wantimpres26.decision_event.v1-value`, wire format Confluent. Producer (untuk PEP) mendaftarkan schema, memvalidasi sebelum kirim, key = tenant_id.
- Consumer hanya menerima schema id yang terdaftar di subject kita: schema longgar dari subject lain ditolak (`unknown_schema`).
- Raw content = nama field terlarang di mana pun (daftar yang sama dengan log, `internal/privacy`), atau snippet berisi ≥ 12 digit berurutan (NIK/PAN belum di-redact). Event yang ditolak hanya dihitung dan dicatat partition/offset-nya, tidak disimpan.
- At-least-once: offset di-commit setelah bulk OpenSearch sukses; `_id` = `event_id` sehingga redelivery tidak menduplikasi. Registry tidak terjangkau → proses restart, tidak menolak event yang valid.
- Index harian `wantimpres26-events-YYYY.MM.DD` (UTC), satu pola untuk semua tenant (`tenant_id` field), mapping `strict`. ISM: hot 90 hari → read-only + force-merge → hapus di 400 hari, otomatis lewat `ism_template`.
- `trace_id` (W3C, 32 hex) wajib di event dan di-index; header `traceparent` menunggu OTel (belum ada span id yang sah).
- franz-go v1.21.7 / kadm v1.18.0: versi terbaru butuh Go 1.26 (sama seperti OPA di ticket 11).

## Hasil verifikasi lokal (2026-10-03)
- `go test -race ./...` dengan semua service integrasi (Postgres, MinIO, Kafka, Karapace, OpenSearch), golangci-lint, trivy config, gitleaks: lulus.
- Image `event-ingest` jalan, join consumer group, `/metrics` menampilkan lag 3 partisi.

## Sisa / follow-up
- Belum ada PEP yang memanggil `events.Producer` (ticket 13 ai-gateway, 28 mcp-gateway).
- Kafka/Karapace/OpenSearch produksi (TLS, SASL/mTLS, auth OpenSearch) di-provision tim platform; client sekarang belum mengonfigurasi TLS/SASL Kafka.
- Warm tier di node khusus (allocation) bila cluster punya node warm; index per tenant bila ada tier yang butuh.
- Pertimbangkan bump Go 1.26 agar bisa memakai OPA/franz-go terbaru.
- `DECISION_EVENT` di Postgres untuk event incident/sampling: ticket 18.
- Ticket 12 menambah field metadata input PDP (opsional) ke `decision_event` v1 dan mapping OpenSearch, untuk simulasi policy.
