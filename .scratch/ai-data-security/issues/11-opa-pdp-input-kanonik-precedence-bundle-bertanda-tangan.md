# 11: OPA PDP: input kanonik, precedence, bundle bertanda tangan

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 05
Spec: `../spec.md` §4.7 FR-POL-1..4, FR-POL-9; §13.1

## Konteks
Satu PDP untuk semua PEP (prinsip P2).

## Scope
- Skema input/output kanonik (FR-POL-2/3) sebagai JSON Schema berversi.
- Library Rego untuk precedence: `block > quarantine > require_approval > tokenize > redact > warn > allow` + penggabungan obligations.
- Policy Service membangun dan menandatangani bundle; OPA sidecar memverifikasi dan melakukan long-poll.
- Decision log dengan masking field sensitif.
- Template kebijakan bawaan (FR-POL-8), termasuk template residency ADR-0001: destinasi offshore → `restricted` block, `confidential` redact/tokenize, `internal`/`public` allow hanya untuk app `sanctioned`.

## Acceptance criteria
- [x] `opa test` untuk precedence dan setiap template. *(18 test; juga dijalankan oleh `go test ./internal/policysvc`, jadi ikut job `test:go`.)*
- [ ] `opa bench`: eval p99 ≤ 5 ms di sidecar. *(Laptop WSL2: mean ~2 ms, p99 4,0–5,4 ms; belum lulus meyakinkan. Ukur ulang di node target, ticket 21.)*
- [x] Bundle dengan signature tidak valid ditolak dan memicu alert.
- [x] `opa test` untuk template residency di setiap kombinasi sensitivity × `hosting_region` × status sanction. *(80 kombinasi.)*

## Keputusan
- Rule = data (`policy/wantimpres26/rules/data.json`), engine generik `policy/wantimpres26/decision.rego`. Input tidak valid terhadap JSON Schema → `block` + `INPUT_SCHEMA_INVALID` (fail closed).
- Policy Service = control-plane (`internal/policysvc`): build + sign bundle (ES256, key id `wantimpres26-policy`) saat start, serve `GET /bundles/wantimpres26.tar.gz` dengan ETag + long-poll. Menolak publish bila `rule_errors` tidak kosong. Tanpa signing key, control-plane tidak start.
- Library OPA v1.19.0 (v1.20+ butuh Go 1.26); sidecar OPA 1.21.1, image di-build ulang lewat `build/opa.Dockerfile` agar ikut SBOM + cosign (Kyverno).
- Sidecar: `persist: true` (bundle terverifikasi terakhir bertahan saat restart), readiness `/health?bundles`, decision log di-mask oleh `system/log/mask.rego` dengan daftar `internal/privacy/forbidden_fields.txt` yang diinjeksi builder.
- `json.match_schema` mengompilasi ulang schema tiap eval (~0,9 ms). Validator Rego native dicoba dan lebih lambat (~2 ms), jadi tidak dipakai.

## Hasil verifikasi lokal (2026-10-03)
- `opa test` 18/18, `opa check --strict`, `go test -race`, golangci-lint, trivy config: lulus.
- Docker e2e (control-plane + OPA 1.21.1): bundle diaktifkan, long-poll menahan request (1 load, bukan ribuan), decision log menghapus `/input/prompt`.
- Bundle ditandatangani key lain → `invalid ECDSA signature`; data.json diubah dengan signature lama → `digest mismatch`. Keduanya ditolak, OPA tetap memakai bundle lama, `bundle_failed_load_counter` naik → alert `PolicyBundleSignatureInvalid` (`deploy/cluster/alerts.yaml`).

## Sisa / follow-up
- Provision Secret `policy-bundle-signing` + ConfigMap `policy-bundle-pubkey` (idealnya key di Vault/HSM); PrometheusRule butuh prometheus-operator.
- Alert ke SIEM (ticket 19); decision log ke event pipeline (ticket 15), sekarang ke stdout.
- Bench p99 di hardware target (ticket 21). Opsi bila gagal: strip anotasi schema saat build (~25% lebih cepat di validasi).
- ~~Bundle dibangun sekali saat start~~: ticket 12 membangun bundle dari release di Postgres pada setiap replica.
