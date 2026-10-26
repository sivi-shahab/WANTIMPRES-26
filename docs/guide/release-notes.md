---
title: Release Notes
outline: [2, 3]
---

# Release Notes

Release notes merangkum perubahan yang penting bagi pengguna dan operator: fitur baru, perubahan yang perlu diperhatikan saat upgrade, perbaikan, dan batasan. Daftar lengkap per commit ada di [Changelog](../changelog).

## v0.1.0 (pratinjau) · 26 Oktober 2026

::: info Rilis pratinjau pertama
Rilis pertama yang diberi tag ([`v0.1.0`](https://github.com/sivi-shahab/WANTIMPRES-26/releases/tag/v0.1.0)), mencakup semua pekerjaan sejak awal proyek. Statusnya pratinjau: belum untuk produksi. Sebagian besar tiket berstatus `needs-gitlab-run` (terimplementasi dan teruji lokal, menunggu pipeline rilis GitLab) atau `needs-signoff`. Lihat [Roadmap](./roadmap).
:::

### Sorotan

- **AI gateway** untuk aplikasi internal ke OpenAI, Anthropic, Gemini, dan model self-hosted, dengan inspeksi request dan response streaming, redact, tokenize, block, serta kuota.
- **MCP gateway** untuk agent: validasi audience token, token exchange, tool pinning, persetujuan manusia, dan kill switch.
- **Satu policy decision point (OPA)** dengan bundle bertanda tangan, simulasi, prinsip dua orang, dan rollback.
- **Bukti kepatuhan**: audit log berantai hash, timer pelanggaran data UU PDP, dan pemetaan kontrol ke regulasi Indonesia.
- **Gate NFR M1** terukur: tambahan latensi p95 +22,2 ms, kill switch 1,19 detik, dan RPO PostgreSQL 45,2 detik ([laporan](../nfr/m1-report)).

### Fitur baru

**AI gateway dan deteksi**
- Adapter provider (OpenAI, Anthropic, Gemini, self-hosted), inspeksi, redact/block, dan kuota per aplikasi dan pengguna ([13](../tickets/13-ai-gateway-core-provider-adapters-redact-block-key-vault)).
- Inspeksi response streaming dan deteksi kebocoran system prompt dengan canary ([14](../tickets/14-ai-gateway-inspeksi-response-streaming-sse)).
- Vault tokenisasi FF1 dengan tokenize/detokenize di gateway ([24](../tickets/24-tokenization-vault-fpe-detokenisasi-response)).
- Deteksi L1: normalisasi, validator NIK/KK/NPWP/PAN, deteksi secret, dan endpoint `/scan/text` ([08](../tickets/08-detection-l1-normalisasi-regex-validator-secrets)).
- Deteksi L2: NER data pribadi dan classifier prompt injection dalam satu pass, di CPU, dalam *shadow mode* ([09](../tickets/09-detection-l2-ner-pii-indonesia-inggris), [10](../tickets/10-detection-l2-prompt-injection-jailbreak-classifier-v1)).
- Fingerprint dokumen rahasia, inline dan untuk data tersimpan ([37](../tickets/37-similarity-fingerprint-dokumen-rahasia)).
- Tuning detektor per tenant dengan active learning dan rollout bertahap ([38](../tickets/38-custom-classifier-per-tenant-active-learning)).

**Agent dan MCP**
- MCP gateway: audience token, token exchange, kebijakan tool, dan inspeksi ([28](../tickets/28-mcp-gateway-core-authz-token-exchange-inspeksi)).
- Tool pinning, scan tool poisoning, dan persetujuan ulang saat definisi tool berubah ([29](../tickets/29-mcp-scan-tool-description-deteksi-rug-pull)).
- Persetujuan manusia (HITL) dan kill switch ([30](../tickets/30-hitl-approval-kill-switch)).
- Agent registry dengan workload identity dan antrean shadow agent ([27](../tickets/27-agent-registry-workload-identity)).
- Inspeksi penulisan memori agent ([44](../tickets/44-memory-context-poisoning-agent)) dan analitik perilaku agent ([39](../tickets/39-agent-behavior-analytics)).

**Kebijakan dan risiko**
- OPA sebagai PDP, bundle kebijakan bertanda tangan, dan Policy Service ([11](../tickets/11-opa-pdp-input-kanonik-precedence-bundle-bertanda-tangan)).
- Siklus kebijakan: versi, prinsip dua orang, simulasi, rollback, dan exception ([12](../tickets/12-policy-lifecycle-versi-4-eyes-simulasi-rollback-exception)).
- Skor risiko dengan critical override dan agregasi 14 hari ([17](../tickets/17-risk-scoring-v1-critical-overrides)), plus kalibrasi bobot dari verdict triage SOC ([25](../tickets/25-kalibrasi-risk-scoring-dengan-label-triage-soc)).

**Data tersimpan dan shadow AI**
- Connector SDK, connector M365, ekstraksi file, dan scan oversharing ([31](../tickets/31-connector-sdk-m365-connector-analisis-oversharing)).
- Connector Google Drive, object storage, dan compliance API AI ([32](../tickets/32-connectors-google-workspace-cloud-storage)).
- Remediation dengan persetujuan, dry run, dan undo ([33](../tickets/33-remediation-actions-untuk-data-at-rest)).
- Baseline shadow AI dari log proxy dan DNS ([03](../tickets/03-baseline-shadow-ai-dari-log-proxy-swg-dns)), katalog aplikasi AI dengan feed bertanda tangan ([16](../tickets/16-ai-app-catalog-status-sanction)), dan deteksi bypass gateway ([43](../tickets/43-paksa-trafik-llm-lewat-ai-gateway)).

**Insiden, audit, dan kepatuhan**
- Manajemen insiden: dedup, state machine, SLA, dan unmask yang diaudit ([18](../tickets/18-incident-management-dasar)).
- Rantai insiden, timer pelanggaran data UU PDP, containment, dan ITSM/SOAR ([26](../tickets/26-incident-lanjut-korelasi-breach-timer-uu-pdp-soar-itsm)).
- Audit log append-only berantai hash dengan anchor WORM ([07](../tickets/07-audit-log-append-only-dengan-hash-chain-anchor-worm)).
- Modul compliance: library framework, bukti, riwayat kontrol, dan laporan ([34](../tickets/34-compliance-module-framework-library-evidence-report)).
- API posture ([20](../tickets/20-posture-dashboard-v1)), export SIEM ([19](../tickets/19-integrasi-siem-cef-syslog-http)), dan pipeline `decision_event` lewat Kafka, schema registry, dan OpenSearch ([15](../tickets/15-event-pipeline-kafka-schema-opensearch-retensi)).

**Identitas dan keamanan platform**
- SSO lewat Keycloak, SCIM, RBAC/ABAC, dan step-up untuk izin sensitif ([06](../tickets/06-identity-sso-oidc-saml-scim-rbac-abac)).
- mTLS antar-service, NetworkPolicy default-deny, dan penandatanganan bundle lewat KMS ([40](../tickets/40-service-authn-mtls-networkpolicy-bundle-key-hsm)).
- TLS dan SASL wajib untuk Kafka dan OpenSearch ([41](../tickets/41-kafka-opensearch-tls-sasl-acl)), serta row-level security PostgreSQL per tenant ([42](../tickets/42-postgres-rls-tenant)).
- Unmask dibatasi per unit, region, dan clearance, dengan prinsip dua orang untuk data `restricted` ([45](../tickets/45-unmask-abuse-volume-abac-four-eyes)).

**Operasional**
- Pipeline GitLab dan admission untuk image bertanda tangan ([05](../tickets/05-repo-skeleton-pipeline-ci-cd-supply-chain)); workflow GitHub Actions yang mencerminkan lint, test, dan scan.
- Harness NFR (load, chaos, soak, DR) dan laporan gate M1 ([21](../tickets/21-nfr-gate-m1-load-soak-chaos-dr)).
- Diagram arsitektur interaktif dan situs dokumentasi dua bahasa.

### Perubahan yang perlu diperhatikan

- **Nama proyek berganti dari `aisec` menjadi WANTIMPRES-26.** Semua identifier memakai `wantimpres26`: modul Go, paket Rego, namespace Kubernetes, topik Kafka, nama index, dan header HTTP `X-Wantimpres26-*`. Integrasi yang membaca header atau topik lama perlu diperbarui.
- **Prefix canary system prompt** sekarang `WTP26-`.
- **Trust domain SPIFFE** sekarang `wantimpres26.bank`; PKI uji model-inference sudah diterbitkan ulang.
- **Go 1.26** sekarang wajib, untuk build lokal maupun CI.

### Perbaikan dan performa

- Gateway tidak lagi berhenti melayani saat Kafka mati; event dikirim asinkron dan event yang hilang dihitung di `decision_events_dropped_total` ([46](../tickets/46-gateway-hang-saat-kafka-down)).
- Waktu tunggu Redis dibatasi dengan fallback per replika, sehingga p95 tetap rendah saat Redis mati ([48](../tickets/48-latensi-gateway-saat-redis-down)).
- Biaya evaluasi OPA per keputusan dipangkas setengah: p99 3,8–4,4 ms dan throughput 125 RPS per pod ([47](../tickets/47-optimasi-pdp-throughput-per-pod)).
- Perbaikan dua test yang gagal di bawah `-race`, slug folder karantina di test remediation, dan image MinIO di CI GitHub.

### Keamanan

- **CVE-2026-78669** diperbaiki dengan pindah ke Go 1.26 dan `golang.org/x/net` v0.60.0. govulncheck tidak lagi menemukan kerentanan yang terjangkau.
- Semua pengecualian scanner (gitleaks, Semgrep, Trivy) sudah direview dan dibatasi ke lokasi masing-masing.
- Kebijakan keamanan baru: laporkan kerentanan lewat *private vulnerability reporting* GitHub ([Kebijakan Keamanan](./security)).

### Batasan yang diketahui

- Deteksi L2 baru berjalan dalam *shadow mode* ([49](../tickets/49-detection-l2-di-jalur-pep)).
- Scan file baru memeriksa 2 MiB teks pertama ([50](../tickets/50-scan-file-hanya-2mib-teks-pertama)).
- Mode gagal untuk bundle kebijakan yang kedaluwarsa lebih dari 24 jam belum diterapkan ([51](../tickets/51-fail-mode-bundle-kedaluwarsa-24-jam)).
- Throughput 125 RPS per pod, di bawah target 300 RPS ([47](../tickets/47-optimasi-pdp-throughput-per-pod)).
- Browser extension, adapter ICAP, dan endpoint agent ditunda ([22](../tickets/22-browser-extension-prompt-paste-upload-coaching), [23](../tickets/23-web-proxy-adapter-icap-reqmod-respmod), [36](../tickets/36-endpoint-agent-windows-macos)). Belum ada UI admin.
