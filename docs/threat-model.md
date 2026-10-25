# Threat Model Platform AI-SPM

Tiket 02. Baseline threat model untuk seluruh platform. Threat model per fitur (DoD §3.2 #4) merujuk ke dokumen ini dan hanya menambahkan hal yang spesifik untuk fitur tersebut.

- **Cakupan:** komponen §5.2 sebagaimana ada di repo per 2026-10-10 (commit `ff6af37`), ditambah komponen yang belum dibangun bila sudah ada tiketnya.
- **Asumsi deployment (ADR-0001):** single-tenant tenant-aware, on-prem di DC/DRC bank, tanpa komponen offshore. Kubernetes, satu namespace `wantimpres26`.
- **Rating:** *High* = kebocoran data nasabah/rahasia dalam skala besar, enforcement bisa dilewati, atau integritas audit/policy rusak. *Medium* = dampak terbatas atau butuh akses orang dalam yang sudah berhak. *Low* = lainnya.
- **Status kontrol:** ✅ ada di kode (dengan rujukan), 🎫 ada tiket terbuka, ❌ gap (tiket baru di §6).

## 1. Aset dan trust boundary

| Aset | Di mana | Kenapa penting |
|---|---|---|
| Konten prompt/response/file/tool args | Hanya transit di PEP dan detection; evidence terenkripsi di incident | Data nasabah (UU PDP, POJK 11), rahasia bank |
| Provider API key, token downstream | Vault, MCP gateway (token exchange) | Akses ke LLM/tool atas nama bank |
| Policy bundle + data (katalog, registry, exceptions) | Policy Service → OPA sidecar | Menentukan semua keputusan enforcement |
| Decision event, incident, evidence | Kafka, OpenSearch, Postgres | Bukti untuk SOC, regulator, dan karyawan yang dipantau |
| Audit log | Postgres hash chain + WORM anchor | Akuntabilitas admin dan SOC |
| Identitas: OIDC session, SCIM, workload identity agent | Keycloak, control plane, agent registry | Dasar RBAC/ABAC dan atribusi |
| Model + label tenant | model-inference, tuning | Kualitas deteksi |

Trust boundary:
- **TB1** klien (app, browser, agent, endpoint) → PEP
- **TB2** PEP → provider LLM / MCP server / SaaS (keluar dari DC)
- **TB3** PEP ↔ detection / OPA / control plane (di dalam cluster)
- **TB4** service → Kafka / Postgres / OpenSearch
- **TB5** admin/SOC → Admin API
- **TB6** feed eksternal (katalog, image, model) → platform

## 2. STRIDE per komponen

### 2.1 Data plane (PEP): AI Gateway, MCP Gateway, connector workers, proxy/extension/endpoint

| | Ancaman | Rating | Kontrol |
|---|---|---|---|
| S | Klien memalsukan identitas app/agent untuk memakai policy yang lebih longgar | High | ✅ MCP: verifikasi token OAuth 2.1, audience RFC 8707, tanpa token passthrough, token exchange RFC 8693 (`internal/mcpgw/gateway.go`, tiket 28); workload identity agent, kredensial user bersama ditolak (`internal/agents/store.go`). 🎫 AI gateway: gateway key per app (13). |
| T | Payload diubah supaya lolos deteksi (encoding, homoglyph, zero-width, tag Unicode) | High | ✅ Normalisasi + decode berlapis sebelum scan (`internal/detect/normalize.go`, tiket 08). 🎫 classifier L2 (09, 10). |
| T | Redaction merusak struktur request sehingga app melewati gateway | Medium | 🎫 FR-DLP-1 contract test per provider (13). |
| R | Agent/user menyangkal sebuah aksi | Medium | ✅ Decision event dengan `trace_id`, `decision_id`, `approval_id` (`internal/events/events.go`); audit approval HITL (tiket 30). |
| I | Provider key bocor ke klien atau masuk konteks model | High | ✅ MCP: kredensial downstream berumur pendek, secret tidak masuk konteks. 🎫 AI gateway: key dari vault, tidak pernah ke klien (13). |
| I | Response LLM membocorkan data sensitif atau system prompt | High | 🎫 Inspeksi response non-streaming (13) dan SSE (14), canary FR-PSEC-5 (14). |
| D | Prompt/stream raksasa, loop agent, zip bomb di connector | Medium | ✅ Rate per agent+tool, batas body (`gateway.go`), deteksi lonjakan volume (tiket 39), batas ekstraksi dan Tika tanpa egress (`internal/extract`, `deploy/base/connector-worker.yaml`). 🎫 kuota token per app/user (13). |
| D | Detection/OPA mati → PEP berhenti atau fail-open diam-diam | High | ✅ OPA memakai bundle cache terakhir. 🎫 fail mode per app + `fail_open_total` + chaos test (13, 21). |
| E | **Bypass gateway**: app/user memanggil provider langsung | High | ❌ G4. Provider key yang hanya ada di vault (13) mencegah app resmi, tetapi tidak mencegah key pribadi atau akses dari browser. Lihat §4.1. |
| E | Agent memanggil tool di luar allow-list/scope atau rantai delegasi terlalu dalam | High | ✅ Allow-list, scope parameter, rate, batas `chain_depth` (`internal/toolscope`, tiket 28); HITL untuk tool `high`, kill switch ≤ 10 dtk (tiket 30). |

### 2.2 Detection plane: detection-svc, model-inference, file extraction, tokenization vault

| | Ancaman | Rating | Kontrol |
|---|---|---|---|
| S | Pod lain di cluster memanggil `/scan/text` atau model-inference, lalu memakainya sebagai oracle untuk mengakali detektor | Medium | ✅ G1 (tiket 40): `/scan/text` dan model hanya di port mTLS untuk identitas SPIFFE di `MTLS_ALLOW` (PEP → detection-svc, detection-svc → model-inference), NetworkPolicy default-deny (`deploy/base/networkpolicy.yaml`, diuji `deploy/netpol_test.go`). |
| T | Model atau image detektor diganti | High | ✅ Image bertanda tangan, admission menolak yang tidak bertanda tangan (`deploy/cluster/require-signed-images.yaml`, tiket 05). Model tenant hanya lewat gate §9.4 dan four-eyes (tiket 38). |
| T | Label poisoning: analis jahat/keliru melatih model untuk membuang temuan nyata | Medium | ✅ Holdout beku per kuartal, gate recall ≥ 0,98, rollout shadow → canary (tiket 38). |
| I | Konten mentah tertinggal di log, temp file, atau response error | High | ✅ Field terlarang tidak boleh ada di log/trace (`internal/privacy/forbidden_fields.txt`, dipakai Go dan Python); snippet ter-redact ≤ 200 karakter (`detect.Snippet`); temp file TTL 1 jam. |
| D | Parser exploit, zip bomb, input patologis ke regex | Medium | ✅ Tika terisolasi tanpa egress, batas ukuran/dekompresi (`internal/extract`); regex RE2 (linear time). 🎫 fuzzing parser (21). |
| E | Exploit parser → lateral movement | Medium | ✅ NetworkPolicy `tika-isolated` (ingress hanya dari connector-worker, egress kosong). 🎫 sandbox gVisor (§10.1, belum dipasang). |

### 2.3 Policy: Policy Service, signed bundles, OPA sidecar

| | Ancaman | Rating | Kontrol |
|---|---|---|---|
| S/T | **Bundle policy palsu** atau diubah di jalan, atau dari cache | High | ✅ Bundle ditandatangani, OPA memverifikasi sebelum load; alert `PolicyBundleSignatureInvalid`/`PolicyBundleLoadFailing` (`deploy/base/opa/opa.yaml`, `deploy/cluster/alerts.yaml`, tiket 11). Lihat §4.2. |
| T | Policy jahat dipublikasikan oleh orang dalam | High | ✅ 4-eyes (author ≠ approver), simulasi diff, step-up untuk `policy.publish`, audit, rollback (tiket 12); alert `PolicyReleaseDiverged`. |
| T | Exception dipakai sebagai backdoor permanen | Medium | ✅ Wajib kedaluwarsa (≤ 90 hari), notifikasi H-7, alert `PolicyExceptionsExpiring` (tiket 12). |
| R | Siapa mengubah policy dan kapan | Medium | ✅ Audit log hash chain + WORM anchor (tiket 07); ekspor ke SIEM (tiket 19). |
| I | Bundle berisi data katalog, registry agent, dan exception dapat diunduh siapa saja di jaringan (`GET /bundles/wantimpres26.tar.gz` public) | Medium | ✅ G1 (tiket 40): `/bundles` hanya di port mTLS control-plane untuk identitas pod yang punya sidecar OPA; tidak ada di admin API. |
| I | Decision log OPA memuat konten | High | ✅ `mask_decision` dengan daftar field terlarang yang sama (`policy/system/log/mask.rego`, ada test). |
| D | Policy Service mati → bundle tidak diperbarui | Medium | ✅ OPA memakai cache terakhir. 🎫 fail-mode bila bundle kedaluwarsa > 24 jam (13, §13.3). |

### 2.4 Control plane: Admin API, identity (Keycloak/SCIM), agent registry, incident, lifecycle, compliance, audit

| | Ancaman | Rating | Kontrol |
|---|---|---|---|
| S | Pengambilalihan akun admin/SOC | High | ✅ SSO OIDC via Keycloak, MFA di IdP, step-up re-auth untuk permission sensitif (`internal/authz`, tiket 06); break-glass diaudit + alert `BreakGlassUsed`. |
| T | Audit log diubah atau dihapus | High | ✅ Append-only, hash chain, anchor WORM, alert `AuditAnchorMissing` (tiket 07). |
| R | Analis menyangkal telah membuka evidence | Medium | ✅ Audit ditulis sebelum plaintext ada; akses ditolak juga diaudit (`internal/incident/store.go` `Unmask`). |
| I | **Abuse unmask evidence** | High | ✅ sebagian. Lihat §4.5. ❌ G6. |
| I | **Tenant crossover** | Medium (single-tenant) | ✅ G3 (tiket 42, ADR-0003): RLS di-FORCE pada setiap tabel ber-`tenant_id` dan anaknya, tenant dipatok per koneksi (`internal/tenantdb`), diuji `TestRowLevelSecurity`. Lihat §4.4. |
| D | Banjir request ke Admin API | Low | Ingress bank + autentikasi wajib. |
| E | Role sendiri dinaikkan lewat SCIM atau Admin API | High | ✅ Binding role ke user/grup hanya oleh permission `identity.admin` dan diaudit (`internal/authz/roles.go`, `internal/identity`); permission sensitif butuh step-up + justifikasi. |

### 2.5 Analytics: Kafka, event-ingest, OpenSearch, SIEM export

| | Ancaman | Rating | Kontrol |
|---|---|---|---|
| S/T | Producer palsu menyuntik decision event (insiden palsu, atau membanjiri SOC untuk menyamarkan serangan nyata) | High | ✅ Schema registry, validasi schema, alert `EventsRejected` (tiket 15). ❌ G2: Kafka tanpa TLS/SASL dan ACL topic di sisi client. |
| T | Event dihapus atau diubah di OpenSearch | Medium | ✅ Incident dan audit di Postgres sebagai sumber kebenaran; event juga diekspor ke SIEM (tiket 19). ❌ G2: auth OpenSearch. |
| I | **Kebocoran lewat log/telemetry** | High | ✅ Lihat §4.3. |
| D | Ingest tertinggal sehingga deteksi insiden terlambat | Medium | ✅ Alert `EventIngestLagging`, `EventSearchSLOBreached`; DLQ SIEM + `SIEMRecordsDeadLettered`. |

## 3. Mapping OWASP LLM Top 10 (2025) dan Agentic Top 10 (ASI, 2026)

| ID | Ancaman | Kontrol spec | Status |
|---|---|---|---|
| LLM01 | Prompt injection | FR-PSEC-1..4, 6, FR-AGT-3 inspeksi tool result, taint → HITL | ✅ L1 injection (08), taint MCP (28). 🎫 classifier L2 (10), corpus (04). |
| LLM02 | Sensitive information disclosure | FR-CLS, FR-DLP, residency ADR-0001 | ✅ L1 PII-ID/PCI/secrets (08), fingerprint dokumen (37). 🎫 NER (09), AI gateway (13), SSE (14), tokenize (24). |
| LLM03 | Supply chain | §12.2, katalog/bundle bertanda tangan | ✅ Image signing + admission (05), feed katalog bertanda tangan (16), pin definisi tool MCP (29). |
| LLM04 | Data & model poisoning | §9.3–9.4 | ✅ Gate + holdout beku (38). 🎫 corpus provenance (04). |
| LLM05 | Improper output handling | FR-PSEC-7 | 🎫 Inspeksi response (13, 14). MCP tool result sudah diinspeksi (28). |
| LLM06 | Excessive agency | FR-AGT-4, 6, 7 | ✅ Allow-list/scope/rate/chain depth (28), HITL + kill switch (30). |
| LLM07 | System prompt leakage | FR-PSEC-5 | 🎫 Canary + n-gram overlap (14). |
| LLM08 | Vector & embedding weaknesses | FR-AGT-9, FR-PSEC-2 | 🎫 Scan `/v1/embeddings` (13). ❌ G5: inspeksi tulis ke memory/vector store. |
| LLM09 | Misinformation | Non-goal v1 (§1.4) | Diterima: kebenaran output model di luar cakupan platform. |
| LLM10 | Unbounded consumption | FR-PSEC-9 | ✅ Rate per agent/tool, deteksi lonjakan (28, 39). 🎫 kuota token per app/user (13). |
| ASI01 | Agent goal hijack | FR-PSEC-2, FR-AGT-6 | ✅ Taint injection → tool high wajib approval (28, 30); deteksi urutan tak lazim (39). |
| ASI02 | Tool misuse | FR-AGT-4 | ✅ Scope parameter, risk tool (28). |
| ASI03 | Identity & privilege abuse | FR-AGT-2, 5 | ✅ Workload identity (27), token exchange, TTL ≤ 15 menit, tanpa passthrough (28). |
| ASI04 | Agentic supply chain | FR-AGT-3 | ✅ Scan poisoning definisi tool, pin hash, re-approval saat berubah (29). |
| ASI05 | Unexpected code execution | FR-PSEC-7 | 🎫 Deteksi payload script/SQL/shell di response (13, 14). Tool eksekusi kode = `tool_risk=high` → HITL (30). |
| ASI06 | Memory & context poisoning | FR-AGT-9 | ❌ G5. |
| ASI07 | Insecure inter-agent communication | FR-AGT-3, 4 | ✅ Token exchange dengan klaim `act` bersarang, batas `chain_depth` (28). |
| ASI08 | Cascading failures | FR-AGT-7 | ✅ Kill switch (30), deteksi lonjakan volume (39). |
| ASI09 | Human-agent trust exploitation | FR-AGT-6 | ✅ Approver melihat parameter lengkap (redacted sesuai hak), timeout → deny (30). |
| ASI10 | Rogue agents | FR-AGT-1, 7 | ✅ Antrean shadow agent (27), behavior analytics → insiden (39), kill switch (30). |

## 4. Threat model khusus

### 4.1 Bypass gateway (High)
**Skenario:** app internal memakai provider key milik developer langsung ke `api.openai.com`; karyawan memakai ChatGPT pribadi di browser; agent dikonfigurasi langsung ke MCP server tanpa MCP gateway.

**Kontrol yang ada:** MCP server internal hanya menerima token yang audience-nya gateway (28), sehingga agent yang melewati gateway tidak punya token yang valid. Shadow agent dari trafik MCP masuk antrean review (27). Shadow AI dari log SWG/DNS (03, 16).

**Kontrol yang direncanakan:** provider key hanya di vault (13), proxy/extension untuk browser (22, 23).

**Gap (G4):** belum ada aturan egress yang memaksa trafik ke domain provider LLM lewat AI gateway, dan belum ada sinyal posture "trafik langsung ke provider dari subnet server". Tanpa ini, AI gateway bersifat opsional.

### 4.2 Bundle policy palsu (High)
**Skenario:** penyerang di jaringan menyajikan bundle yang mengizinkan semua; orang dalam menaruh bundle di cache sidecar; kunci tanda tangan dicuri.

**Kontrol:** OPA memverifikasi signature setiap bundle, termasuk dari cache disk; bundle tanpa signature valid tidak dimuat dan memicu alert (11). Kunci privat hanya di-mount ke control-plane secara read-only; public key lewat ConfigMap. Publish butuh 4-eyes (12).

**Sisa risiko:** (tiket 40) kunci privat ada di Vault transit dengan backing HSM, bukan file di pod. Yang ada di pod adalah token Vault berizin `sign` saja. Siapa pun yang bisa membaca token itu bisa menandatangani selama token berlaku. Mitigasi: TTL pendek dan diperbarui oleh Vault agent, audit device Vault, dan RBAC namespace. Rotasi tanpa downtime lewat dua slot kunci (`docs/runbooks/rotasi-kunci-bundle.md`).

### 4.3 Kebocoran lewat log/telemetry (High)
**Skenario:** konten prompt masuk ke log aplikasi, decision log OPA, trace, pesan error, event Kafka, atau SIEM.

**Kontrol:**
- Satu daftar field terlarang (`internal/privacy/forbidden_fields.txt`) dipakai Go, Python, dan mask OPA.
- Event hanya membawa metadata, HMAC, dan snippet ter-redact ≤ 200 karakter (§10.2).
- Alert `EventsWithRawContent` bila ingest menemukan konten mentah.
- Evidence mentah hanya per policy forensik, terenkripsi DEK per insiden, TTL 30 hari (18).
- Tidak ada telemetri offshore (ADR-0001).

**Sisa risiko:** konten yang lolos dengan nama field lain (misalnya stack trace yang memuat argumen). Mitigasi: alert `EventsWithRawContent` sebagai detektor; uji leak di CI (tiket 38 memperbaiki uji leak datascan).

### 4.4 Tenant crossover (Medium untuk deployment single-tenant)
**Skenario:** query tanpa filter `tenant_id`, HMAC lintas tenant, atau model tenant terpakai di tenant lain.

**Kontrol:** filter `tenant_id` di query store (incident, tuning, similarity); HMAC dan feature hash dengan pepper per tenant; uji isolasi dua tenant (38).

**Gap (G3):** ADR-0001 U11 menetapkan RLS PostgreSQL di semua tabel sebagai defense-in-depth, tetapi belum ada satu pun policy RLS. Isolasi saat ini hanya bergantung pada setiap query yang benar. `authz.Caller` juga tidak membawa tenant. Dampaknya rendah selama satu deployment = satu bank, tetapi deviasi dari ADR harus ditutup atau ADR diubah.

**Status G3 (tiket 42):** ditutup oleh ADR-0003. RLS berlaku pada data per tenant; data konfigurasi deployment diisolasi per database; audit log di luar RLS (satu hash chain). Sisa: pemisahan role pemilik/migrasi dan role aplikasi.

### 4.5 Abuse unmask evidence (High)
**Skenario:** analis SOC berhak `evidence.unmask` membuka evidence di luar kasusnya, misalnya prompt atasan, rekan kerja, atau data nasabah tertentu, secara massal atau berulang.

**Kontrol:** permission khusus, step-up re-auth, justifikasi minimal, audit sebelum plaintext ada (ditolak juga diaudit), ekspor audit ke SIEM (`SIEMAuditExportLagging`), dekripsi dengan DEK per insiden, evidence kedaluwarsa 30 hari (06, 07, 18).

**Gap (G6):** belum ada deteksi volume/pola unmask per analis (alert hanya ada untuk break-glass). ABAC belum diterapkan pada unmask: pemeriksaan memakai `authz.Resource{}` kosong, sehingga atribut unit bisnis dan region (§10.1) tidak membatasi insiden mana yang boleh dibuka. Tidak ada four-eyes untuk evidence `restricted`.

## 5. Ancaman High dan penanganannya

| Ancaman High | Ditangani oleh |
|---|---|
| Spoofing app/agent di PEP | 28, 27 ✅; 13 🎫 |
| Evasion via encoding | 08 ✅; 09, 10 🎫 |
| Kebocoran provider key | 28 ✅; 13 🎫 |
| Kebocoran via response / system prompt | 13, 14 🎫 |
| Fail-open diam-diam | 13, 21 🎫 |
| Bypass gateway | **G4 → tiket 43** |
| Tool di luar scope | 28, 30 ✅ |
| Image/model diganti | 05, 38 ✅ |
| Konten mentah di log | privacy, 15, 18 ✅ |
| Bundle palsu, policy jahat | 11, 12 ✅; kunci di HSM → **tiket 40** |
| Decision log OPA | 11 ✅ |
| Pengambilalihan akun admin, eskalasi role | 06 ✅ |
| Audit log diubah | 07 ✅ |
| Abuse unmask | 18 ✅ sebagian; **G6 → tiket 45** |
| Event palsu ke Kafka | 15 ✅ sebagian; **G2 → tiket 41** |
| Memory/context poisoning (ASI06, LLM08) | **G5 → tiket 44** |

## 6. Gap → tiket baru

| Gap | Tiket | Prioritas |
|---|---|---|
| G1 Service-to-service authN: mTLS/SPIFFE, NetworkPolicy default-deny di namespace, `/bundles` dan endpoint detection hanya untuk workload yang berhak, kunci tanda tangan bundle di KMS/HSM | 40 | P1 |
| G2 Kafka/OpenSearch: TLS + SASL/mTLS di client, ACL topic per producer, auth OpenSearch | 41 | P1 |
| G3 RLS PostgreSQL sesuai ADR-0001 U11, atau ADR diubah | 42 | P2 |
| G4 Paksa trafik LLM lewat AI gateway: aturan egress + sinyal posture trafik langsung ke provider | 43 | P1 |
| G5 FR-AGT-9: inspeksi tulis ke memory agent / vector store dan provenance | 44 | P1 |
| G6 Unmask: alert volume/pola per analis, ABAC atribut unit/region, four-eyes untuk evidence `restricted` | 45 | P1 |

## 7. Pemeliharaan
- Fitur baru menambah baris STRIDE di komponen terkait atau di dokumen threat model fiturnya, dengan rujukan ke sini.
- Tinjau ulang setiap milestone (M1, M2, …) dan saat OWASP merilis versi baru LLM/ASI Top 10.
