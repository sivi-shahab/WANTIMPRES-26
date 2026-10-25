---
title: Cara Menggunakan
outline: [2, 3]
---

# Cara Menggunakan WANTIMPRES-26

Panduan ini dibagi per tugas. Pilih bagian yang sesuai dengan peran Anda:

| Saya ingin… | Bagian | Untuk |
|---|---|---|
| Mencoba platform di laptop | [Coba di lokal](#coba-di-lokal) | Semua |
| Menghubungkan aplikasi ke LLM lewat gateway | [Hubungkan aplikasi](#hubungkan-aplikasi-ke-ai-gateway) | AI engineer |
| Mendaftarkan aplikasi dan provider baru | [Daftarkan aplikasi](#daftarkan-aplikasi-dan-provider) | Security admin |
| Menghubungkan agent ke MCP server | [Hubungkan agent](#hubungkan-agent-lewat-mcp-gateway) | Agent owner |
| Membuat dan merilis kebijakan | [Kelola kebijakan](#kelola-kebijakan) | DLP analyst, policy approver |
| Menangani insiden dan bukti kepatuhan | [Operasional](#operasional-soc-dan-compliance) | SOC, DPO, auditor |
| Memetakan shadow AI dan data tersimpan | [Shadow AI & data at rest](#shadow-ai-dan-data-at-rest) | Security admin |

::: info Konvensi
Contoh di halaman ini memakai `aigw.example.internal` untuk AI gateway, `mcpgw.example.internal` untuk MCP gateway, dan `cp.example.internal` untuk control-plane. Ganti dengan alamat di lingkungan Anda.
:::

## Coba di lokal

Cara tercepat adalah harness NFR. Harness ini menjalankan AI gateway beserta OPA, detection-svc, Kafka, Redis, OpenSearch, dan provider tiruan yang kompatibel dengan OpenAI. Butuh Docker.

```sh
deploy/nfr/run.sh up      # build image dan bundle bertanda tangan, lalu jalankan semuanya
```

Gateway mendengarkan di `localhost:18080`. Kirim permintaan pertama dengan key aplikasi uji `nfr-app-key`:

```sh
curl -i localhost:18080/openai/v1/chat/completions \
  -H 'Authorization: Bearer nfr-app-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"m","messages":[{"role":"user","content":"halo"}]}'
```

Perhatikan header `X-Wantimpres26-Action` di respons. Header ini menunjukkan aksi yang diterapkan (`allow`, `redact`, dan seterusnya). Metrik Prometheus ada di `localhost:18080/metrics`.

```sh
deploy/nfr/run.sh down    # hentikan dan bersihkan
```

::: warning Batas stack lokal
Harness ini hanya menjalankan jalur gateway. Control-plane dan MCP gateway tidak ikut dijalankan, token vault tidak dipasang (aksi `tokenize` jatuh ke `redact`), dan model L2 tidak aktif.
:::

## Hubungkan aplikasi ke AI Gateway

Aplikasi tidak perlu mengganti SDK. Cukup arahkan base URL ke gateway dan pakai **key gateway** milik aplikasi, bukan key provider. Key provider disimpan oleh gateway dan tidak pernah sampai ke aplikasi.

### Format URL

```text
https://aigw.example.internal/<nama-provider>/<path API provider>
```

`<nama-provider>` adalah nilai `name` di konfigurasi gateway (misalnya `openai`, `anthropic`, `gemini`). Endpoint yang didukung:

| Jenis provider (`kind`) | Endpoint | Streaming |
|---|---|---|
| `openai` | `POST v1/chat/completions` | Ya |
| `openai` | `POST v1/responses` | Tidak |
| `openai` | `POST v1/embeddings` | Tidak (request diperiksa, vektor balasan tidak) |
| `anthropic` | `POST v1/messages` | Ya |
| `gemini` | `POST v1/models/<model>:generateContent` (atau `v1beta`) | – |
| `gemini` | `POST …:streamGenerateContent?alt=sse` | Ya |

Model self-hosted (vLLM, Ollama, TGI) memakai `kind: openai`. Gateway tidak memilih atau mengganti model; model tetap ditentukan aplikasi di body request.

### Contoh dengan SDK

::: code-group

```python [OpenAI (Python)]
from openai import OpenAI

client = OpenAI(
    base_url="https://aigw.example.internal/openai/v1",
    api_key=GATEWAY_KEY,                              # key gateway, bukan key OpenAI
    default_headers={"X-Wantimpres26-User": user_id}, # opsional, untuk limit per user
)
resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Ringkas dokumen ini"}],
)
```

```python [Anthropic (Python)]
from anthropic import Anthropic

client = Anthropic(
    base_url="https://aigw.example.internal/anthropic",
    api_key=GATEWAY_KEY,
    default_headers={"X-Wantimpres26-User": user_id},
)
msg = client.messages.create(
    model="claude-sonnet-5-5",
    max_tokens=512,
    messages=[{"role": "user", "content": "Ringkas dokumen ini"}],
)
```

```sh [Gemini (curl)]
curl https://aigw.example.internal/gemini/v1beta/models/gemini-2.5-flash:generateContent \
  -H "x-goog-api-key: $GATEWAY_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"contents":[{"parts":[{"text":"Ringkas dokumen ini"}]}]}'
```

:::

Gateway menerima key dari header pertama yang ditemukan, berurutan: `Authorization: Bearer`, `x-api-key`, `x-goog-api-key`, `api-key`, lalu parameter `?key=`. Jadi header bawaan setiap SDK langsung bekerja.

Header `X-Wantimpres26-User` bersifat opsional. Nilainya di-HMAC sebelum disimpan dan dipakai untuk limit per pengguna.

### Membaca keputusan gateway

Setiap respons membawa dua header:

| Header | Isi |
|---|---|
| `X-Wantimpres26-Action` | Aksi paling ketat yang diterapkan: `allow`, `warn`, `redact`, `tokenize`, atau `block` |
| `X-Wantimpres26-Decision-Id` | ID keputusan, untuk dilacak tim keamanan |

Apa yang dilihat aplikasi untuk tiap aksi:

- **`redact`**: teks sensitif diganti `[REDACTED:<TIPE>]` sebelum dikirim ke provider. Request tetap diteruskan.
- **`tokenize`**: angka sensitif diganti token yang formatnya sama (FPE). Jika aplikasi diizinkan `detokenize`, token di jawaban model dikembalikan ke nilai asli.
- **`block`**: gateway membalas **403** dalam format error milik provider, sehingga SDK melempar error yang biasa. Pesannya menyertakan alasan dan Decision ID. `quarantine` dan `require_approval` juga menjadi block di kanal ini karena tidak ada langkah persetujuan manusia.

Contoh body 403 untuk aplikasi OpenAI:

```json
{"error": {"message": "Request blocked by WANTIMPRES-26 policy [SECRET_TO_AI]. Decision ID: …. Contact the security team if this is unexpected.",
           "type": "wantimpres26_policy_violation", "param": null, "code": "wantimpres26_policy_block"}}
```

Untuk Anthropic tipenya `permission_error`, dan untuk Gemini statusnya `PERMISSION_DENIED`.

**Streaming.** Jika jawaban model melanggar kebijakan di tengah stream, gateway menghentikan stream dengan cara yang sama seperti provider menghentikan konten terfilter: `finish_reason: "content_filter"` (OpenAI), `stop_reason: "refusal"` (Anthropic), atau `finishReason: "SAFETY"` (Gemini), disertai pemberitahuan `[WANTIMPRES-26: response stopped by policy …]`.

### Kode error lain

| Status | Kode | Arti dan tindakan |
|---|---|---|
| 400 | `invalid_json`, `streaming_unavailable` | Body bukan JSON valid, atau streaming diminta di endpoint yang tidak mendukungnya |
| 401 | `invalid_gateway_key` | Key gateway tidak ada atau salah |
| 403 | `provider_not_allowed` | Aplikasi tidak diizinkan memakai provider ini |
| 403 | `wantimpres26_redaction_failed` | Penyamaran gagal; request tidak dikirim |
| 404 | `unknown_provider`, `unsupported_endpoint` | Nama provider atau path tidak dikenal |
| 413 | `request_too_large` | Body melebihi 4 MiB |
| 429 | `rate_limit_exceeded` | Batas request per menit; ulangi setelah `Retry-After` (60 detik) |
| 429 | `token_quota_exceeded` | Kuota token harian habis |
| 502 | `upstream_unavailable` | Provider tidak bisa dihubungi |
| 503 | `wantimpres26_policy_unavailable` | Penimbang kebijakan tidak tersedia dan aplikasi memakai `fail_closed` |

## Daftarkan aplikasi dan provider

Aplikasi dan provider didaftarkan di file JSON yang ditunjuk `AIGW_CONFIG_FILE`. Field yang tidak dikenal ditolak.

```json
{
  "apps": [{
    "id": "chatbot-cs",
    "key_sha256": "<sha256 dari key gateway, 64 hex>",
    "providers": ["openai"],
    "fail_mode": "fail_closed",
    "rpm": 600, "user_rpm": 30,
    "tokens_per_day": 5000000, "user_tokens_per_day": 200000
  }],
  "providers": [{
    "name": "openai",
    "kind": "openai",
    "upstream": "https://api.openai.com",
    "key_file": "/secrets/openai.key",
    "app_id": "chatgpt", "sanction": "sanctioned", "region": "US"
  }]
}
```

Hal yang perlu diperhatikan:

- **Key gateway** tidak disimpan dalam bentuk asli. Buat key acak, berikan ke tim aplikasi, lalu simpan hash-nya:
  ```sh
  printf %s "$GATEWAY_KEY" | sha256sum
  ```
- **`fail_mode`** default `fail_closed`. Pakai `fail_open` hanya untuk aplikasi yang boleh tetap jalan tanpa pemeriksaan kebijakan; setiap kejadian dihitung di metrik.
- **Limit** bernilai `0` berarti tanpa batas. Penghitungnya disimpan di Redis; jika Redis mati, request tetap dilayani.
- **Provider** wajib punya `app_id`, `sanction`, dan `region`. Ketiganya dipakai kebijakan, misalnya untuk menolak data `restricted` ke provider di luar negeri.
- **`key_file`** dibaca ulang otomatis saat file berubah, jadi rotasi key provider tidak perlu restart.
- Opsi lain per aplikasi: `canary` (canary token untuk mendeteksi kebocoran system prompt), `detokenize`, dan `token_ttl_minutes` (default 60).

Egress ke provider LLM sebaiknya hanya diizinkan lewat gateway. Lihat [runbook egress AI gateway](../runbooks/egress-ai-gateway).

## Hubungkan agent lewat MCP Gateway

MCP gateway berada di antara agent dan MCP server. Ia memeriksa argumen dan hasil tool call, menukar token, menahan aksi berisiko untuk persetujuan, dan menjalankan kill switch.

### 1. Daftarkan MCP server

Tambahkan server ke file `MCP_SERVERS_FILE`:

```json
[{"name": "crm", "upstream": "https://crm-mcp.internal/mcp", "audience": "crm-mcp",
  "app_id": "crm-mcp", "sanction": "sanctioned", "region": "ID"}]
```

Agent lalu terhubung ke `https://mcpgw.example.internal/mcp/crm` (Streamable HTTP).

### 2. Daftarkan agent

Daftarkan agent di control-plane dengan `POST /agents`, termasuk identitas workload (`spiffe`, `oidc_client`, atau `managed_identity`) dan daftar tool yang boleh dipakai beserta tingkat risikonya. Agent tanpa pemilik otomatis dikarantina. Skema lengkapnya ada di `internal/agents/store.go`.

### 3. Autentikasi agent

Agent mengirim `Authorization: Bearer <access token OAuth>`. Audience (`aud`) token harus sama dengan resource URI server, yaitu `https://mcpgw.example.internal/mcp/crm`. Jika token tidak ada atau salah, gateway membalas 401 dengan header `WWW-Authenticate` yang menunjuk ke metadata di `/.well-known/oauth-protected-resource/mcp/crm`, sehingga klien MCP yang mengikuti spesifikasi bisa menemukan authorization server sendiri.

Token agent tidak pernah diteruskan ke MCP server. Gateway menukarnya dengan token downstream berumur pendek (RFC 8693).

### 4. Persetujuan tool

Saat agent memanggil `tools/list`, gateway mencatat hash setiap definisi tool. Hanya tool yang sudah disetujui yang terlihat oleh agent. Admin menyetujui atau menolak tool dengan:

```text
POST /mcp/tools/{server}/{name}/approve
POST /mcp/tools/{server}/{name}/reject
```

Jika definisi tool berubah setelah disetujui (*rug pull*), tool kembali harus disetujui.

### 5. Persetujuan manusia untuk aksi berisiko

Jika kebijakan meminta persetujuan, agent menerima error JSON-RPC dengan kode `-32001` dan pesan `approval required: call again with the same arguments once approved`. Field `data` berisi `approval_id`, `state`, dan `expires_at`. Agent yang baik menampilkan status ini ke pengguna, lalu **memanggil ulang dengan argumen yang persis sama** setelah disetujui.

Approver memutuskan lewat control-plane:

```text
POST /approvals/{id}/approve   {"note": "…"}
POST /approvals/{id}/reject    {"note": "…"}
```

Persetujuan terikat pada agent, server, tool, dan hash argumen, hanya bisa dipakai sekali, dan kedaluwarsa setelah 15 menit (atur dengan `APPROVAL_TTL`). Notifikasi ke approver bisa dikirim lewat `APPROVAL_WEBHOOK_URL`.

### 6. Kill switch

```text
POST /agents/{id}/kill         {"reason": "…"}
POST /kills                    {"scope": "…", "target": "…", "reason": "…"}
POST /kills/global             {"reason": "…"}      # izin sensitif agent.kill.global
POST /kills/{id}/lift
```

Sesi yang sedang berjalan langsung diputus. Pemanggil yang terkena kill switch menerima 403 `stopped by kill switch`.

## Kelola kebijakan

### Bentuk aturan

Kebijakan adalah daftar aturan data. Setiap aturan punya kondisi (`when`), aksi, dan alasan. Dua contoh dari template bawaan:

```json
{"id": "tpl.secret-to-any-ai",
 "when": [{"field": "direction", "op": "in", "value": ["request", "tool_call"]},
          {"field": "content.classes", "op": "class_any", "value": ["SECRET.*"]}],
 "action": "block", "reason": "SECRET_TO_AI"}

{"id": "tpl.pci-pan-redact",
 "when": [{"field": "content.classes", "op": "class_any", "value": ["PCI.PAN"]}],
 "action": "redact", "obligations": [{"type": "redact", "classes": ["PCI.PAN"]}],
 "reason": "PCI_PAN"}
```

Urutan aksi dari yang paling longgar: `allow` < `warn` < `redact` < `tokenize` < `require_approval` < `quarantine` < `block`. Jika beberapa aturan cocok, aksi paling ketat yang dipakai. Tambahkan `"mode": "monitor"` untuk mencoba aturan tanpa menegakkannya.

Template bawaan ada di `policy/wantimpres26/rules/data.json`, dan mesin keputusannya di `policy/wantimpres26/decision.rego`.

### Siklus rilis

Semua panggilan ke control-plane memakai token OIDC dengan MFA. Izin sensitif seperti `policy.publish` juga meminta login ulang dan justifikasi minimal 10 karakter di header `X-Justification`.

1. **Buat draft**: `POST /policies` dengan body `{"name": "…", "rules": [ … ]}`. Balasannya berisi `id` dan `version: 1`. Versi berikutnya dibuat dengan `POST /policies/{id}/versions`.
2. **Simulasikan**: `POST /policies/{id}/simulate` dengan body `{"version": 1, "window": {"from": "…", "to": "…"}, "include_corpus": true}`. Hasilnya di `GET /simulations/{id}` dan menunjukkan berapa keputusan yang berubah.
3. **Ajukan**: `POST /policies/{id}/versions/{v}/submit`.
4. **Setujui**: `POST /policies/{id}/versions/{v}/approve` oleh orang **yang berbeda** dari pembuat. Versi langsung aktif dan didistribusikan ke semua titik jaga sebagai bundle bertanda tangan.
5. **Rollback** bila perlu: `POST /policies/{id}/rollback`.

Pengecualian dibuat dengan `POST /exceptions` dan harus disetujui (`POST /exceptions/{id}/approve`). Setiap pengecualian wajib punya tanggal kedaluwarsa.

## Operasional SOC dan compliance

| Tugas | Endpoint control-plane |
|---|---|
| Lihat dan triage insiden | `GET /incidents`, `POST /incidents/{id}/transition` |
| Containment | `POST /incidents/{id}/actions` |
| Lihat bukti (tersamarkan) | `GET /incidents/{id}/evidence/{eid}` |
| Buka bukti asli | `POST /incidents/{id}/evidence/{eid}/unmask-requests`, disetujui orang lain, lalu `GET …/evidence/{eid}/raw` (izin `evidence.unmask`) |
| Pelanggaran data (UU PDP) | `POST /incidents/{id}/breach/declare`, lalu `…/breach/report` untuk draft laporan |
| Posture | `GET /posture` |
| Bukti kepatuhan | `GET /compliance/frameworks`, `…/controls`, `…/report`, `…/ai-register` |

Event juga dikirim ke SIEM oleh `siem-export` lewat syslog/TLS atau HTTP (HEC/JSON), dengan ambang risiko `SIEM_MIN_RISK` (default 40).

Integritas audit log bisa diverifikasi dari CLI:

```sh
control-plane audit anchor --day yesterday
control-plane audit verify --from 2026-10-01 --to 2026-10-25
```

## Shadow AI dan data at rest

**Peta shadow AI** dibuat dari log proxy atau DNS yang sudah ada, tanpa memasang apa pun di jaringan:

```sh
TENANT_PEPPER=… shadow-baseline -format squid -units units.csv -out report/ /var/log/squid/access.log*
```

Format yang didukung: `squid`, `dns`, dan `jsonl`. Hasilnya `report/shadow-baseline.json` dan `.md`.

**Data tersimpan** dipindai oleh `connector-worker`. Sumber yang didukung: Microsoft 365, Google Drive (termasuk audit OAuth grant), S3, GCS, Azure Blob, serta compliance API Claude dan ChatGPT. Hasilnya bisa dilihat di `GET /data/assets` dan `GET /data/summary`. Remediation (misalnya mencabut link publik) diajukan lewat `POST /data/assets/{id}/remediations` dan baru dijalankan setelah disetujui. Saat ini remediation tersedia untuk M365, Google Drive, dan S3.

## Yang belum tersedia

- Browser extension, adapter web proxy (ICAP), dan endpoint agent belum dibangun ([tiket 22](../tickets/22-browser-extension-prompt-paste-upload-coaching), [23](../tickets/23-web-proxy-adapter-icap-reqmod-respmod), [36](../tickets/36-endpoint-agent-windows-macos)).
- Belum ada UI admin; semua pengelolaan lewat API control-plane.
- Detection L2 baru berjalan dalam *shadow mode* ([tiket 49](../tickets/49-detection-l2-di-jalur-pep)).

Daftar lengkap variabel lingkungan per layanan ada di `README.md` dan `cmd/<layanan>/main.go`. Langkah deploy produksi ada di [ADR-0001](../adr/0001-hosting-residency-build-scope) dan runbook.
