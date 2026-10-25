# 13: AI Gateway core: provider adapters, redact/block, key vault

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 08, 11
Spec: `../spec.md` §4.6; §5.4; §7.1; §8.7; §10.1 Secrets

## Konteks
PEP P0 untuk app-to-LLM.

## Scope
- Endpoint kompatibel: `/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`, `/v1/messages`, `:generateContent`, dan passthrough self-hosted.
- AuthN app via gateway key; provider key diambil dari vault dan tidak pernah dikirim ke klien.
- Alur: normalize → scan → OPA → allow/warn/redact/block; redaction menjaga JSON dan `messages[]` tetap valid.
- Block memakai HTTP 403 dengan body berformat error provider + header `X-Wantimpres26-Decision-Id`, `X-Wantimpres26-Action`.
- Rate limit dan kuota token per app/user (FR-PSEC-9) via Redis.
- Konfigurasi fail mode per app (§13.3).
- Input `destination.hosting_region` dan `destination.ojk_approval_ref` dari katalog (tiket 16) dikirim ke OPA untuk residency policy (ADR-0001).

## Acceptance criteria
- [x] Contract test golden request/response per provider. *(`TestContract` + `internal/aigw/testdata/`: OpenAI chat/responses/embeddings, self-hosted OpenAI-compatible, Anthropic messages, Gemini generateContent. Request sampai ke provider utuh dengan key provider di header yang benar, tanpa key gateway/cookie app; response kembali utuh dengan header keputusan; event per arah lolos schema.)*
- [x] Overhead p95 ≤ 80 ms, p99 ≤ 200 ms (text ≤ 8K token) pada load test. *(`TestOverhead`, prompt 32 KB ≈ 8K token, 300 request, policy asli dievaluasi: p50 14,5 ms, p95 20,7 ms, p99 23,1 ms. Diukur dengan PDP in-process; sidecar OPA menambah satu hop loopback. Load test multi-replika + Redis di tiket 21.)*
- [x] SDK resmi OpenAI/Anthropic tidak crash saat menerima block. *(`testdata/sdk_smoke.py` dengan openai 3.28.0 dan anthropic 1.13.0 terhadap `TestServeForSDK`: block → `PermissionDeniedError` 403 dengan `x-wantimpres26-decision-id`; request bersih → `ChatCompletion`/`Message` ter-parse; stream → `BadRequestError` 400.)*
- [x] Chaos test: detection/OPA mati → perilaku sesuai fail mode. *(`TestFailMode`: PDP mati → app `fail_closed` dapat 503 format provider dan provider tidak dipanggil; app `fail_open` diteruskan, event `FAIL_OPEN`, metrik `aigw_fail_open_total`, alert `AIGatewayFailOpen`. Detection L1 berjalan in-process, jadi tidak bisa mati terpisah dari gateway.)*
- [x] Prompt `restricted` ke provider offshore di-block; `confidential` ter-redact sebelum keluar. *(`TestResidency` dengan policy asli: 12 NIK ke OpenAI (region US dari katalog) → 403 `RESIDENCY_RESTRICTED_OFFSHORE`; NIK + HP → di-redact, `messages[]` tetap 2 dan JSON valid; model self-hosted region ID menerima apa adanya. Setelah redaksi, gateway memindai ulang dan mem-block bila kelas yang wajib dihapus masih ada (ADR-0001).)*

## Out of scope
Response streaming (tiket 14) dan tokenize (tiket 24).

## Keputusan
- **`internal/aigw` + `cmd/ai-gateway`.** Route `/<provider>/<path API>`; app mengarahkan `base_url` SDK ke sana. Provider dikonfigurasi di `AIGW_CONFIG_FILE` (kind `openai|anthropic|gemini`, upstream, `key_file`, `app_id` katalog, fallback sanction/region). Self-hosted (vLLM/Ollama) = kind `openai`. Azure OpenAI lewat path `/openai/v1` dengan `auth: api-key`.
- **AuthN app:** gateway key di header yang biasa dipakai SDK-nya (`Authorization: Bearer`, `x-api-key`, `x-goog-api-key`, `?key=`), disimpan sebagai SHA-256 dan dibandingkan constant-time. Header auth, cookie, dan `?key=` app tidak pernah diteruskan.
- **Key provider dari file Vault agent** (`KeyFiles`), dibaca ulang saat mtime berubah. Rotasi tanpa restart.
- **Inspeksi hanya teks yang dibaca model**: per endpoint ditentukan root-nya (`messages`, `input`/`instructions`, `system`, `contents`/`systemInstruction`; response `choices`/`output`/`content`/`candidates`). Role, id, dan media base64 dilewati. Logika walk/scan/redact dipindahkan dari `mcpgw` ke `internal/inspect` dan dipakai kedua gateway.
- **Aksi:** allow/warn → teruskan; redact/tokenize → redaksi di tempat (tokenize = redact sampai tiket 24), lalu pindai ulang dan block bila belum bersih; block/quarantine/require_approval → 403 format error provider (`wantimpres26_policy_violation` / `permission_error` / `PERMISSION_DENIED`) dengan `X-Wantimpres26-Decision-Id` dan `X-Wantimpres26-Action`. Tidak ada konten di pesan error.
- **Response** non-streaming diinspeksi dengan alur yang sama sebelum sampai ke app. Error provider diteruskan apa adanya. Embeddings tidak diinspeksi di sisi response (isinya vektor).
- **Streaming ditolak** dengan 400 format provider sampai tiket 14, bukan diteruskan tanpa inspeksi.
- **Principal:** `X-Wantimpres26-User` dari app → `user` (HMAC); tanpa itu → `service` (HMAC nama app). Nama app pemanggil dicatat di field event baru `source_app` (schema, struct, index OpenSearch).
- **Rate limit dan kuota token (FR-PSEC-9):** rpm per app dan per user (request yang ditolak ikut dihitung), token per hari per app dan per user dari `usage` provider (fallback estimasi). Counter di Redis (`REDIS_URL`, go-redis) atau in-memory per replika. Redis mati → tidak membatasi dan dicatat di log: ini kontrol ketersediaan, bukan kontrol data. `content.tokens` juga dikirim ke PDP.
- **Fail mode per app** (`fail_open` | `fail_closed`, default `fail_closed`). Event `FAIL_OPEN`/`FAIL_CLOSED` dengan `policy_version: unavailable`, metrik di `/metrics`, alert di `deploy/cluster/alerts.yaml`.
- **Residency:** gateway mengirim `destination {app_id, sanction, region}`; `wantimpres26.dest` mengganti sanction/region dari katalog dan sekarang juga membawa `ojk_approval_ref` (release katalog, schema input, test rego).

## Sisa
- Streaming SSE (14), tokenize/detokenize (24), load/soak/chaos multi-replika + Redis + sidecar OPA (21).
- Deteksi bundle OPA kedaluwarsa > 24 jam → fail mode (§13.3) belum ada; saat ini sidecar terus memakai bundle terakhir dan alert `PolicyBundleLoadFailing` yang memberi tanda.
- Label trust untuk konten untrusted di request (hasil tool/RAG, FR-PSEC-2) belum dibedakan dari instruksi user; skor injection dihitung atas seluruh teks.
- `/metrics` dilayani di port yang sama dengan API; pisahkan bila app tidak boleh melihatnya (G1/tiket 40).
