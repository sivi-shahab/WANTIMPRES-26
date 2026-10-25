# 28: MCP Gateway core: authz, token exchange, inspeksi

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M3
Blocked by: 27, 08, 11
Spec: `../spec.md` §4.8 FR-AGT-3..5, FR-AGT-8; §7.2; §8.6

## Konteks
PEP untuk agent → tool.

## Scope
- Proxy MCP Streamable HTTP.
- Validasi token sesuai spec MCP 2026-07-28: OAuth 2.1, RFC 9728, RFC 8707 `resource`, audience.
- Tanpa token passthrough: token exchange RFC 8693 ke kredensial downstream TTL ≤ 15 menit.
- Consent per-client (anti confused deputy).
- DLP + injection scan pada tool-call args, tool results, dan resource reads.
- Allow-list tool + constraint parameter + rate limit + batas kedalaman rantai agent.
- Session audit `prompt → tool_call → result` dengan `trace_id`.

## Acceptance criteria
- [x] Test: token dengan audience salah ditolak. *(`TestTokenValidation`: aud server MCP lain, aud tool server, aud origin gateway, tanpa aud, kedaluwarsa, issuer lain, ID token, kunci asing, bukan JWT → 401 + `WWW-Authenticate: Bearer resource_metadata=…` (`error="invalid_token"` bila token ada). Tool server dan STS tidak tersentuh. JWT RS256 asli diverifikasi go-oidc; uji mutasi (cek aud dimatikan) membuat test gagal.)*
- [x] Test: token upstream tidak pernah muncul di request downstream. *(`TestNoTokenPassthrough`: semua request ke tool server (initialize, tools/call, notification) membawa `Bearer down-N` hasil exchange; token agent tidak ada di header mana pun maupun body, termasuk saat diselundupkan lewat `Cookie`/`X-Forwarded-Authorization`/`Proxy-Authorization`. Exchange di-cache per (subject token, audience) dan tidak dipakai lintas token; token downstream > 15 menit ditolak (502, tidak diteruskan). Uji mutasi (meneruskan Authorization) membuat test gagal.)*
- [x] Test: indirect injection di tool result terdeteksi dan diblok/di-redact sesuai policy. *(`TestIndirectInjection`, JSON dan SSE: hasil berisi injection → `isError` tanpa sebutir teks aslinya, event `tool_result` block `INDIRECT_INJECTION` dengan trace_id yang sama dengan `tool_call`; tool high berikutnya di trace itu → `INJECTION_THEN_HIGH_TOOL`, trace lain tidak terdampak; PAN di hasil → `[REDACTED:PCI.PAN]`; `resources/read` ikut diinspeksi. `TestHostileToolServer`: result berupa string/array, injection di pesan error JSON-RPC, id lain, `prompts/get`, halaman error HTML, content type asing: tidak ada yang lolos; ketujuh kebocoran ini tertangkap pada versi sebelum perbaikan.)*
- [x] Suite AgentDojo-style: ASR turun ≥ 70% vs baseline. *(`TestAgentDojoASR`: 160 kasus = 4 user task × 5 tujuan penyerang × 8 gaya payload (important_instructions AgentDojo, ignore_previous, Indonesia, tool_knowledge, fake system turn, base64, komentar HTML, stealth), agen worst-case yang mematuhi instruksi apa pun yang ia baca. ASR baseline 100% → lewat gateway 5,0%: **turun 95%**. Sisa 8 keberhasilan = gaya stealth (tidak menyapa AI) × 2 tujuan yang sengaja di dalam scope registry (overpay payee yang diizinkan, email ke alamat yang diizinkan). Tiga tujuan di luar scope 0%. Utility tanpa serangan 4/4; utility saat diserang 16,2% (baseline 100%) karena hasil yang ber-injection diblok utuh.)*

## Keputusan
- Service baru `mcp-gateway` (`internal/mcpgw`) dengan sidecar OPA sendiri, satu path per tool server: `/mcp/{server}` (POST/GET/DELETE Streamable HTTP) dan PRM RFC 9728 di `/.well-known/oauth-protected-resource/mcp/{server}`. Konfigurasi server (upstream, audience downstream, app_id/sanction/region untuk PDP) dari ConfigMap `mcp-servers`.
- **Token**: tanda tangan (JWKS realm Keycloak lewat discovery), `iss`, `exp`, dan `aud` harus memuat resource URI server ini (RFC 8707); `typ` selain `Bearer` (ID token) ditolak. Identitas workload = `azp` → `client_id` → `sub`. Kedalaman rantai agent = nesting klaim `act` (RFC 8693) di token yang ditandatangani AS, bukan header yang bisa dipalsukan agent.
- **Tanpa passthrough**: header ke tool server di-allow-list (Accept, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-Id) + `Authorization` hasil token exchange RFC 8693 (`subject_token` = token agent, `audience` = audience server, autentikasi client gateway). Token hasil exchange wajib Bearer, bukan token subjek, dan `expires_in` ≤ 900 detik (FR-AGT-5), atau request gagal 502 tanpa diteruskan. 401/403 dari tool server → 502 (tantangan downstream bukan urusan agent).
- **Consent per-client (confused deputy)**: gateway tidak memproksi alur otorisasi dan tidak melakukan dynamic client registration; klien MCP mengambil token langsung dari Keycloak lewat PRM. Kredensial downstream selalu diturunkan dari token klien itu sendiri dan di-cache per token subjek, sehingga tidak pernah dipakai lintas client. Persetujuan per client atas tool = allow-list registry (dibuat owner, diaudit). Delegasi atas nama user mengandalkan "Consent Required" Keycloak per client agent (konfigurasi realm).
- **Registry di bundle**: release `data.wantimpres26.agents` kini membawa `identity` dan `tools[{name, risk, scopes}]`. Paket baru `wantimpres26/mcp` memetakan identity → agent. `wantimpres26/agent` menghitung `tool_allowed` dan memakai risk tool dari registry, bukan klaim PEP. Agent tak terdaftar tidak punya allow-list, jadi `tools/call`-nya diblok, tetapi event tetap tercatat dengan identity-nya agar masuk antrean shadow agent (tiket 27). Sekalian diperbaiki: `risk_tier` untuk agent tak dikenal dulu membuat objek agent undefined.
- **Format scope** (`internal/toolscope`, divalidasi registry saat tulis, ditegakkan gateway): `{"<arg|a.b>": {"max", "min", "in"}, "rate_per_minute": n}`. Argumen yang dibatasi tetapi hilang atau salah jenis = pelanggaran (fail closed); angka berupa string diterima, NaN/Inf tidak.
- **Rule baru** (data, bisa diubah lewat lifecycle tiket 12): `tpl.tool-not-allowed`, `tpl.tool-scope-violation`, `tpl.tool-rate-limit`, `tpl.agent-chain-depth` (≥ 4 hop), `tpl.indirect-injection` (`tool_result` dengan injection ≥ 0,7 → block), `tpl.injection-then-high-tool` (injection ≥ 0,5 di sesi lalu tool high → `require_approval`). Gateway mengirim `hitl_available=false`, jadi `require_approval` = deny sampai tiket 30. Input PDP dan `decision_event` mendapat `scope_violations`, `rate_exceeded`, `chain_depth` (juga di mapping OpenSearch) agar simulasi policy bisa me-replay keputusan ini.
- **Taint sesi**: injection yang terlihat (di argumen maupun hasil) menaikkan `session_injection_max` selama 30 menit, per trace bila agent mempropagasi `traceparent` (satu tugas lintas tool server), selain itu per agent. `Mcp-Session-Id` tidak dipakai karena berbeda per tool server.
- **Inspeksi**: semua string leaf argumen/hasil digabung untuk satu pass `detect.Scan`, lalu redaksi dipetakan kembali per field. Yang diinspeksi: hasil `tools/call` dan `resources/read`, pesan error JSON-RPC, serta (di stream GET/SSE) pesan berbentuk content/contents/messages. Result non-objek atau respons yang tidak bisa dibaca → error (fail closed). Body error HTTP tidak diteruskan. Batch JSON-RPC ditolak. PDP tidak tersedia → deny.
- **Deteksi injection L1** (`internal/detect/injection.go`, bagian dari `detect.Scan` dan respons `POST /scan/text`): aturan ber-anchor EN/ID untuk override instruksi (0,85), role marker (0,7), sapaan/arahan ke AI termasuk frasa AgentDojo (0,6), exfil lewat markdown image (0,6), ASCII smuggling via tag Unicode (0,6), dan tool steering (0,35, di bawah semua ambang bila sendirian). Skor = 1 − Π(1 − w) per tipe, dengan evidence span. Berlaku juga di bawah decode base64/hex/URL/ROT13 dan homoglyph. Latensi L1 p95 tetap ≤ 10 ms (±4,6 ms untuk 8K token).
- **Audit sesi (FR-AGT-8)**: setiap keputusan `tool_call`/`tool_result` = `decision_event` (divalidasi skema sebelum dikirim) dengan `trace_id` dari `traceparent` agent (atau dibuat) dan diteruskan ke tool server. Isinya metadata + HMAC konten, tanpa konten. `event_id` = `decision_id` yang dilihat agent.

## Hasil verifikasi lokal (2026-10-03)
- `go test -race ./...` hijau; test Rego 46/46 (lewat `policysvc`); integrasi Postgres agents/lifecycle/identity/catalog hijau; golangci-lint 0 issue; image `mcp-gateway` ter-build. Belum dijalankan terhadap Keycloak/Kafka/OPA sungguhan (perlu lingkungan GitLab/cluster).

## Sisa / follow-up
- **Utility saat diserang** rendah (16%) karena hasil ber-injection diblok utuh. Alternatif: redaksi/spotlighting span evidence (FR-PSEC-8) agar task tetap jalan; perlu kebijakan "redact injection" dan uji ulang ASR.
- Gaya stealth (instruksi tanpa menyapa AI) di dalam scope lolos: butuh classifier L2 (tiket 10) dan/atau HITL untuk tool high (tiket 30).
- ~~HITL approval dan kill switch~~ (tiket 30: selesai).
- ~~Scan tool description / rug-pull pada `tools/list`~~ (tiket 29: selesai); filter `tools/list` ke allow-list agent belum.
- Permintaan server→client (sampling/elicitation) di stream belum diinspeksi; `resources/read` belum dibatasi allow-list.
- Rate limit dan taint disimpan di memori per replika (deploy 1 replika); butuh store bersama untuk HA. Kegagalan kirim event hanya di-log (belum ada spool lokal).
- Keycloak: client `mcp-gateway` dengan izin token exchange per audience tool server, audience mapper resource URI untuk client agent, dan "Consent Required" untuk client yang bertindak atas nama user, sebagai realm-as-code bersama tim IAM.
- STDIO via local wrapper (P2).