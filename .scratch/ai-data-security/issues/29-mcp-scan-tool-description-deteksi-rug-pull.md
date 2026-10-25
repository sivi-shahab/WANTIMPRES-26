# 29: MCP: scan tool description & deteksi rug-pull

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M3
Blocked by: 28
Spec: `../spec.md` §4.8 FR-AGT-3 (tool poisoning); §15 Adversarial

## Konteks
Tool poisoning lewat deskripsi tool atau perubahan diam-diam setelah disetujui.

## Scope
- Scan deskripsi, metadata, dan schema tool saat registrasi (detektor injection + rule).
- Pin hash deskripsi; perubahan memicu status `under_review` dan re-approval.
- Laporan tool berisiko per MCP server.

## Acceptance criteria
- [x] Test dengan sampel ala MCPTox. *(`internal/mcptools` `TestScanMCPToxStyle`: 25 definisi beracun mencakup tiga paradigma MCPTox (explicit trigger–function hijacking, implicit trigger–function hijacking, implicit trigger–parameter tampering) dengan tujuan privacy leakage, message hijacking, data tampering, dan unauthorized action, pola `<IMPORTANT>` Invariant Labs, EN/ID, serta obfuscation (homoglyph, zero-width, base64, payload hanya di schema, secret tertanam). **25/25 tertandai (14 high)**. 20 definisi wajar bergaya server MCP populer (filesystem, GitHub, Slack, Postgres, fetch) dan tool bank: **0 tertandai**. Catatan: sampel ditulis sendiri meniru dataset, bukan dataset MCPTox asli; ukur ulang terhadap dataset asli bila tersedia.)*
- [x] Perubahan deskripsi → tool tidak bisa dipanggil sampai di-approve ulang. *(Postgres `TestToolPinning`: v1 bersih → pinned/approved; v2 (rug pull) → `under_review` dan PDP rilis terbaru memblok `TOOL_NOT_APPROVED` apa pun hash yang dilihat replika; approve dengan hash usang ditolak, definisi berisiko wajib catatan; perbaikan jujur dari vendor pun perlu approve eksplisit; setelah approve → allow. Gateway `TestRugPull` (JSON dan SSE): tool yang berubah langsung hilang dari `tools/list` (teks beracun tidak sampai ke model) dan `tools/call` diblok **sebelum** rilis bundle sampai (hash yang diamati ≠ pin), juga di replika yang belum melihatnya setelah rilis; tool lain tetap jalan; re-approve memulihkan. Uji mutasi (cek hash di Rego dimatikan) membuat test gagal.)*

## Keputusan
- **Pin** = SHA-256 JSON kanonik seluruh objek tool dari `tools/list` (`mcptools.Hash`): nama, deskripsi, input/output schema, annotations, `_meta`. Perubahan apa pun adalah definisi baru.
- **Inventaris** di registry agent (`agents.mcp_tools`, Postgres): definisi terakhir yang dilihat, hasil scan (score, risk, signals), status `approved | under_review | rejected`, `approved_hash`. Definisi baru yang bersih (risk low) langsung di-pin dan approved oleh `mcp-gateway`; yang tertandai masuk `under_review`. Perubahan definisi apa pun (rug pull maupun update jujur) → `under_review` sampai di-approve ulang. Approve mewajibkan hash definisi yang dilihat reviewer (mencegah TOCTOU). Definisi berisiko dan penolakan wajib catatan. Setiap registrasi, perubahan, approve, dan reject diaudit dan memotong rilis policy dalam transaksi yang sama. Observasi yang tidak berubah hanya memperbarui `last_seen`.
- **Pelaporan**: gateway mengirim setiap respons `tools/list` ke `POST /mcp/tools/observed` di control-plane. Ini route publik dengan token bearer sendiri (disimpan sebagai SHA-256, pola SCIM), sehingga matriks route publik ikut bertambah. Advisory lock per server mencegah dua replika mencatat perubahan yang sama dua kali.
- **Penegakan dua lapis**: (1) gateway hanya meneruskan tool yang callable menurut jawaban registry, dengan fallback ke pin di bundle (`wantimpres26/mcp.tools`) bila registry tidak terjangkau; tanpa keduanya tidak ada tool yang ditampilkan. (2) PDP: `tpl.mcp-tool-not-approved` memblok `tools/call` yang statusnya bukan approved atau `tool_hash` yang terakhir dilihat gateway ≠ pin (`data.wantimpres26.mcp_tools`). Lapis kedua menutup jeda rilis bundle. Hanya berlaku bila `agent.mcp_server` ada, jadi tool call di luar gateway tidak terdampak.
- **Scanner** (`internal/mcptools`): semua string definisi (termasuk nama properti schema, enum, default) dipindai dengan detektor injection tiket 28 (kecuali `tool_steering`, karena dokumentasi tool memang menyebut tool lain) ditambah aturan khusus metadata: `sensitive_path`, `cross_tool` (shadowing/hijacking tool lain), `param_tamper`, `concealment`, `directive_tag` (`<IMPORTANT>`), dan secret tertanam. Skor = 1 − Π(1 − w): ≥ 0,7 high, > 0 medium, 0 low.
- Event `decision_event` (dan mapping OpenSearch) mendapat `mcp_server` dan `tool_hash` agar simulasi policy bisa me-replay keputusan ini.
- Sekalian di detect: aturan `before answer…` kini wajib "before you…", karena "Before answering policy questions, prefer…" adalah prosa wajar (FP di konten dan deskripsi tool).

## API
- `GET /mcp/tools?server=&status=` dan `GET /mcp/tools/report` (laporan per server: tools, callable, under_review, rejected, changed, high/medium risk), dengan permission `agent.read`.
- `POST /mcp/tools/{server}/{name}/approve {hash, note}` dan `.../reject {note}`, dengan permission `config.write` (security_admin, break_glass).

## Hasil verifikasi lokal (2026-10-03)
- `go test -race ./...` termasuk integrasi Postgres hijau; Rego 48/48; suite AgentDojo tetap 100% → 5,0%; golangci-lint 0 issue; image `control-plane` dan `mcp-gateway` ter-build.

## Sisa / follow-up
- Ukur scanner pada dataset MCPTox asli; classifier L2 (tiket 10) untuk deskripsi beracun yang tidak memakai pola dikenal (auto-approve saat registrasi bergantung pada scanner).
- Notifikasi ke reviewer (SOC/security_admin) saat ada tool `under_review`; metrik `mcp_tools_under_review`.
- Tool yang belum pernah di-list sebelum dipanggil diblok (`TOOL_NOT_APPROVED`) sampai `tools/list` + rilis bundle; klien MCP standar selalu me-list lebih dulu.
- Prompts dan resources templates (`prompts/list`, `resources/list`) belum di-pin.
- Allow-list tool per agent masih berdasarkan nama; definisi diikat per server, bukan per agent.