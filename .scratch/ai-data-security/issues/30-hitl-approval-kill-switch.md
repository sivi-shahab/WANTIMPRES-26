# 30: HITL approval & kill switch

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M3
Blocked by: 28
Spec: `../spec.md` §4.8 FR-AGT-6, FR-AGT-7; §8.6

## Konteks
Aksi agent berisiko tinggi butuh manusia, dan harus ada tombol darurat.

## Scope
- `APPROVAL_REQUEST` dengan preview aksi dan parameter (redacted sesuai hak); timeout → deny.
- Kanal approval: UI + notifikasi (email/chat).
- Kill switch per agent/tool/app/global: cabut token, putus sesi, push policy block.

## Acceptance criteria
- [x] Kill switch efektif ≤ 10 s (diukur). *(Dua bagian, keduanya diukur. `agents.TestKillSwitchPropagation` (Postgres + releaser + bundle server + OPA asli lewat SDK long-poll, 10 kill agent/global): commit kill → OPA memblok p50 171 ms, maks 187 ms. `mcpgw.TestKillSwitch`: kill di PDP → sesi SSE yang sedang berjalan terputus dalam ±0,99 s (poll 1 s), request baru 403. Total kasus terburuk ±1,2 s.)*
- [x] Approval kedaluwarsa → aksi ditolak. *(`agents.TestApprovals`: approval yang disetujui tetapi belum dipakai sampai tenggat tidak bisa di-claim; approve setelah tenggat → 410 dan request menjadi `expired`; retry setelahnya membuka request baru. `mcpgw.TestApprovalFlow`: approval yang lewat 15 menit → panggilan tetap ditolak, tool tidak dieksekusi.)*
- [x] Approver tidak bisa menyetujui permintaan agent miliknya sendiri. *(Store menolak dengan `errSelf`; API `TestHITLAndKillAPI`: owner → 403, approver di luar business unit binding-nya → 403, peran tanpa `agent.approve` → 403, keputusan ganda → 409.)*

## Keputusan
- **Alur HITL tanpa menahan koneksi**: saat PDP memutuskan `require_approval`, gateway membuka permintaan approval di control-plane lalu menjawab agent dengan error JSON-RPC berisi `approval_id`, `state`, dan `expires_at`. Agent memanggil ulang dengan argumen yang sama. Approval terikat ke (agent, server, tool, SHA-256 argumen kanonik) dan sekali pakai. Gateway meng-*claim*-nya sebelum bertanya ke PDP, lalu mengirim `agent.approval_granted`. PDP memperlakukannya sebagai pengecualian satu kali hanya untuk rule `require_approval`, yang dilaporkan di `exempted_rules`. Rule yang lebih ketat (scope, kill, secret) dan redaksi tetap berlaku. Event `tool_call` membawa `approval_id`. Approval yang di-claim tetapi kemudian diblok rule lain ikut hangus.
- Permintaan yang sama selama masih terbuka mengembalikan request yang sama, jadi retry agent tidak membanjiri approver. TTL default 15 menit (`APPROVAL_TTL`). Timeout = deny, baik untuk request yang belum diputus maupun approval yang belum dipakai.
- **Preview "redacted sesuai hak"**: approver melihat parameter lengkap kecuali `SECRET.*` dan `PCI.*`, yang di-redact oleh gateway. Argumen mentah tidak pernah keluar dari gateway dan tidak disimpan; control-plane hanya menerima preview dan digest. Alasannya: hak approve mencakup melihat apa yang disetujui (mis. rekening tujuan), tetapi tidak ada keputusan yang butuh secret atau nomor kartu.
- **Approver**: permission baru `agent.approve`, role `agent_approver` (plus break_glass), dibatasi business unit lewat ABAC. Owner agent tidak bisa menyetujui aksi agent-nya. Approve/reject diaudit.
- **Notifikasi**: webhook chat (`APPROVAL_WEBHOOK_URL`, format `{"text"}` Teams/Slack/Mattermost) setelah commit, berisi agent, tool, alasan, tenggat, dan tautan; tanpa argumen. UI = API `GET /approvals`, `GET /approvals/{id}`, `POST /approvals/{id}/approve|reject`.
- **Kill switch**: tabel `agents.kills` (satu aktif per scope/target, riwayat disimpan) dirilis sebagai `data.wantimpres26.kills`; rule `tpl.kill-switch` (`KILL_SWITCH`) memblok semua aksi agent untuk agent, tool (nama), app (destination app_id), atau global. Approval tidak bisa mengangkat kill. Gateway mem-poll kill set tiap 1 s dan:
  - memutus request yang sedang berjalan yang tercakup (context dibatalkan, stream SSE ke agent berakhir);
  - menolak semua request agent/app yang di-kill dengan 403, termasuk `initialize`/`tools/list` (token agent efektif dicabut di gateway);
  - membuang cache token downstream hasil exchange setiap kali kill set berubah.
- **Hak kill**: owner bisa mengekill agent-nya sendiri (`POST /agents/{id}/kill`, `agent.write` + unit); SOC bisa mengekill agent/tool/app mana pun (`POST /kills`, `incident.write`); global hanya lewat `POST /kills/global` dengan `agent.kill.global` (sensitif: step-up + justifikasi). Lift lewat `POST /kills/{id}/lift`, dan untuk global `POST /kills/global/{id}/lift`. Semuanya diaudit dan memotong rilis policy di transaksi yang sama. Spec §8.6 menaruh `scope` di body; di sini dipisah per route karena permission-nya berbeda.
- Endpoint servis gateway (token sendiri): `POST /mcp/approvals/request` dan `POST /mcp/approvals/claim`, di samping `/mcp/tools/observed`.

## Hasil verifikasi lokal (2026-10-04)
- `go test -race ./...` termasuk integrasi Postgres hijau; Rego 50/50; suite AgentDojo tetap 100% → 5,0%; golangci-lint 0 issue; image `control-plane` dan `mcp-gateway` ter-build.

## Sisa / follow-up
- Pencabutan di IdP: men-disable client agent di Keycloak (admin API) saat kill agent, agar token tidak bisa dipakai di tempat lain selain gateway. Saat ini pencabutan efektif di gateway (satu-satunya jalur ke tool).
- UI console untuk approver (saat ini API + tautan di notifikasi). Notifikasi email (SMTP) belum ada; webhook best-effort tanpa outbox.
- Approver tingkat dua (4-eyes) untuk nilai sangat besar; aturan siapa approver per tool/nominal.
- Kill per tool berdasarkan nama tool di semua server; kill per server MCP lewat scope app (`app_id` server).
- Rate limit, taint, dan kill set per replika gateway; kill set konsisten antar replika lewat bundle.