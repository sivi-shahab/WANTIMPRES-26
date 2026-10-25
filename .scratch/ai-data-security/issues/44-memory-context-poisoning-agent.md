# 44: Inspeksi tulis ke memory agent / vector store (FR-AGT-9)

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M2
Blocked by: 28
Spec: `../spec.md` §4.8 FR-AGT-9; OWASP ASI06, LLM08; `docs/threat-model.md` G5

## Konteks
Threat model (tiket 02) G5: belum ada kontrol untuk ASI06 (memory & context poisoning). Konten berinjeksi yang tersimpan di memory jangka panjang atau vector store akan dibaca ulang oleh agent sebagai konteks tepercaya.

## Scope
- MCP gateway mengenali tool tulis memory/vector store (ditandai di registry tool, misalnya `writes_memory: true`) dan menginspeksi argumennya dengan detektor injection + DLP sebelum diteruskan.
- Provenance: sumber tulis (agent, trace, asal konten: user/tool result/web) dicatat di decision event.
- Konten dari sesi yang ter-taint injection tidak boleh ditulis ke memory tanpa approval.

## Acceptance criteria
- [x] Tulis memory berisi injection diblok atau butuh approval (test gateway). *(`mcpgw.TestMemoryPoisoning`: tulis berisi injection 0,6 diblok `MEMORY_POISONING` dan tidak sampai ke tool server. Sesi yang sudah membaca email berinjeksi menulis catatan bersih → `require_approval` `MEMORY_WRITE_TAINTED_SESSION`; setelah disetujui manusia, tulisan masuk sekali dan event membawa `approval_id`. `decision_test.test_registry_decides_writes_memory`: penanda dari registry yang berlaku, bukan klaim PEP.)*
- [x] Event tulis memory membawa provenance. *(Setiap event `tool_call` ke tool `writes_memory` membawa `memory_write: true`, `content_origin` (`user` = hanya input agent sendiri di sesi itu, `tool_result` = sesi sudah membaca output tool), dan `content_sources` (mis. `bank/read_inbox`), selain `agent_id` dan `trace_id` yang sudah ada. Test memeriksa ketiganya; tool call biasa tidak membawanya.)*
- [x] Skenario poisoning sintetis (tulis → baca ulang di sesi lain) tertangkap. *(Racun yang sudah ada di store, misalnya tertulis sebelum gateway atau lewat jalur lain, dibaca ulang oleh sesi lain lewat `recall_memory`: hasilnya diblok `INDIRECT_INJECTION` tanpa satu byte pun sampai ke agent. Sesi itu menjadi ter-taint, sehingga `send_money` butuh approval dan sesi itu tidak bisa menulis racunnya kembali ke memory tanpa approval.)*

## Keputusan
- **Penanda di registry agent**: `agents.Tool.writes_memory` (opsional, default false) ikut di `data.wantimpres26.agents`. `wantimpres26.agent` menimpa `agent.writes_memory` dari input PEP dengan nilai registry, sama seperti `tool_risk`. Tool yang tidak ada di allow-list sudah diblok `tpl.tool-not-allowed`.
- **Inspeksi**: argumen tool call sudah diinspeksi (DLP + injection) oleh gateway. Yang baru adalah dua template rule:
  - `tpl.memory-write-injection`: tulis memory dengan `injection_score ≥ 0,5` → block. Ambangnya lebih rendah dari `tpl.injection-high` (0,9) karena yang tersimpan akan dibaca ulang sebagai konteks tepercaya.
  - `tpl.memory-write-tainted`: sesi dengan `session_injection_max ≥ 0,5` menulis memory → `require_approval` (tanpa HITL = deny). Approval hanya mengangkat rule ini; block karena isi tetap berlaku.
  - DLP pada argumen memakai rule yang sudah ada (secret block, PAN redact, dst.).
- **Provenance**: gateway mencatat per sesi (kunci taint: agent + trace) output tool yang *diteruskan* ke agent (allow/warn/redact). Output yang diblok tidak dihitung karena agent tidak melihatnya. Masa berlakunya sama dengan taint (30 menit). Asal "web" tidak dibedakan dari tool lain karena terlihat dari namanya di `content_sources` (mis. `bank/web_fetch`).
- **Field event baru** (opsional, tambahan di `decision_event` v1 seperti `tool_hash`/`approval_id` sebelumnya): `memory_write`, `content_origin`, `content_sources`. Mapping OpenSearch juga ditambah.

## Hasil verifikasi lokal (2026-10-10)
- `go build`, `go vet ./...`, gofmt bersih. golangci-lint v2.5.0: 0 issue.
- `go test` (tanpa race) untuk `mcpgw`, `policysvc` (54 test Rego), `events`, dan `agents` hijau.
- `go test -race ./...` hijau kecuali tiga test yang memakai ambang waktu: `agents.TestKillSwitchPropagation` (10,3 detik > 10 detik), `mcpgw.TestKillSwitch` (pemutusan sesi > 2 detik, termasuk compile query Rego), dan `policysvc.TestRegoPolicies` (`test_residency_matrix` melewati batas 1 menit). Saat itu load average host 56–85 di 16 core karena beberapa fork menjalankan suite race secara paralel. Saat diulang, `TestKillSwitchPropagation` lulus dengan `-race`; dua lainnya lulus tanpa race. Perubahan tiket ini tidak menyentuh jalur kill switch. Perlu konfirmasi di GitLab CI (host tidak sibuk).

## Sisa
- Template rule baru hanya aktif otomatis di database kosong (policy `builtin`). Deployment yang sudah berjalan perlu menambahkan dua rule ini lewat policy lifecycle.
- Taint dan provenance disimpan in-memory per replica gateway, sama seperti taint dan rate limit. Perlu store bersama bila replica harus sepakat.
- Tulis ke vector store yang tidak lewat MCP gateway (SDK langsung ke database vektor) tidak terlihat. Perlu dipaksa lewat gateway, mirip tiket 43 untuk LLM.
- Pemindaian ulang isi memory/vector store yang sudah ada (racun lama) belum dilakukan. Untuk saat ini racun lama tertangkap saat dibaca.
