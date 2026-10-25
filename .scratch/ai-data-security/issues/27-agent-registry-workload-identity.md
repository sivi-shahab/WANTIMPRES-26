# 27: Agent registry & workload identity

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M3
Blocked by: 06, 11
Spec: `../spec.md` §4.8 FR-AGT-1, FR-AGT-2; §6

## Konteks
Fondasi governance agent.

## Scope
- Registry: owner, purpose, model, tools+scopes, data scopes, risk tier, status.
- Agent tanpa owner otomatis `quarantined`.
- Workload identity (SPIFFE/OIDC client/managed identity); kredensial user bersama dilarang.
- Antrean review untuk shadow agent (dari MCP traffic dan OAuth grant).

## Acceptance criteria
- [x] Metrik 'agent tanpa owner & policy' = 0 dapat diukur. *(`GET /agents/summary` → `active_without_owner_or_policy`; dipakai posture (ticket 20) sebagai metrik §1.5 yang kini terukur. Policy = allow-list tool (FR-AGT-4); agent tanpa owner aktif otomatis quarantined, jadi tidak ikut terhitung "active".)*
- [x] Semua perubahan registry tercatat di audit log. *(`agent.register`, `agent.update` (before/after), `agent.status`, `agent.quarantine` (otomatis), `agent.discovered.dismiss`, dalam transaksi yang sama dengan release.)*

## Keputusan
- Modul `internal/agents` di control-plane, schema `agents`. Field FR-AGT-1 + `business_unit` untuk ABAC: agent owner hanya bisa mengubah/mendaftarkan/memindahkan agent di unit binding-nya (dites lewat API).
- **Registry = sumber kebenaran PDP**: setiap perubahan memotong policy release berisi `data.wantimpres26.agents`; `wantimpres26/agent` menghitung `registered` (= ada di registry dan `active`) dan `status`, klaim `registered` dari PEP diabaikan. Template baru `tpl.agent-not-active`: agent quarantined/suspended = block.
- Tanpa owner aktif (tidak ada, belum di-provision, atau dinonaktifkan via SCIM) → `quarantined` dengan alasan `no active owner`, saat register/update/status dan lewat reconcile per jam; aktivasi ditolak sampai ada owner.
- Workload identity wajib (`spiffe` | `oidc_client` | `managed_identity`, format divalidasi), satu identity satu agent (unique). Ditolak: tipe lain, identity berbentuk email (kecuali service account GCP), dan identity yang sama dengan user di IdP (kredensial user bersama).
- Antrean shadow agent: event keputusan dengan `agent_id` yang tidak terdaftar (consumer bersama control-plane); register menutup entrinya, dismiss butuh catatan. Hitungan `events` perkiraan (redelivery dihitung lagi).
- Control-plane kini memakai satu consumer group (`control-plane`) dengan fan-out ke incident, usage katalog, dan shadow agent (`events.Consume`), menggantikan dua consumer terpisah.

## Hasil verifikasi lokal (2026-10-03)
- `opa test` 41/41; integrasi Postgres (registry, quarantine, identity, shadow queue, ringkasan, audit, ABAC via API, keputusan PDP dari release); seluruh suite `-race`; golangci-lint bersih; image ter-build.

## Sisa / follow-up
- Sumber shadow agent dari OAuth grant (ticket 31) dan endpoint (36): kolom `source` sudah ada.
- Penegakan allow-list tool & scope parameter di MCP gateway (ticket 28); verifikasi SVID/token workload saat runtime (ticket 28).
- Reconcile per jam: owner yang dinonaktifkan bisa tetap aktif hingga 1 jam; percepat bila perlu dengan memicu reconcile dari perubahan SCIM.
