# 26: Incident lanjut: korelasi, breach timer UU PDP, SOAR/ITSM

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M2
Blocked by: 18, 19
Spec: `../spec.md` §4.10 FR-INC-1, FR-INC-5, FR-INC-6; §11

## Konteks
Melengkapi incident untuk kebutuhan regulasi dan otomasi.

## Scope
- Korelasi berbasis `trace_id`/sesi agent ke satu incident rantai.
- Breach workflow: timer 3×24 jam + draft laporan (data terungkap, kapan/bagaimana, penanganan) sesuai Pasal 46.
- Containment actions API.
- Integrasi ServiceNow/Jira SM + webhook SOAR.

## Acceptance criteria
- [x] Draft laporan breach dapat dihasilkan ≤ 24 jam dari deteksi (metrik §1.5). *(Draft tersedia sejak timer mulai (saat deteksi), dibangun on-demand dari evidence ter-redact. Draft pertama dicatat (`breach_drafted_at`, audit `incident.breach.draft` dengan `hours_since_detection`) sebagai metrik. `TestBreachWorkflow`: draft 1,5 jam setelah deteksi.)*
- [x] Alert eskalasi saat sisa timer < 24 jam. *(Sweep tiap menit: sekali per insiden, severity → critical, audit `incident.breach.escalate` (severity SIEM 9) yang diteruskan ke SIEM dan webhook SOAR. Metrik `breach_timer_remaining_hours` dan `breach_timers_running`. Test: tidak eskalasi di sisa 25 jam, eskalasi di sisa 23 jam, tidak dua kali.)*
- [x] Test integrasi ITSM. *(`TestITSM`: server tiruan ServiceNow Table API dan Jira SM request API memeriksa path, auth, field, mapping severity → urgency/impact, korelasi id, tidak ada konten mentah, satu tiket per insiden, dan ITSM error tidak tercatat sehingga bisa di-retry.)*

## Keputusan
- **Korelasi rantai (FR-INC-1):** event dengan `trace_id` yang sudah punya insiden terbuka (event-nya dalam jendela geser 30 menit) bergabung ke insiden itu, apa pun dedup key-nya. Di MCP gateway satu trace = satu sesi agent. Trace kosong/nol tidak dikorelasikan. Lock advisory per trace lalu per key (urutan tetap) mencegah insiden kembar.
- **Breach otomatis (FR-INC-6):** timer mulai saat event *keluar* membawa data pribadi: arah bukan `response`, aksi `allow`/`warn`, dan ada kelas `PII*`, `PCI.*`, `FIN.*`, atau `PHI*`. Event yang di-block/redact/tokenize tidak dihitung, begitu juga secret (bukan data pribadi). Mulai = waktu deteksi, batas = +72 jam. Severity naik minimal `high`. "Terkonfirmasi" ditafsirkan konservatif: timer jalan otomatis, lalu DPO menutupnya sebagai `notified` atau `dismissed` (dengan catatan, diaudit, `compliance.write`). SOC bisa `declare` manual (dengan catatan) untuk kebocoran di luar PEP.
- **Draft laporan** (`GET /incidents/{id}/breach/report`, JSON atau `?format=md` berbahasa Indonesia per huruf Pasal 46 ayat (2)): (a) kelas data pribadi, jenis umum/spesifik (Pasal 4), jumlah nilai dan event; (b) pertama/terakhir terungkap, waktu deteksi, kanal, tujuan, jumlah pengguna (pseudonim), agent, dan timeline; (c) transisi status dan aksi containment. Subjek terdampak: evidence hanya menyimpan kelas dan jumlah, jadi yang dilaporkan adalah batas atas, ditandai "tidak dapat dipastikan", dengan rujukan ke unmask berjustifikasi.
- **Containment (FR-INC-5)** `POST /incidents/{id}/actions` (`incident.write`; sekaligus entry point playbook SOAR lewat service account). Setiap aksi dicatat di insiden dan diaudit, dan masuk ke draft laporan.
  - `block_access`: blok principal → app untuk pasangan yang ada di event insiden saja (default 72 jam, maks 30 hari), lewat dokumen `data.wantimpres26.containment` di setiap policy release. PDP menegakkannya di luar rule set, jadi tidak bisa diangkat oleh edit policy atau exception. Lift: `POST /incidents/{id}/blocks/{bid}/lift`.
  - `kill_switch`: agent/tool/app (registry, tiket 30). Ini bentuk "cabut token agent": PDP memblok semua aksinya dan MCP gateway memutus sesinya. Kill global tetap lewat `POST /kills/global`.
  - `revoke_share_link`: permintaan remediasi data-at-rest (butuh `data.remediate`, lalu approval 4-eyes FR-DATA-6).
  - `open_ticket`: ServiceNow (`ITSM_KIND=servicenow`) atau Jira SM (`jira-sm`). Satu tiket per insiden; isinya metadata saja.
- **Webhook SOAR:** sink tambahan di siem-export (`SOAR_WEBHOOK_URL`, `SOAR_WEBHOOK_SECRET_FILE`) yang hanya meneruskan record audit `incident.*` (open, escalate, breach, contain). Ditandatangani HMAC-SHA256 atas `timestamp.body`. Retry, DLQ, dan cursor memakai jalur SIEM yang sudah ada, jadi tidak ada outbox baru.

## Hasil verifikasi lokal (2026-10-10)
- `go vet ./...` + `go test -race ./...` dengan Postgres 17 hijau (termasuk test Rego lewat `policysvc`). golangci-lint v2.5.0: 0 issue.
- Fixture `store_test` kini memakai trace acak per event (sebelumnya konstan, yang sekarang akan merangkai semua event).
- Catatan: `opa test` CLI 1.4.2 menggagalkan `test_invalid_input_fails_closed` juga di HEAD (beda versi dari library yang dipin). Pemeriksa yang berlaku tetap `TestRegoPolicies`.

## Sisa
- Paksa reset kredensial (FR-INC-5) belum ada karena belum ada integrasi IAM/secrets. Sementara lewat `open_ticket` ke tim IAM.
- Event connector data-at-rest (share link publik berisi data pribadi) belum memicu timer otomatis. Untuk sekarang pakai `declare`.
- Tiket ITSM tidak disinkronkan balik (status tiket → insiden).
- Lock baris insiden selama panggilan ITSM (≤ 30 detik), ditandai `ponytail:` di `contain.go`.
- Uji dengan instance ServiceNow/Jira SM bank yang nyata, termasuk request type dan field wajib yang mungkin ditambahkan admin.
