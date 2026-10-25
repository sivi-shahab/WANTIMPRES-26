# 33: Remediation actions untuk data-at-rest

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M3
Blocked by: 31
Spec: `../spec.md` §4.3 FR-DATA-6; §4.6 quarantine/remediate

## Konteks
Menutup oversharing yang ditemukan.

## Scope
- Aksi: cabut link anonim, hapus grup luas, terapkan label, quarantine.
- Aksi hanya jalan dengan approval sesuai policy.
- Dry-run + audit log + kemampuan undo bila API mendukung.

## Acceptance criteria
- [x] Test dry-run vs eksekusi. *(Dua level. Contract SDK (`connectortest`, berlaku untuk semua konektor): dry-run tidak mengubah apa pun dan memberi langkah yang sama untuk keadaan yang sama, eksekusi menjalankan tepat langkah itu, setelahnya `ErrNothingToDo`, dan undo memulihkan bila ditawarkan. Per konektor: M365 dan Drive memastikan dry-run tidak menghasilkan satu panggilan tulis pun ke sumber (termasuk tidak membuat folder karantina); S3 terhadap MinIO sungguhan. Alur (`remediate.TestDryRunApproveExecute`, Postgres + Graph palsu + scanner): rencana tersimpan tanpa write, eksekusi = rencana, exposure aset turun (60 → 6).)*
- [x] Aksi tanpa approval ditolak. *(Request yang belum disetujui tidak pernah dieksekusi worker; requester tidak bisa menyetujui requestnya sendiri (403); eksekutor tetap menolak (`ErrNotApproved`) baris yang "approved" tanpa approver atau dengan approver = requester (diuji dengan memalsukan baris di DB); approval atas rencana yang sudah berubah di sumber → `stale`, tanpa write; rencana yang tidak disetujui dalam 72 jam → `expired`. Uji mutasi (guard eksekutor dihapus) membuat test gagal.)*

## Keputusan
- **Kontrak SDK**: `Remediate(item, action, dryRun) → Change{Steps, Undo}` dan `Undo(item, undo, dryRun)`. Aksi: `revoke_anyone_links`, `remove_grants` (dipakai untuk "hapus grup luas" maupun user/domain eksternal, dengan grantee eksplisit dari ACL aset), `apply_label`, `quarantine`. Langkah deterministik supaya rencana bisa dibandingkan sebelum eksekusi. `ErrNothingToDo` dan `ErrNotSupported` dibedakan.
- **"Sesuai policy" = empat mata untuk setiap aksi**: diminta oleh pemegang `data.remediate` (dlp_analyst, security_admin), disetujui oleh pemegang `data.remediate.approve` (security_admin, break_glass) yang bukan peminta. Approval selalu atas rencana dry-run yang ditampilkan; worker merencanakan ulang tepat sebelum eksekusi dan hanya mengeksekusi bila rencana identik. Undo adalah request tersendiri dengan alur yang sama, karena mengembalikan eksposur. Semua transisi diaudit (request, plan, approve/reject, execute, stale, failed, nothing_to_do).
- **Kemampuan per sumber**:
  - **M365**: keempat aksi. Undo: user di-invite ulang, label sebelumnya dikembalikan, file dipindah kembali. Link anonim dan grup situs tidak bisa dipulihkan (ditandai "not restorable" di rencana).
  - **Google Drive**: revoke, remove_grants, quarantine. Undo memulihkan persis (permission dibuat ulang dengan URL file yang sama). Label Drive belum didukung.
  - **S3/MinIO**: quarantine ke bucket karantina (`<bucket>/<key>`) dengan undo. Akses publik di object storage diatur per bucket, jadi revoke per objek tidak didukung.
  - **Azure Blob dan Compliance API**: tidak didukung (`ErrNotSupported`).
- **Quarantine** = pindah ke folder/bucket "WANTIMPRES-26 Quarantine" dan mencabut semua sharing eksplisit kecuali owner. Permission yang di-inherit tidak dihapus di level item; rencana gagal dengan pesan untuk meremediasi folder induknya.
- **Kredensial tulis terpisah** dari kredensial scan yang read-only: app registration M365 kedua, scope `drive` untuk Drive, dan kunci S3 terpisah. Tanpa kredensial tulis, sumber tidak bisa diremediasi.
- Setelah eksekusi, aset disegarkan (`Scanner.Refresh`): grant, label, flag, dan exposure dibaca ulang tanpa mengubah hash path atau content tag.
- **API** (control-plane):
  - `POST /data/assets/{id}/remediations {action, note}` (`data.remediate`);
  - `GET /data/remediations[?state=&asset_id=]` dan `GET /data/remediations/{id}` (`dashboard.read`);
  - `POST /data/remediations/{id}/approve|reject` (`data.remediate.approve`);
  - `POST /data/remediations/{id}/undo` (`data.remediate`).
- Eksekutor berjalan di `connector-worker` setiap 30 detik. Baris dikunci (`FOR UPDATE SKIP LOCKED`) sehingga replika tidak mengeksekusi dua kali.

## Hasil verifikasi lokal (2026-10-05)
- `go test -race ./...` dengan Postgres, MinIO, dan Azurite hijau; golangci-lint 0 issue (lint sempat menemukan `err` yang ter-shadow di quarantine M365/Drive, sudah diperbaiki); image `connector-worker` dan `control-plane` ter-build. Belum diuji terhadap tenant M365/Google sungguhan.

## Sisa / follow-up
- Matriks policy yang bisa dikonfigurasi (mis. revoke link anonim pada restricted tanpa approval, atau approval dua tingkat untuk quarantine massal); saat ini empat mata untuk semua.
- Notifikasi ke approver dan ke owner file; remediasi massal per container atau flag.
- Label Google Drive; quarantine Azure (butuh SAS tulis) dan GCS.
- Transaksi DB tetap terbuka selama panggilan API sumber saat eksekusi (menjamin satu eksekusi per request); pantau bila API lambat.
- Folder karantina M365/Drive perlu dibatasi aksesnya oleh admin saat deploy (Graph/Drive tidak bisa memutus inheritance lewat API ini).