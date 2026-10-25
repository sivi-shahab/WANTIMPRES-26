---
title: Kontribusi
outline: [2, 3]
---

# Kontribusi

Terima kasih ingin membantu WANTIMPRES-26. Halaman ini menjelaskan cara kerja di repository [github.com/sivi-shahab/WANTIMPRES-26](https://github.com/sivi-shahab/WANTIMPRES-26): dari tiket sampai perubahan Anda ter-merge.

## Alur singkat

1. **Pilih atau buat tiket** di `.scratch/ai-data-security/issues/` ([lihat format](#tiket)).
2. **Siapkan lingkungan** sesuai [Cara Instalasi](./install#lingkungan-pengembangan).
3. **Kerjakan perubahan** beserta test-nya, mengikuti [standar kode](#standar-kode).
4. **Jalankan pemeriksaan lokal** ([daftar perintah](#pemeriksaan-sebelum-commit)).
5. **Commit** dengan [pesan yang baik](#pesan-commit), lalu buka pull request ke `main`.
6. **CI GitHub** menjalankan lint, test, dan scan. Setelah di-review dan di-merge, rilis resmi (build image, SBOM, tanda tangan) berjalan di pipeline GitLab.

## Tiket

Pekerjaan dicatat sebagai file markdown, satu file per tiket, di `.scratch/ai-data-security/issues/NN-<slug>.md`. Nomornya berurutan mulai dari `01`. Jangan menggabungkan beberapa tiket dalam satu file.

Bagian atas file berisi field yang dibaca oleh situs ini. Tulis persis seperti contoh berikut:

```md
# 52: Judul singkat tiket

Status: needs-triage
Type: task
Priority: P1
Milestone: M2
Blocked by: 49, 50
Spec: `../spec.md` §9.1; §13.3

## Konteks
Kenapa pekerjaan ini perlu.

## Scope
- Apa yang dikerjakan.

## Acceptance criteria
- [ ] Kondisi yang membuktikan pekerjaan selesai.
```

- **`Status`** salah satu dari `needs-triage`, `needs-gitlab-run`, `needs-signoff`, `deferred`, atau `done`. Artinya dijelaskan di [Roadmap](./roadmap#arti-status). Progres roadmap dan papan tiket dihitung dari field ini.
- **`Blocked by`** berisi nomor tiket lain, dipisah koma. Hapus baris ini bila tidak ada.
- **Diskusi dan riwayat** ditambahkan di bagian paling bawah, di bawah heading `## Comments`.
- **Hasil pekerjaan** biasanya dicatat di section seperti `## Keputusan`, `## Hasil verifikasi lokal (tanggal)`, dan `## Sisa`, supaya pembaca berikutnya tahu apa yang sudah dan belum dilakukan.

Tiket ditulis dalam Bahasa Indonesia. Terjemahan English-nya ada di `.scratch/ai-data-security/en/issues/` ([lihat terjemahan](#dokumentasi-dan-terjemahan)).

## Standar kode

- **Ikuti gaya kode di sekitarnya:** penamaan, kepadatan komentar, dan idiom yang sama dengan file yang Anda ubah.
- **Go** harus lolos `gofmt` dan `golangci-lint`. **Python** (`services/`) harus lolos `ruff check` dan `ruff format --check`.
- **Setiap logika yang tidak sepele punya test.** Ini terutama berlaku untuk keputusan kebijakan, parser, validator, dan jalur keamanan.
- **Tanpa konten mentah di log, trace, atau event.** Test privasi bersama di `internal/privacy` dijalankan bersama `go test` dan akan gagal bila aturan ini dilanggar.
- **Tanpa secret di repository.** gitleaks memeriksa seluruh riwayat git. Secret diberikan saat deploy lewat Secret Kubernetes atau Vault.
- **Penyederhanaan yang disengaja** (misalnya batas ukuran atau perilaku yang belum lengkap) ditandai komentar `ponytail:` yang menyebut batasnya dan cara meningkatkannya, contohnya:
  ```go
  // ponytail: per-object ACLs (AWS legacy ACLs, GCS fine-grained) are not read.
  ```
- **Pengecualian scanner harus direview dan diberi alasan**, dengan cakupan sesempit mungkin:
  - Semgrep: `// nosemgrep: <rule> -- <alasan>` di baris yang bersangkutan.
  - Trivy: entri di `.trivyignore.yaml` dengan `paths` dan `statement`.

## Pemeriksaan sebelum commit

Jalankan pemeriksaan yang sama dengan CI:

```sh
gofmt -l .                       # harus kosong
golangci-lint run ./...
go vet ./...
go test -race ./...              # termasuk test Rego dan test privasi

ruff check services
ruff format --check services
(cd services/model-inference && python -m unittest -v)
```

Bila mengubah dokumentasi:

```sh
npm run docs:build               # gagal bila ada link mati
```

Integration test butuh backend sungguhan (PostgreSQL, Kafka, OpenSearch, MinIO, Azurite) dan otomatis dilewati di lokal. CI menjalankannya untuk Anda; daftar variabelnya ada di `.gitlab-ci.yml`.

## Pesan commit

- **Subjek dalam bahasa Inggris, kalimat perintah, singkat:** `Bound the AI gateway's Redis wait and fall back per replica`.
- **Sebutkan tiketnya** dengan format `(ticket NN)` atau `(tickets 09 and 40)`. Rujukan ini otomatis menjadi link di [Changelog](../changelog).
- **Badan pesan menjelaskan alasannya**, bukan mengulang diff: masalah apa yang diselesaikan dan keputusan apa yang diambil.
- **Satu commit, satu perubahan yang utuh.** Pisahkan perbaikan format atau refactor dari perubahan perilaku.

Contoh dari riwayat repository (commit `e19c7de`):

```text
Publish decision events without waiting on Kafka (ticket 46)

ProduceSync in the request path did not stop at its 2 s context, so a
Kafka outage hung every gateway request. Publish now validates and hands
the record to a bounded buffer (10k records, 30 s delivery timeout);
failures count as decision_events_dropped_total, alerted as an audit
gap. Both gateways expose the counter.
```

## Mengubah kebijakan

Kebijakan bawaan ada di `policy/wantimpres26/`: mesin keputusan di `decision.rego` dan template aturan di `rules/data.json`.

- Tambahkan atau ubah test-nya. Test Rego dijalankan lewat `go test ./...`.
- Untuk aturan baru, pertimbangkan `"mode": "monitor"` dulu, lalu periksa dampaknya lewat [simulasi](./how-to-use#siklus-rilis) sebelum ditegakkan.
- Perubahan kebijakan di lingkungan berjalan tetap melalui siklus rilis di control-plane (draft, simulate, submit, lalu approve oleh orang lain), bukan lewat commit.

## Dokumentasi dan terjemahan

Situs ini dibangun dengan VitePress dari folder `docs/`. Jalankan `npm run docs:dev` untuk melihat perubahan secara langsung.

- **Halaman baru** didaftarkan di sidebar `docs/.vitepress/config.mts` untuk kedua bahasa. Halaman Indonesia ada di `docs/`, English di `docs/en/` dengan path yang sama.
- **Spec dan tiket** berbahasa Indonesia adalah sumber utama. Setelah mengubahnya, perbarui terjemahan di `.scratch/ai-data-security/en/` lalu tandai sebagai sesuai:
  ```sh
  npm run docs:stamp -- .scratch/ai-data-security/en/issues/52-judul-singkat.md
  ```
  Jika terjemahan tertinggal, build menampilkan peringatan `[i18n]` dan halaman English tiket tersebut diberi banner.
- **Changelog dan progres roadmap** dibuat otomatis dari git dan status tiket, jadi tidak perlu diubah manual.

## Keputusan arsitektur

Keputusan yang sulit diubah kembali, misalnya soal hosting, identitas, atau model data, dicatat sebagai ADR di `docs/adr/NNNN-<slug>.md`. Ikuti struktur ADR yang ada: konteks, keputusan beserta alternatif yang ditolak, pemicu review, dan dampak ke tiket. Contohnya [ADR-0001](../adr/0001-hosting-residency-build-scope).

## Melaporkan kerentanan

Jangan laporkan kerentanan keamanan lewat tiket atau issue publik. Gunakan *private vulnerability reporting* GitHub seperti dijelaskan di [Kebijakan Keamanan](./security).

## Butuh bantuan?

Mulai dari [FAQ](./faq) dan [Glosarium](./glossary). Untuk konteks teknis yang lebih dalam, baca [Spesifikasi](../spec) dan [threat model](../threat-model).
