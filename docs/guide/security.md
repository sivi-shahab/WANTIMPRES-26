---
title: Keamanan
outline: [2, 3]
---

# Kebijakan Keamanan

WANTIMPRES-26 adalah platform keamanan, jadi kerentanan di dalamnya bisa berdampak langsung pada data nasabah dan rahasia perusahaan. Kami sangat menghargai laporan yang disampaikan secara bertanggung jawab.

## Melaporkan kerentanan

::: danger Jangan laporkan secara publik
Jangan laporkan kerentanan lewat issue GitHub, pull request, tiket di `.scratch/`, atau forum publik lain.
:::

Laporkan secara privat lewat fitur **private vulnerability reporting** GitHub:

1. Buka [tab Security repository](https://github.com/sivi-shahab/WANTIMPRES-26/security).
2. Klik **Report a vulnerability**, atau langsung ke [formulir laporan](https://github.com/sivi-shahab/WANTIMPRES-26/security/advisories/new).
3. Laporan hanya terlihat oleh Anda dan maintainer.

Agar laporan cepat ditangani, sertakan:

- **Komponen yang terdampak**, misalnya `ai-gateway`, `mcp-gateway`, `control-plane`, kebijakan Rego, atau manifest deploy, beserta commit yang Anda uji.
- **Langkah reproduksi** yang bisa diulang, termasuk konfigurasi yang dipakai.
- **Dampak**: apa yang bisa dicapai penyerang, misalnya melewati kebijakan, membocorkan konten, menembus isolasi tenant, atau merusak integritas audit log.
- **Bukti konsep** seminimal mungkin. Jangan sertakan data pribadi atau data nyata nasabah.

### Pedoman saat meneliti

- Uji di lingkungan Anda sendiri, misalnya [stack lokal](./install#jalankan-stack-lokal). Jangan menguji deployment milik pihak lain tanpa izin tertulis.
- Jangan mengakses, mengubah, atau menyimpan data melebihi yang dibutuhkan untuk membuktikan masalah.
- Jangan melakukan serangan yang mengganggu layanan (DoS), rekayasa sosial, atau akses fisik.
- Beri kami waktu memperbaiki sebelum detailnya dipublikasikan.

## Setelah laporan masuk

1. **Konfirmasi:** maintainer mengonfirmasi bahwa laporan diterima dan menghubungi Anda di thread advisory yang sama.
2. **Triage:** dampak dinilai dengan rating yang sama seperti [threat model](../threat-model). *High* berarti kebocoran data nasabah dalam skala besar, enforcement bisa dilewati, atau integritas audit/kebijakan rusak.
3. **Perbaikan:** perbaikan dikerjakan secara privat dan diuji lewat pipeline yang sama dengan perubahan lain.
4. **Publikasi terkoordinasi:** setelah perbaikan tersedia, detailnya dipublikasikan sebagai GitHub Security Advisory (beserta CVE bila relevan), dan pelapor dicantumkan bila bersedia.

## Versi yang didukung

WANTIMPRES-26 belum memiliki rilis bertag. Perbaikan keamanan hanya diterapkan ke branch `main`.

| Versi | Didukung |
|---|---|
| `main` (terbaru) | Ya |
| Commit lama atau fork | Tidak |

## Cakupan

**Termasuk cakupan:**

- Kode service di `cmd/`, `internal/`, dan `services/`.
- Kebijakan di `policy/`, termasuk cara melewati keputusan atau memalsukan bundle.
- Manifest dan konfigurasi deploy di `deploy/`, bila dipakai sesuai panduan instalasi.
- Workflow CI/CD di `.github/` dan `.gitlab-ci.yml`.

**Di luar cakupan:**

- Kerentanan di dependensi pihak ketiga yang belum bisa dieksploitasi lewat WANTIMPRES-26; laporkan ke proyek aslinya.
- Deployment yang menyimpang dari konfigurasi yang disarankan, misalnya tanpa mTLS atau dengan `MTLS_INSECURE`.
- Serangan volumetrik (DoS), rekayasa sosial, dan akses fisik.
- [Batasan yang sudah diketahui](#batasan-yang-sudah-diketahui) di bawah.

## Kontrol keamanan platform

Ringkasan kontrol utama. Analisis lengkap per komponen (STRIDE, OWASP LLM Top 10, dan OWASP Agentic Top 10) ada di [threat model](../threat-model).

| Area | Kontrol |
|---|---|
| Identitas antar-service | mTLS dengan identitas SPIFFE berumur pendek; NetworkPolicy default-deny |
| Identitas admin | OIDC dengan MFA lewat Keycloak; login ulang dan justifikasi untuk izin sensitif; akun break-glass diaudit |
| Integritas kebijakan | Bundle ditandatangani lewat Vault Transit (kunci privat tidak pernah masuk pod) dan diverifikasi oleh setiap sidecar OPA |
| Perubahan kebijakan | Prinsip dua orang: pembuat dan penyetuju harus berbeda; simulasi sebelum rilis; rollback |
| Isolasi data | Row-level security PostgreSQL per tenant |
| Privasi | Tanpa konten mentah di log, trace, atau event (ditegakkan oleh test privasi bersama); pseudonimisasi HMAC |
| Bukti insiden | Dienkripsi per insiden; dibuka hanya lewat permintaan *unmask* yang disetujui orang lain |
| Audit | Audit log append-only berantai hash, dengan anchor harian bertanda tangan di object storage WORM |
| Agent | Token exchange tanpa meneruskan token agent, tool pinning, persetujuan manusia, kill switch |
| Kegagalan | Mode gagal eksplisit per aplikasi (`fail_closed` sebagai default) |

## Keamanan rantai pasok

- **Image bertanda tangan:** cluster hanya menjalankan image yang ditandatangani cosign (kebijakan Kyverno). Setiap image disertai SBOM.
- **Pemindaian di setiap perubahan:** Semgrep (SAST), Trivy (kerentanan, lisensi, IaC), dan gitleaks atas seluruh riwayat git.
- **Pengecualian scanner** harus direview, diberi alasan, dan dibatasi ke path atau baris tertentu (`.trivyignore.yaml`, `nosemgrep: … -- alasan`).
- **GitHub Actions** di-pin ke commit SHA.
- **Repository GitHub** mengaktifkan secret scanning dan push protection.
- **Model deteksi** di-pin dengan sha256 di `MODELS.json`, dan feed eksternal diverifikasi tanda tangannya.

## Batasan yang sudah diketahui

Hal berikut sudah tercatat dan sedang ditangani, jadi tidak perlu dilaporkan sebagai temuan baru:

- Deteksi L2 baru berjalan dalam *shadow mode*; keputusan masih diambil dari deteksi L1 ([tiket 49](../tickets/49-detection-l2-di-jalur-pep)).
- Scan file baru memeriksa 2 MiB teks pertama ([tiket 50](../tickets/50-scan-file-hanya-2mib-teks-pertama)).
- Mode gagal saat bundle kebijakan kedaluwarsa lebih dari 24 jam belum diterapkan ([tiket 51](../tickets/51-fail-mode-bundle-kedaluwarsa-24-jam)).
- Selama Redis tidak tersedia, rate limit dan kuota token tidak ditegakkan.

Daftar terbaru ada di [Roadmap](./roadmap) dan [Ringkasan Tiket](../tickets/).
