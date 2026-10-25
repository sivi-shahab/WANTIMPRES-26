---
title: Mengapa WANTIMPRES-26
---

# Mengapa WANTIMPRES-26

Karyawan sudah memakai AI, dengan atau tanpa izin. Aplikasi internal mulai memanggil LLM, dan agent mulai bertindak sendiri lewat tool. Pertanyaannya bukan lagi *apakah* AI dipakai, tetapi *apakah perusahaan tahu dan bisa mengendalikan data apa yang ikut terbawa*. WANTIMPRES-26 dibangun untuk menjawab pertanyaan itu.

## Masalah yang dijawab

| Masalah | Akibatnya tanpa kontrol | Yang dilakukan WANTIMPRES-26 |
|---|---|---|
| **Shadow AI** | Data nasabah, kode, dan dokumen internal keluar lewat akun GenAI pribadi tanpa jejak | Katalog aplikasi AI, deteksi shadow AI dari log proxy/DNS, status *sanctioned* per aplikasi |
| **DLP lama buta konteks AI** | Prompt, response streaming, RAG, dan tool call agent lolos dari pemeriksaan | Inspeksi di kanal AI: prompt, response (termasuk streaming), argumen dan hasil tool call |
| **Serangan khusus LLM** | Prompt injection, jailbreak, dan kebocoran system prompt tidak tertangkap oleh regex | Normalisasi dan decode berlapis, detektor injection, aturan arsitektural (least privilege, persetujuan manusia) |
| **Oversharing data tersimpan** | Copilot/RAG "menemukan" file yang aksesnya terlalu longgar | Connector data-at-rest, analisis ACL, remediation dengan persetujuan |
| **Agent otonom** | Agent memegang kredensial panjang dan bertindak tanpa jejak | Registry agent, token berumur pendek, tool pinning, persetujuan manusia, kill switch |
| **Kewajiban regulasi** | Sulit membuktikan kontrol ke OJK dan auditor; notifikasi pelanggaran 3×24 jam terlewat | Audit log hash-chain, pemetaan kontrol ke UU PDP/POJK 11/Panduan AI OJK, timer dan draft laporan pelanggaran |

## Mengapa bukan DLP atau gateway LLM biasa

| | DLP/CASB klasik | Gateway LLM satu vendor | **WANTIMPRES-26** |
|---|---|---|---|
| Memahami prompt dan response streaming | Terbatas | Ya | Ya |
| Tool call agent dan MCP | Tidak | Sebagian | Ya, lewat MCP gateway |
| Satu kebijakan untuk semua kanal | Per produk | Hanya kanal gateway | Ya, satu OPA untuk semua titik jaga |
| Detektor data Indonesia (NIK, KK, NPWP, rekening) | Biasanya perlu kustomisasi | Jarang | Bawaan, dengan validasi struktur |
| Data tetap di Indonesia | Tergantung vendor | Sering diproses di luar negeri | Seluruh komponen di-deploy di DC sendiri; model deteksi self-hosted |
| Bukti untuk OJK dan UU PDP | Laporan umum | Tidak ada | Pemetaan kontrol dan export bukti per periode audit |
| Kebijakan bisa dibaca dan diuji | Konfigurasi tertutup | Konfigurasi tertutup | Policy-as-code (Rego), simulasi sebelum publish, rollback |

WANTIMPRES-26 tidak harus menggantikan SWG/CASB/DLP yang sudah ada. Platform ini bisa mengonsumsi log dari alat tersebut dan fokus pada kanal yang belum mereka jaga (lihat [ADR-0001](../adr/0001-hosting-residency-build-scope)).

## Prinsip yang membuatnya bisa dipercaya

- **Penimbang terpisah dari penegak.** Semua titik jaga bertanya ke policy decision point yang sama, sehingga aturan tidak bercabang antar-kanal.
- **Pertahanan berlapis.** Aturan deterministik, model ML, dan kontrol arsitektural saling menutup celah. Tidak ada satu detektor yang dipercaya sendirian.
- **Privasi sejak awal.** Konten mentah tidak disimpan secara default; yang disimpan hanya metadata, hash, dan cuplikan yang sudah disamarkan.
- **Keputusan bisa dijelaskan.** Setiap keputusan membawa `reason_codes`, versi kebijakan, dan versi model.
- **Mode gagal eksplisit.** Setiap aplikasi menentukan sendiri: tutup (`fail_closed`) atau tetap jalan dengan alarm (`fail_open`) saat penimbang tidak tersedia.

## Bukti terukur

Angka berikut diambil dari [laporan NFR gate M1](../nfr/m1-report). Pengukuran dilakukan di satu host Docker, tanpa mTLS/SASL dan tanpa model L2, jadi angka produksi perlu diukur ulang.

| Yang diukur | Target spec | Hasil |
|---|---|---|
| Tambahan latensi gateway (teks 8K token, p95) | ≤ 80 ms | **+22,2 ms** |
| Evaluasi kebijakan OPA (p99) | ≤ 5 ms | **3,8–4,4 ms** |
| Kill switch efektif end-to-end | ≤ 10 s | **1,19 s** |
| Publish/rollback kebijakan ke semua titik jaga (p99) | ≤ 60 s | **15,2 s** |
| Event sampai bisa dicari di OpenSearch (p95) | ≤ 60 s | **4,8 s** |
| PostgreSQL: RPO / RTO | ≤ 15 menit / ≤ 4 jam | **45,2 s / 20,9 s** |
| Throughput gateway per pod (4 vCPU) | ≥ 300 RPS | **125 RPS** dalam target; 300 RPS belum tercapai |

Chaos test juga menunjukkan gateway tetap melayani saat Kafka atau Redis mati, dan OPA kembali melayani dari bundle tersimpan dalam 1 detik setelah restart.

## Manfaat per peran

| Peran | Yang didapat |
|---|---|
| **CISO** | Skor posture dan tren AI di seluruh organisasi, risiko teratas, bukti untuk direksi dan regulator (lewat API posture dan export compliance; UI admin belum tersedia) |
| **SOC** | Insiden yang sudah dikorelasikan dan dideduplikasi, bukti tersamarkan, aksi containment lewat API, event ke SIEM yang sudah ada |
| **DLP analyst** | Kebijakan sebagai kode, simulasi dampak sebelum publish, exception dengan tanggal kedaluwarsa |
| **Compliance / DPO** | Pemetaan kontrol ke regulasi, riwayat kontrol per periode audit, draft laporan pelanggaran data |
| **AI engineer** | Cukup mengganti base URL ke gateway; SDK OpenAI/Anthropic yang ada tetap dipakai |
| **Agent owner** | Agent terdaftar dengan hak minimum, persetujuan untuk aksi berisiko, jejak sesi lengkap |
| **Karyawan** | Tahu alasan sebuah permintaan diblokir atau disamarkan lewat `reason_codes`, dan bisa meminta pengecualian |

## Batasan saat ini

Agar ekspektasi tepat, berikut yang belum selesai pada saat dokumentasi ini ditulis:

- Detection L2 (model NER dan classifier injection) baru berjalan dalam *shadow mode*: hasilnya dicatat di decision event, tetapi keputusan masih diambil dari deteksi L1 deterministik ([tiket 49](../tickets/49-detection-l2-di-jalur-pep)).
- Scan file baru memeriksa 2 MiB teks pertama ([tiket 50](../tickets/50-scan-file-hanya-2mib-teks-pertama)).
- Mode gagal saat bundle kebijakan kedaluwarsa lebih dari 24 jam belum diterapkan ([tiket 51](../tickets/51-fail-mode-bundle-kedaluwarsa-24-jam)).
- Throughput per pod 125 RPS, di bawah target 300 RPS; butuh keputusan sizing ([tiket 47](../tickets/47-optimasi-pdp-throughput-per-pod)).
- Belum ada UI admin; semua pengelolaan lewat API control-plane.
- Endpoint agent (P2) belum dibangun. WANTIMPRES-26 juga tidak mencegah kebocoran tanpa jalur teknis, misalnya memotret layar dengan ponsel pribadi.

Status terbaru setiap item ada di [Ringkasan Tiket](../tickets/).
