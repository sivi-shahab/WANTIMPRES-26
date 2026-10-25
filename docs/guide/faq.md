---
title: FAQ
outline: [2, 3]
---

# Pertanyaan yang Sering Diajukan

## Umum

### Apa itu WANTIMPRES-26?

Platform *Enterprise AI Data Security & AI Security Posture Management*. Platform ini memeriksa dan menimbang setiap interaksi AI di perusahaan, yaitu prompt, file, response model, dan tool call agent, sebelum data sensitif berpindah. Penjelasan lengkapnya ada di [Mengapa WANTIMPRES-26](./why).

### Apakah nama WANTIMPRES-26 berkaitan dengan lembaga negara?

Tidak. Nama ini adalah akronim teknis dari fungsi platform (*Workforce AI Network Threat Inspection, Monitoring, Policy, Risk & Enforcement System*), dan "26" berarti edisi 2026. Platform ini tidak berafiliasi dengan lembaga, partai, atau tokoh politik mana pun. Lihat [Filosofi Nama & Logo](../about/philosophy).

### Apakah WANTIMPRES-26 menggantikan DLP, CASB, atau SWG yang sudah ada?

Tidak harus. Cakupan v1 sengaja difokuskan pada kanal yang belum dijaga alat tersebut: AI gateway, MCP gateway untuk agent, detektor lokal, policy engine, audit, incident, compliance, dan connector data tersimpan. Shadow AI di v1 dibaca secara pasif dari log proxy/SWG/DNS yang sudah ada. Browser extension, adapter ICAP, dan endpoint agent ditunda sampai inventaris vendor yang ada diketahui. Keputusan ini tercatat di [ADR-0001](../adr/0001-hosting-residency-build-scope).

### Apakah AI tetap boleh dipakai karyawan?

Ya. Tujuannya bukan melarang AI, tetapi memastikan data yang ikut terbawa terkendali. Prompt tanpa data sensitif diteruskan seperti biasa. Aturan bawaan memang banyak memakai `block`, tetapi untuk kasus yang jelas berbahaya, misalnya kredensial yang dikirim ke AI mana pun atau data `restricted` ke provider di luar negeri. Data seperti nomor kartu (PAN) cukup disamarkan (`redact`).

## Privasi dan data

### Apakah isi prompt dan jawaban disimpan?

Tidak secara default. Yang disimpan hanya metadata, hash, klasifikasi, dan cuplikan yang sudah disamarkan. Konten asli hanya disimpan bila sebuah kebijakan mengaktifkan *forensic capture*. Dalam kasus itu konten dienkripsi per insiden, dan untuk membukanya perlu permintaan *unmask* yang disetujui orang lain serta izin `evidence.unmask`.

### Di mana data diproses dan disimpan?

Seluruh komponen berjalan di Kubernetes di data center dan DRC bank di Indonesia, sesuai POJK 11/2022. Model deteksi berjalan sendiri (self-hosted) di CPU, jadi konten tidak pernah dikirim ke pihak ketiga untuk diperiksa. Feed dari luar, seperti katalog aplikasi AI dan model detektor, hanya ditarik masuk dan diverifikasi tanda tangannya.

### Bagaimana dengan LLM provider di luar negeri?

Tidak dilarang total, tetapi diatur lewat katalog dan kebijakan. Untuk tujuan yang di-hosting di luar Indonesia, default-nya adalah:
- konten `restricted` diblokir,
- konten `confidential` (termasuk data pribadi nasabah) disamarkan atau diganti token, atau diblokir bila tidak bisa disamarkan,
- konten `internal` dan `public` diizinkan hanya untuk aplikasi berstatus `sanctioned`.

Setiap keputusan tercatat di audit log sebagai bukti untuk OJK dan UU PDP.

### Apakah karyawan dipantau secara pribadi?

Pemantauan dibatasi pada interaksi dengan layanan AI. Identitas pengguna di analitik disamarkan dengan HMAC, dan akses ke bukti asli dibatasi serta tercatat. Penilaian dampaknya terhadap karyawan didokumentasikan di [DPIA pemantauan AI karyawan](../dpia-pemantauan-ai-karyawan).

## Integrasi

### Apakah aplikasi kami perlu diubah untuk memakai gateway?

Hampir tidak. Ganti base URL ke gateway (`https://<gateway>/<nama-provider>/v1`) dan pakai key gateway sebagai pengganti key provider. SDK OpenAI, Anthropic, dan Gemini yang sudah dipakai tetap berfungsi. Langkahnya ada di [Cara Menggunakan](./how-to-use#hubungkan-aplikasi-ke-ai-gateway).

### Provider dan model apa yang didukung?

Bentuk API OpenAI (chat completions, responses, embeddings), Anthropic (messages), dan Gemini (generateContent, streamGenerateContent). Model self-hosted seperti vLLM, Ollama, atau TGI didukung lewat bentuk OpenAI. Gateway tidak memilih atau mengganti model.

### Apakah streaming didukung?

Ya, untuk OpenAI chat completions, Anthropic messages, dan Gemini streamGenerateContent. Jawaban diperiksa per jendela selama stream berjalan. Bila terjadi pelanggaran, stream dihentikan dengan cara yang sama seperti provider menghentikan konten terfilter.

### Bagaimana aplikasi tahu sebuah request diblokir atau disamarkan?

Setiap respons membawa header `X-Wantimpres26-Action` dan `X-Wantimpres26-Decision-Id`. Request yang diblokir menerima 403 dalam format error milik provider, sehingga SDK melempar error yang biasa. Pesannya menyertakan alasan dan Decision ID.

### Berapa tambahan latensinya?

Pada pengukuran M1, tambahan latensi p95 untuk teks 8K token sekitar 22 ms (target ≤ 80 ms). Angka ini diukur di satu host tanpa mTLS dan tanpa model L2, jadi perlu diukur ulang di produksi. Detailnya ada di [laporan NFR M1](../nfr/m1-report).

### Bagaimana dengan agent dan MCP?

Agent terhubung ke MCP server lewat MCP gateway dengan token OAuth yang audience-nya server tujuan. Gateway menukar token itu dengan token berumur pendek, hanya menampilkan tool yang sudah disetujui, menahan aksi berisiko untuk persetujuan manusia, dan menjalankan kill switch. Lihat [Hubungkan agent](./how-to-use#hubungkan-agent-lewat-mcp-gateway).

## Kebijakan dan operasional

### Siapa yang bisa mengubah kebijakan?

Kebijakan dibuat sebagai draft, disimulasikan, lalu diajukan. Versi baru hanya aktif setelah disetujui orang **yang berbeda** dari pembuatnya, yang memegang izin `policy.publish`. Persetujuan itu meminta login ulang dan justifikasi tertulis. Semua langkah tercatat di audit log dan bisa di-rollback.

### Apa yang terjadi jika policy engine mati?

Tergantung `fail_mode` aplikasi. Dengan `fail_closed` (default), request ditolak dengan 503 `wantimpres26_policy_unavailable`. Dengan `fail_open`, request diteruskan dan setiap kejadian dihitung di metrik. Setelah restart, OPA kembali melayani dari bundle kebijakan tersimpan dalam sekitar 1 detik.

### Apa yang terjadi jika Kafka atau Redis mati?

Gateway tetap melayani. Event keputusan yang tidak terkirim dihitung di metrik `decision_events_dropped_total`, dan limit rate/kuota tidak ditegakkan selama Redis mati.

### Seberapa cepat kill switch bekerja?

Pada pengukuran M1, kill switch efektif end-to-end dalam sekitar 1,2 detik (target ≤ 10 detik), dan sesi MCP yang berjalan terputus dalam kurang dari 1 detik.

### Bisakah mencoba aturan tanpa menegakkannya?

Bisa, dengan dua cara. Pertama, simulasikan versi kebijakan terhadap event lalu untuk melihat berapa keputusan yang berubah. Kedua, beri aturan `"mode": "monitor"` supaya ia hanya dicatat, tidak ditegakkan.

## Kepatuhan

### Regulasi dan standar apa yang dipetakan?

UU PDP (Law No. 27/2022) dan PP 33/2026, POJK 11/POJK.03/2022, Panduan Tata Kelola AI Perbankan OJK 2025, ISO/IEC 42001, NIST AI RMF, serta OWASP LLM Top 10 dan Agentic Top 10. Pemetaannya berversi dan bisa diekspor per periode audit. Sel ISO/IEC 42001 masih perlu dikonfirmasi terhadap salinan standar berlisensi.

### Bagaimana platform membantu kewajiban notifikasi pelanggaran 3×24 jam?

Insiden yang melibatkan data pribadi bisa dideklarasikan sebagai pelanggaran data. Sejak itu, timer 3×24 jam berjalan dan sistem menyiapkan draft laporan berisi data yang terungkap, kapan dan bagaimana kejadiannya, serta langkah penanganan.

### Bagaimana membuktikan audit log tidak diubah?

Audit log bersifat append-only dan berantai hash. Setiap hari dibuat anchor yang ditandatangani dan disimpan di object storage dengan object lock. Integritasnya bisa diperiksa kapan saja dengan `control-plane audit verify`.

## Status proyek

### Apakah sudah siap produksi?

Belum sepenuhnya. Gate NFR M1 masih menunggu sign-off, dan beberapa hal terbuka:
- detection L2 baru berjalan dalam *shadow mode*,
- scan file baru memeriksa 2 MiB teks pertama,
- mode gagal untuk bundle kebijakan yang kedaluwarsa belum diterapkan,
- throughput per pod baru 125 RPS dari target 300.

Daftar lengkapnya ada di [Batasan saat ini](./why#batasan-saat-ini) dan [Ringkasan Tiket](../tickets/).

### Apakah ada UI admin?

Belum. Semua pengelolaan lewat API control-plane yang diamankan dengan OIDC dan MFA.

### Di mana melaporkan masalah atau mengusulkan fitur?

Tiket disimpan sebagai file markdown di `.scratch/ai-data-security/issues/` di [repository GitHub](https://github.com/sivi-shahab/WANTIMPRES-26), satu file per tiket. Status setiap tiket bisa dilihat di [Ringkasan Tiket](../tickets/).
