---
title: Glosarium
outline: [2, 2]
---

# Glosarium

Istilah yang sering muncul di dokumentasi WANTIMPRES-26, beserta artinya dalam konteks platform ini. Gunakan pencarian (<kbd>Ctrl</kbd> <kbd>K</kbd>) untuk langsung menemukan istilah.

## Konsep platform

| Istilah | Arti |
|---|---|
| **AI-SPM** | *AI Security Posture Management*: menemukan, menilai, dan memperbaiki risiko keamanan dari pemakaian AI di organisasi. |
| **DSPM** | *Data Security Posture Management*: menemukan data sensitif yang tersimpan dan menilai siapa yang bisa mengaksesnya. |
| **Titik jaga (PEP)** | *Policy Enforcement Point*: komponen yang menangkap interaksi dan menjalankan keputusan, misalnya AI gateway, MCP gateway, dan connector. |
| **Penimbang kebijakan (PDP)** | *Policy Decision Point*: satu-satunya tempat keputusan diambil. Di WANTIMPRES-26 perannya dijalankan OPA. |
| **Hybrid enforcement** | Pola arsitektur dengan banyak titik jaga tetapi satu lapisan deteksi, satu PDP, dan satu pipeline event. |
| **Kanal** (*channel*) | Jalur yang dilewati data: `ai_gateway`, `mcp_gateway`, `connector`, dan seterusnya. |
| **Arah** (*direction*) | Posisi data pada sebuah interaksi: `request`, `response`, `tool_call`, `tool_result`, atau `at_rest`. |
| **Control plane** | Layanan pengelola: identitas, kebijakan, katalog, agent, insiden, compliance, dan posture. Diakses lewat API. |
| **Data plane** | Titik jaga yang berada di jalur trafik secara langsung. |
| **Shadow AI** | Aplikasi AI atau agent yang dipakai tanpa visibilitas atau persetujuan tim IT. |
| **Katalog aplikasi AI** | Daftar aplikasi AI beserta status persetujuan, lokasi hosting, dan atribut risikonya. |
| **Status sanction** | Status persetujuan aplikasi: `sanctioned`, `tolerated`, `unsanctioned`, `blocked`, atau `under_review`. |

## Deteksi dan klasifikasi

| Istilah | Arti |
|---|---|
| **L1** | Deteksi deterministik dan cepat: normalisasi teks, decode berlapis, regex, validator (misalnya Luhn dan struktur NIK), serta pola secret. Ini yang saat ini menentukan keputusan. |
| **L2** | Deteksi berbasis model ML: NER untuk data pribadi dan classifier prompt injection, dijalankan di CPU (ONNX int8). |
| **Shadow mode** | Model berjalan dan hasilnya dicatat, tetapi belum ikut menentukan keputusan. L2 saat ini berada dalam mode ini. |
| **NER** | *Named Entity Recognition*: model yang mengenali entitas seperti nama, alamat, atau nomor identitas di teks bebas. |
| **Kelas data** | Jenis data yang terdeteksi, misalnya `PII_ID.NIK`, `PCI.PAN`, atau `SECRET.*`. |
| **Sensitivitas** | Tingkat kerahasiaan konten: `public` < `internal` < `confidential` < `restricted`. |
| **Normalisasi** | Menyeragamkan teks sebelum diperiksa (NFKC, menghapus karakter tak terlihat, memetakan homoglyph) agar serangan yang disamarkan tetap tertangkap. |
| **Eval corpus** | Kumpulan data uji beku, di-pin dengan hash, untuk mengukur precision dan recall detektor sebelum rilis. |
| **Precision / recall** | Precision: berapa persen temuan yang benar. Recall: berapa persen data sensitif yang berhasil ditemukan. |
| **ECE** | *Expected Calibration Error*: seberapa jauh skor keyakinan model dari kenyataan. Makin kecil makin baik. |

## Ancaman pada AI

| Istilah | Arti |
|---|---|
| **Prompt injection** | Instruksi jahat yang disisipkan agar model mengabaikan instruksi aslinya. *Direct* berarti ditulis langsung oleh pengguna; *indirect* berarti tersembunyi di konten luar seperti dokumen, web, atau hasil tool. |
| **Jailbreak** | Upaya membuat model melanggar batas keamanannya, misalnya lewat roleplay atau persona. |
| **System prompt leakage** | Bocornya instruksi sistem aplikasi lewat jawaban model. |
| **Canary token** | Penanda rahasia yang disisipkan ke system prompt. Jika muncul di jawaban, berarti system prompt bocor. |
| **Adversarial suffix** | Rangkaian karakter hasil optimasi yang ditempelkan ke prompt untuk membobol model (contoh: serangan GCG). |
| **Excessive agency** | Agent punya hak atau kemampuan lebih besar dari yang dibutuhkan tugasnya. |
| **Tool poisoning** | Instruksi jahat yang disembunyikan di deskripsi tool MCP. |
| **Rug pull** | Definisi tool yang diam-diam berubah setelah disetujui. |
| **Memory poisoning** | Konten jahat yang ditulis ke memori jangka panjang atau vector store agent. |
| **OWASP LLM / ASI** | Daftar 10 risiko teratas OWASP untuk aplikasi LLM (`LLM01`–`LLM10`, 2025) dan aplikasi agentic (`ASI01`–`ASI10`, 2026). |

## Kebijakan dan keputusan

| Istilah | Arti |
|---|---|
| **OPA** | *Open Policy Agent*: mesin kebijakan open source yang menjadi PDP, berjalan sebagai sidecar di samping setiap titik jaga. |
| **Rego** | Bahasa kebijakan milik OPA. Mesin keputusan WANTIMPRES-26 ada di `policy/wantimpres26/decision.rego`. |
| **Policy-as-code** | Kebijakan ditulis sebagai kode atau data berversi yang bisa direview, diuji, dan di-rollback. |
| **Bundle** | Paket kebijakan dan data yang ditandatangani lalu didistribusikan ke semua sidecar OPA. |
| **Aksi** | Hasil keputusan, dari yang paling longgar: `allow` < `warn` < `redact` < `tokenize` < `require_approval` < `quarantine` < `block`. Jika beberapa aturan cocok, aksi paling ketat yang dipakai. |
| **Obligation** | Tugas tambahan yang menyertai aksi, misalnya kelas data apa saja yang harus disamarkan. |
| **Reason code** | Kode alasan yang menjelaskan sebuah keputusan, misalnya `SECRET_TO_AI` atau `PCI_PAN`. |
| **Decision ID** | Pengenal unik setiap keputusan, untuk dilacak tim keamanan. |
| **Mode monitor** | Aturan yang hanya dicatat tanpa ditegakkan, untuk mencoba dampaknya. |
| **Simulasi** | Menjalankan versi kebijakan baru terhadap event lalu untuk melihat berapa keputusan yang berubah. |
| **Exception** | Pengecualian terbatas dari sebuah kebijakan, dengan pemberi persetujuan dan tanggal kedaluwarsa wajib. |
| **Four-eyes** | Prinsip dua orang: pembuat dan penyetuju tidak boleh orang yang sama. |
| **Fail mode** | Perilaku titik jaga saat PDP tidak tersedia: `fail_closed` (tolak, default) atau `fail_open` (teruskan dan catat di metrik). |
| **Skor risiko** | Nilai 0–100 per event dari faktor sensitivitas, tujuan, serangan, aksi agent, volume, dan identitas. *Critical override* langsung menetapkan skor tinggi untuk kasus tertentu. |

## Perlindungan data

| Istilah | Arti |
|---|---|
| **Redact** | Mengganti teks sensitif dengan penanda `[REDACTED:<TIPE>]`. |
| **Tokenize** | Mengganti nilai sensitif dengan token yang formatnya sama, sehingga aplikasi tetap berjalan tanpa melihat nilai asli. |
| **FPE / FF1** | *Format-Preserving Encryption*; FF1 adalah algoritma FPE standar NIST yang dipakai token vault. |
| **Detokenize** | Mengembalikan token menjadi nilai asli. Hanya untuk aplikasi atau principal yang berhak, dan setiap kejadian tercatat. |
| **Pseudonimisasi** | Mengganti identitas dengan nilai HMAC berkunci (*pepper* per tenant), supaya analitik tidak menyimpan identitas asli. |
| **Forensic capture** | Penyimpanan konten asli yang hanya aktif bila diizinkan kebijakan; terenkripsi per insiden. |
| **Unmask** | Membuka bukti asli dari sebuah insiden. Perlu permintaan yang disetujui orang lain dan izin `evidence.unmask`. |
| **Data at rest** | Data yang tersimpan, misalnya di SharePoint, Google Drive, atau bucket cloud. |
| **Oversharing** | Data sensitif yang aksesnya terlalu luas, misalnya link publik atau grup "semua karyawan". |
| **Remediation** | Tindakan memperbaiki oversharing, misalnya mencabut link publik. Dijalankan setelah disetujui. |
| **Data residency** | Ketentuan lokasi pemrosesan dan penyimpanan data. Platform ini sepenuhnya berjalan di Indonesia. |

## Agent dan MCP

| Istilah | Arti |
|---|---|
| **Agent** | Program AI yang bertindak sendiri dengan memanggil tool atau API. |
| **MCP** | *Model Context Protocol*: protokol standar untuk menghubungkan agent ke tool dan sumber data. |
| **MCP server** | Layanan yang menyediakan tool lewat MCP, misalnya akses CRM. |
| **MCP gateway** | Titik jaga WANTIMPRES-26 di antara agent dan MCP server. |
| **Tool pinning** | Mencatat hash definisi tool yang sudah disetujui, sehingga perubahan diam-diam terdeteksi. |
| **HITL** | *Human-in-the-loop*: aksi berisiko ditahan sampai disetujui manusia. |
| **Kill switch** | Penghenti darurat per agent, tool, aplikasi, atau global. Mencabut token dan memutus sesi yang berjalan. |
| **Audience** (`aud`) | Klaim di token yang menyebut untuk layanan mana token itu diterbitkan. Token dengan audience salah ditolak. |
| **Token exchange** | Menukar token agent dengan token baru berumur pendek untuk layanan tujuan (RFC 8693), supaya token agent tidak pernah diteruskan. |
| **Agent registry** | Daftar agent beserta pemilik, identitas, tool yang diizinkan, dan statusnya. |

## Identitas dan infrastruktur

| Istilah | Arti |
|---|---|
| **OIDC** | *OpenID Connect*: standar login yang dipakai control-plane, dengan Keycloak sebagai broker. |
| **SCIM** | Standar sinkronisasi pengguna dan grup dari direktori perusahaan. |
| **RBAC / ABAC** | Kontrol akses berdasarkan peran (*role*) dan atribut, misalnya unit bisnis atau region. |
| **Break-glass** | Akun darurat dengan akses penuh yang setiap pemakaiannya diaudit. |
| **mTLS** | TLS dua arah: kedua sisi koneksi saling membuktikan identitasnya. |
| **SPIFFE / SVID** | Standar identitas workload. Setiap pod mendapat sertifikat berumur pendek dengan ID `spiffe://wantimpres26.bank/…`. |
| **Tenant** | Satuan isolasi data. WANTIMPRES-26 di-deploy single-tenant, tetapi desainnya tenant-aware. |
| **RLS** | *Row-Level Security* di PostgreSQL: setiap query otomatis dibatasi ke data tenant-nya. |
| **Decision event** | Catatan metadata setiap keputusan (`decision_event.v1`) yang dikirim lewat Kafka. Tidak berisi konten mentah. |
| **Schema registry** | Layanan yang menyimpan skema event (di sini Karapace) agar produsen dan konsumen sepakat formatnya. |
| **Image bertanda tangan** | Image container yang ditandatangani (cosign). Cluster hanya menjalankan image seperti ini. |
| **SBOM** | *Software Bill of Materials*: daftar komponen di dalam sebuah image. |

## Audit, insiden, dan operasional

| Istilah | Arti |
|---|---|
| **Audit log hash-chain** | Log tambah-saja; setiap entri memuat hash entri sebelumnya, sehingga perubahan apa pun terdeteksi. |
| **Anchor** | Ringkasan hash audit log harian yang ditandatangani dan disimpan di object storage WORM. |
| **WORM / object lock** | *Write Once Read Many*: objek tidak bisa diubah atau dihapus selama masa retensi. |
| **Insiden** | Kumpulan event terkait yang perlu ditangani SOC, dengan status, tingkat keparahan, dan bukti. |
| **Containment** | Tindakan membatasi dampak insiden, misalnya memblokir pengguna ke sebuah aplikasi atau mencabut token agent. |
| **Breach timer** | Hitung mundur 3×24 jam sejak pelanggaran data pribadi dideklarasikan, sesuai UU PDP Pasal 46. |
| **Posture** | Gambaran tingkat keamanan saat ini per domain (discovery, data, prompt, agent, policy) beserta trennya. |
| **SIEM / SOAR / ITSM** | Sistem pemantauan keamanan, otomasi respons, dan manajemen tiket layanan TI yang menerima event dari platform. |
| **NFR** | *Non-Functional Requirements*: target latensi, throughput, ketersediaan, dan pemulihan. Lihat [laporan NFR M1](../nfr/m1-report). |
| **p95 / p99** | Persentil latensi: 95% atau 99% permintaan selesai dalam waktu tersebut. |
| **RPO / RTO** | Batas data yang boleh hilang (RPO) dan batas waktu pemulihan (RTO) saat bencana. |
| **DC / DRC** | *Data Center* dan *Disaster Recovery Center*. |
| **Chaos test** | Uji ketahanan dengan sengaja mematikan komponen, misalnya OPA, Kafka, atau Redis. |

## Regulasi dan standar

| Istilah | Arti |
|---|---|
| **UU PDP** | Undang-Undang No. 27/2022 tentang Pelindungan Data Pribadi. |
| **PP 33/2026** | Peraturan Pemerintah pelaksana UU PDP. |
| **OJK** | Otoritas Jasa Keuangan, pengawas sektor jasa keuangan di Indonesia. |
| **POJK 11/2022** | POJK 11/POJK.03/2022 tentang Penyelenggaraan Teknologi Informasi oleh Bank Umum, termasuk kewajiban DC/DRC di Indonesia. |
| **Panduan AI Perbankan OJK** | Panduan Tata Kelola Kecerdasan Artifisial Perbankan Indonesia (OJK, 2025). |
| **ISO/IEC 42001** | Standar sistem manajemen AI. |
| **NIST AI RMF** | Kerangka manajemen risiko AI dari NIST (Govern, Map, Measure, Manage). |
| **DPIA** | *Data Protection Impact Assessment*: penilaian dampak pemrosesan data pribadi. Lihat [DPIA pemantauan AI karyawan](../dpia-pemantauan-ai-karyawan). |
| **DPO** | *Data Protection Officer*, pejabat pelindungan data pribadi. |
| **NIK / KK / NPWP** | Nomor Induk Kependudukan, nomor Kartu Keluarga, dan Nomor Pokok Wajib Pajak. |
| **PAN** | *Primary Account Number*: nomor kartu pembayaran, divalidasi dengan algoritma Luhn. |

## Istilah proyek

| Istilah | Arti |
|---|---|
| **ADR** | *Architecture Decision Record*: catatan keputusan arsitektur beserta alasan dan alternatif yang ditolak. Lihat [ADR-0001](../adr/0001-hosting-residency-build-scope). |
| **DEC-n / ASM-n / U-n** | Penanda di spec untuk keputusan (*decision*), asumsi, dan hal yang belum diketahui (*unknown*). |
| **FR-…** | Penanda *functional requirement* di spec, misalnya `FR-POL-4`. |
| **M0–M4** | Milestone roadmap, dari discovery (M0) sampai fitur P2 (M4). |
| **P0 / P1 / P2** | Prioritas: P0 wajib untuk MVP, P1 fase berikutnya, P2 lanjutan. |
| **Status tiket** | Antara lain `needs-triage`, `needs-signoff`, `needs-gitlab-run`, `deferred`, dan `done`. Lihat [Ringkasan Tiket](../tickets/). |
