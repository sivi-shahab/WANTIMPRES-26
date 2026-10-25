# Laporan NFR gate M1 (tiket 21)

Tanggal: 2026-10-10, commit dasar `f0befa5`. Harness dan data mentah: `deploy/nfr/` (skrip) dan `deploy/nfr/results/` (JSON/log tiap pengukuran).

**Ringkasan.** Pada beban puncak ASM-2 (20 RPS) dan sampai 60 RPS per pod, overhead gateway jauh di bawah target (p95 ≈ 20 ms). Propagasi policy, kill switch, dan event ke OpenSearch juga memenuhi target. Soak 30 menit stabil, dan DR drill lulus (RPO 45 s, RTO 21 s, bucket WORM pulih utuh). Ada empat hal yang **tidak** memenuhi target atau spec: eval OPA (p99 9,0 ms vs 5 ms), throughput per pod (≈ 60–100 RPS vs 300 RPS), gateway yang **berhenti melayani saat Kafka mati**, dan latensi saat Redis mati. Ditambah tiga celah fungsional yang ditemukan saat pengukuran. Semuanya punya tiket (46–51), kecuali tiga hal yang diusulkan sebagai keputusan terima risiko dan **butuh sign-off** (§6).

## 1. Lingkungan dan metode

- **Host:** 1 mesin, 16 vCPU, 15 GB RAM, Linux 5.15 (WSL2), Docker Compose v2.29. Tanpa cluster Kubernetes, tanpa mTLS (harness memakai flag dev yang sudah disediakan service: `KAFKA_PLAINTEXT`, `OPENSEARCH_PLAINTEXT`, `MTLS_INSECURE` untuk detection-svc). Satu-satunya beban berat di host selama pengukuran (load average < 1 sebelum mulai).
- **Topologi (`deploy/nfr/compose.yaml`):** image service dibangun dari repo (`build/go.Dockerfile`). Satu "pod" = ai-gateway (3 vCPU) + sidecar OPA 1.21.1 (1 vCPU); sejak tiket 47, 2 + 2 vCPU dan decision log aktif seperti produksi dalam satu network namespace, total 4 vCPU sesuai §13.1. OPA mengambil bundle **bertanda tangan** (dibangun dengan `policysvc.Build` dari policy bawaan) dengan verifikasi signature dan `persist: true` seperti `deploy/base/opa/opa.yaml`. Pendukung: Kafka 3.9 (KRaft), karapace, Redis 8, OpenSearch 2.19.3, event-ingest, detection-svc, dan mock provider OpenAI-compatible (`deploy/nfr/nfr mock`) yang menjawab seketika.
- **Overhead** = latensi beban yang sama lewat gateway dikurangi langsung ke mock (load generator open-loop `deploy/nfr/nfr load`, prompt teks kantor biasa tanpa temuan detektor, 1K dan 8K token).
- **Model L2 tidak ikut.** Artefak model tiket 09/10 tidak ada di repo, dan, lebih penting, tidak ada PEP yang memanggil detection-svc (lihat temuan T5). Angka di bawah adalah jalur produksi saat ini: L1 in-process + OPA.
- **Reproduksi:** `deploy/nfr/run.sh up`, lalu `measure.sh`, `opa-bench.sh`, `chaos.sh`, `DURATION=24h soak.sh`, `dr.sh`, `timing-tests.sh`. `run.sh down` membersihkan.

## 2. Hasil vs §13.1

| Item §13.1 | Target | Hasil terukur | Status |
|---|---|---|---|
| Overhead gateway, teks ≤ 8K token | p95 ≤ 80 ms, p99 ≤ 200 ms | 20 RPS: 1K tok p95 **+19,6 ms**, p99 +22,5 ms; 8K tok p95 **+22,2 ms**, p99 +24,9 ms. 60 RPS: p95 24,9 ms, p99 29,3 ms total. 80 RPS: p99 171 ms. 100 RPS: runtuh (65% 503) | ✅ sampai kapasitas pod; lihat throughput |
| Overhead per chunk streaming | p95 ≤ 20 ms per window | 20 chunk × 5 ms, 20 RPS: total p95 141,5 vs 123,8 ms langsung = +17,7 ms per jawaban (termasuk keputusan akhir), ≤ 0,9 ms per chunk | ✅ (perkiraan per chunk, bukan per window internal) |
| OPA eval (sidecar) | p99 ≤ 5 ms (`opa bench`) | 1 vCPU: median 3,2 ms, p95 7,8 ms, **p99 9,0 ms**, max 22 ms. Setelah tiket 47 (`decision.checked`, bundle `-O=1`, `GOGC=800`): median 1,67 ms, **p99 3,8–4,4 ms** (3 run, `results/opa-bench.txt`) | ✅ setelah tiket 47 |
| File scan sync ≤ 5 MB | p95 ≤ 2 s | zip CSV 5,1 MB: p95 **0,38 s** (extract + L1, 4 vCPU) | ✅* hanya 2 MiB teks pertama diperiksa → tiket 50; format via Tika tidak diukur |
| File scan async ≤ 50 MB | p95 ≤ 60 s | zip CSV 49 MB: p95 **0,37 s** | ✅* sama: angka ini rendah *karena* pemotongan → tiket 50 |
| Throughput gateway per pod (4 vCPU) | ≥ 300 RPS | Pembagian manifest (gateway 3 + OPA 1): sehat **60 RPS**, menurun di 80, runtuh di 100 (OPA 106% CPU, gateway 59%). OPA 3 + gateway 1: sehat **100 RPS**, maksimum ≈ 225 RPS dengan p95 1,5 s. Semua itu **tanpa** decision log OPA, yang di produksi aktif. Setelah tiket 47, dengan decision log, gateway 2 + OPA 2: dalam target sampai **125 RPS** (p95 61 ms, p99 180 ms), 150 RPS sedikit di atas (p99 332 ms), runtuh di 175 (`results/t47-*`) | ❌ → tiket 47 (butuh keputusan) |
| Propagasi publish/rollback ke semua PEP | ≤ 60 s p99 | `TestPropagation` (2 replika control-plane, OPA nyata, 22 release): p50 0,18 s, **p99 15,2 s** | ✅ |
| Kill switch efektif | ≤ 10 s | `TestKillSwitchPropagation`: maks 0,19 s ke OPA, **1,19 s** end-to-end dengan poll gateway 1 s; `mcpgw TestKillSwitch`: sesi terputus 0,99 s | ✅ |
| Event ke dashboard/SIEM | ≤ 60 s p95 | gateway → Kafka → event-ingest → OpenSearch (bisa dicari): 200/200, p50 2,6 s, **p95 4,8 s**, maks 5,1 s | ✅ dashboard; jalur siem-export tidak diukur di harness |
| Availability data plane | 99,95% bulanan | tidak terukur di harness satu host | ⚠️ usulan RA-1 (§6); chaos menemukan T3 yang mengancamnya |
| Availability control/analytics plane | 99,9% bulanan | tidak terukur | ⚠️ usulan RA-1 |

Mentah: `results/{direct,gateway}-*-20rps.json`, `ramp-*.json`, `split-opa3-gw1-*.json`, `*-stream-*.json`, `opa-bench.txt`, `filescan.json`, `propagation-killswitch.txt`, `event-to-opensearch.json`. File `gateway-*-100rps.json` dan `gateway-*-closed-*.json` adalah run saturasi (beban di atas kapasitas pod): angkanya menunjukkan kegagalan di 100 RPS, bukan overhead.

## 3. Chaos dan fail mode (§13.3)

Dua app, masing-masing 30 RPS: `nfr-closed` (`fail_closed`) dan `nfr-open` (`fail_open`). Setiap dependensi dimatikan 30 detik lalu dinyalakan lagi (`chaos.sh`, `results/chaos-summary.txt`). `results/chaos-*` adalah run ulang setelah tiket 46 dan 48 (2026-10-11), di host yang juga dipakai proses lain: ekor ~1 s di beberapa skenario tanpa gangguan berasal dari host, bukan dari gateway. Baris lain di tabel ini mengutip run awal, yang ada di riwayat git.

| Skenario | Diharapkan | Teramati | Status |
|---|---|---|---|
| Baseline | | 100% 200, p95 25,7 ms | |
| OPA (PDP) mati | `fail_closed` menolak, `fail_open` meneruskan + `fail_open_total` | closed: 899/899 **503** `wantimpres26_policy_unavailable`; open: 899/899 200, `aigw_fail_open_total` +1.798 (2 keputusan per request) | ✅ |
| OPA di-restart saat Policy Service mati | pakai bundle cache terakhir | melayani lagi dalam **1 s** dari bundle tersimpan; app `fail_closed` 100% 200 (butuh keputusan PDP) | ✅ |
| Bundle kedaluwarsa > 24 jam | masuk fail-mode policy | **tidak diimplementasikan** di PEP | ❌ → tiket 51 |
| Detection timeout (150 ms) → L1 saja | | tidak bisa diuji: tidak ada PEP yang memanggil detection-svc. Mematikannya tidak berdampak apa pun (p95 24 ms, 100% 200) | ❌ → tiket 49 |
| Kafka mati | (tidak disebut eksplisit; data plane harus tetap jalan untuk 99,95%) | Awalnya **semua** request kedua app tidak selesai dalam 30 s sampai Kafka hidup lagi: `ProduceSync` sinkron di jalur request tidak berhenti di context 2 s. Setelah tiket 46 (produce async): 899/899 200 per app, p95 20 ms, p99 25 ms; 3.592 event hilang terhitung di `decision_events_dropped_total` | ✅ setelah tiket 46 |
| Redis mati | limit tidak ditegakkan, trafik jalan | Awalnya 100% 200, tetapi p95 **416 ms** (kadang sampai 3,8 s dengan 503), ~7.000 baris error log per 30 s. Setelah tiket 48 (timeout 50 ms + fallback per replika): 5 run Redis saja, p95 17–59 ms, p99 ≤ 149 ms, 0 dari 899 request 503; 6 baris log | ✅ setelah tiket 48 |
| Pemulihan setelah tiap skenario | kembali normal | p95 20–28 ms, 100% 200 | ✅ |

## 4. Soak

- **Dijalankan:** soak **dipersingkat 30 menit** pada 50 RPS (2,5× puncak ASM-2, di bawah kapasitas sehat 60 RPS). Hasil: 89.998 request, **0 error**, p95 per menit 22,5–25,1 ms tanpa drift, p99 total 27,9 ms. Memori stabil: gateway 55 MiB awal = akhir, OPA 26 → 31 MiB, event-ingest 11 MiB (`results/soak-30m*.{json,tsv}`).
- **Belum:** soak 24 jam yang diminta tiket tidak muat di sesi ini. Skrip siap: `DURATION=24h deploy/nfr/soak.sh` (atau sebagai Job di staging dengan URL gateway staging). Lihat usulan RA-2.

## 5. DR drill (§12.1)

Prosedur (`dr.sh`, `results/dr.json`):
1. Postgres 17 primary dengan WAL archiving (`archive_timeout` 60 s). Segmen dikirim ke MinIO (S3-compatible) begitu diarsip, dan base backup (`pg_basebackup -Ft -z -X stream`) diunggah ke MinIO.
2. Sebuah writer menyisipkan baris bertimestamp tiap ~200 ms selama ~4,5 menit.
3. **Bencana:** primary, disk-nya, dan arsip lokalnya dihapus.
4. **Restore:** server baru hanya dari isi MinIO (base backup + WAL, PITR sampai akhir arsip, lalu promote).

| Item §12.1 | Target | Hasil | Status |
|---|---|---|---|
| Postgres RPO | ≤ 15 menit | **45,2 s** (baris terakhir yang pulih vs saat bencana; batas atasnya `archive_timeout` 60 s + jeda kirim) | ✅ |
| Postgres RTO | ≤ 4 jam | **20,9 s** sampai server hasil restore menerima tulis (775 baris, 7 objek WAL) | ✅ untuk ukuran ini |
| Object storage (bucket audit WORM) | dapat dipulihkan, retensi tetap | object lock COMPLIANCE: delete versi **ditolak**; replika di MinIO kedua; primary hilang; bucket baru dipulihkan dari replika dalam **6,8 s**; isi identik (sha256); retensi COMPLIANCE terpasang pada objek hasil restore | ✅ |

Catatan:
- **RTO naik dengan ukuran data.** Restore base backup dan replay WAL sebanding dengan volume, jadi 21 detik di sini hanya berlaku untuk database kecil. Ulangi drill di DRC dengan salinan berukuran produksi, dan catat waktu unduh dari object storage DRC.
- **RPO bergantung pada `archive_timeout`.** Produksi (Patroni) sebaiknya memakai `archive_timeout` ≤ 60 s atau streaming ke DRC.
- **Replikasi bucket di drill dilakukan dengan `mc mirror` sekali jalan.** Di produksi, pakai site replication MinIO atau replikasi bucket S3 yang berjalan terus-menerus.

## 6. Deviasi: tiket dan usulan keputusan

| # | Deviasi | Penanganan |
|---|---|---|
| T1 | OPA eval p99 9,0 ms > 5 ms | tiket **47**, selesai |
| T2 | Throughput per pod 60–100 RPS < 300 RPS | tiket **47**: naik ke 125 RPS, 300 belum (butuh keputusan) |
| T3 | Kafka mati → gateway berhenti melayani | tiket **46** (P0, M1), selesai |
| T4 | Redis mati → p95 416 ms | tiket **48**, selesai |
| T5 | L2/detection-svc tidak di jalur PEP; timeout 150 ms §13.3 tidak ada | tiket **49** |
| T6 | Scan file hanya 2 MiB teks pertama (angka latensi file "lulus" karena ini) | tiket **50** |
| T7 | Fail mode bundle > 24 jam tidak diimplementasikan | tiket **51** |
| RA-1 | Availability 99,95% / 99,9% tidak bisa dibuktikan oleh gate lokal | **usulan, butuh sign-off** |
| RA-2 | Soak 24 jam belum dijalankan (30 menit saja) | **usulan, butuh sign-off** |
| RA-3 | Angka diukur di 1 host docker, tanpa mTLS/SASL/TLS (tiket 40/41) dan tanpa model L2 | **usulan, butuh sign-off** |

**Usulan keputusan (belum diterima; menunggu sign-off pemilik risiko, mis. CISO/Head of IT Ops):**
- **RA-1:** availability dibuktikan lewat SLO produksi (error budget bulanan dari metrik gateway dan probe sintetis) setelah pilot, bukan di gate M1. Syaratnya, tiket 46 selesai lebih dulu, karena tanpa itu outage Kafka = outage data plane.
- **RA-2:** pilot terbatas boleh berjalan dengan soak 30 menit ini. Soak 24 jam di staging (`soak.sh`) wajib hijau sebelum rollout luas.
- **RA-3:** ulangi `measure.sh` dan `chaos.sh` di staging Kubernetes dengan mTLS, Kafka SASL/TLS, NetworkPolicy, dan model L2 terpasang. Angka laporan ini menjadi baseline, bukan bukti produksi.

## 7. Sizing awal (ASM-2, §13.2)

- **Beban:** 10.000 karyawan × 20% aktif × 50 interaksi = ~100.000 request/hari, puncak ~20 RPS. Linear sampai 100× = ~2.000 RPS.
- **Gateway, kapasitas terukur sekarang (60 RPS sehat per pod 4 vCPU):**
  - Puncak 20 RPS: 1 pod cukup; **2 pod** (manifest `replicas: 2`) untuk HA, headroom 3× per pod.
  - 100×: ⌈2.000 / 60⌉ = 34 pod + N+1 ≈ **35–36 pod (≈ 144 vCPU)**.
  - Dengan target tiket 47 (300 RPS/pod): 7 + 1 pod (32 vCPU).
  - Setelah tiket 47 (125 RPS/pod, gateway 2 + OPA 2 vCPU seperti manifest, decision log aktif): 100× = ⌈2.000 / 125⌉ = 16 pod + N+1 ≈ **17 pod (68 vCPU)**.
- **Event:**
  - ~2 decision event per request (request + response) = ~200.000 event/hari (2,3/s rata-rata, ~40/s puncak). Untuk Kafka (3 partisi) dan event-ingest ini kecil: harness memproses ratusan per detik tanpa lag.
  - OpenSearch: 321 byte/dokumen primer terukur (326.331 dokumen, 104,9 MB) = ~64 MB/hari primer, ~128 MB/hari dengan 1 replika, ~11,5 GB untuk 90 hari hot.
  - 100× = ~1,2 TB/90 hari: rencanakan ILM ke warm/cold.
- **Postgres:** beban per request tidak ada (gateway tidak menulis ke DB). Sizing ditentukan modul kontrol (insiden, audit), kecil di ASM-2.
