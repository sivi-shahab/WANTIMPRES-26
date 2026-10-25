# 25: Kalibrasi risk scoring dengan label triage SOC

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M2
Blocked by: 17, 18
Spec: `../spec.md` §4.9 FR-RISK-3

## Konteks
Bobot awal perlu dikalibrasi dengan data nyata.

## Scope
- Pipeline label TP/FP dari triage.
- Analisis kalibrasi bobot per kuartal + simulasi versi bobot baru.
- Laporan perubahan distribusi severity.

## Acceptance criteria
- [x] Versi bobot baru hanya aktif setelah simulasi dan approval. *(`TestCalibration`: submit tanpa simulasi ditolak (`ErrState`), approve oleh author ditolak (`ErrFourEyes`), approve oleh orang lain mengaktifkan versi dan memotong policy release dalam satu transaksi. Decision lalu membawa `risk_version = risk-cal-1`, dan release berikutnya dari modul lain tetap membawa bobot itu.)*

## Keputusan
- **Label** (`riskcal.Labels`): verdict per insiden yang di-resolve dalam window. Pernah `Contained` = TP; `Investigating → Resolved` tanpa containment = FP. Label kelas analis per event (`tuning.labels`, tiket 38) meng-override verdict insiden untuk event itu.
- **Fit kuartalan** (`POST /risk/versions {"propose": true}`, `policy.write`): logistic regression verdict terhadap enam faktor dari `data.wantimpres26.risk` pada label 3 bulan terakhir. Minimal 60 verdict dengan ≥ 20 per kelas, kalau kurang `400`. Faktor yang konstan di semua label tidak diubah bobotnya. Faktor lainnya digeser setengah jalan (`Shrink = 0.5`) ke porsi hasil fit, dengan total massa mereka tetap. Bobot dibulatkan 2 desimal dan jumlahnya tetap 1. Basis fit (jumlah verdict, koefisien, bobot lama, window) disimpan di versi.
- **Config manual** (`{"config": {...}}`) juga bisa. Config yang ditolak `risk.config_errors` tidak pernah menjadi versi.
- **Simulasi** (`POST /risk/versions/{v}/simulate`): replay label kuartal ini plus event keputusan 30 hari terakhir (`search.Events`) di bawah config saat ini dan kandidat. Laporan berisi distribusi severity, TP/FP per band, rata-rata skor TP vs FP, jumlah event yang naik/turun band, dan jumlah event ≥ `incident.MinRisk`. Laporan disimpan di versi untuk dibaca approver.
- **State**: draft → simulated → pending_approval → active (yang lama → retired). Reject → draft. Approve/reject memakai `policy.publish` (step-up + justifikasi) dengan 4-eyes terhadap author. Semua langkah diaudit. Satu versi aktif per tenant (unique index).
- Versi aktif ikut setiap policy release lewat `lifecycle.AddExtra`, didaftarkan sebelum modul lain memotong release.

## Hasil verifikasi lokal (2026-10-10)
- `go vet ./...` + `go test -race ./...` dengan Postgres 17 hijau. Data sintetis (50 TP = data ke AI unsanctioned, 41 FP = teks mirip injection ke asisten sanctioned): rata-rata skor TP/FP 36,4/25,5 → 43,5/13,6. 17 event naik band, 0 turun.

## Sisa
- Belum ada penjadwal otomatis per kuartal: propose dipicu manual lewat API (cron/CI bisa memanggil endpoint yang sama).
- Kalibrasi threshold severity (`levels`) belum di-fit, hanya bobot. Bisa diubah lewat config manual.
- Eval di data triage nyata bank setelah M2 berjalan satu kuartal.
