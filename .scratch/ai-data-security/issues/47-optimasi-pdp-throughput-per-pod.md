# 47: Optimasi PDP: OPA eval p99 dan throughput gateway per pod

Status: needs-signoff
Type: task
Priority: P1
Milestone: M1
Blocked by: -
Spec: `../spec.md` §13.1 (OPA eval p99 ≤ 5 ms; throughput gateway per pod 4 vCPU ≥ 300 RPS); temuan tiket 21 (`docs/nfr/m1-report.md`)

## Konteks
Hasil tiket 21 (bundle bawaan, input khas gateway):
- `opa bench` di 1 vCPU: median 3,2 ms, p95 7,8 ms, **p99 9,0 ms** (target 5 ms).
- Satu pod (gateway 3 vCPU + OPA 1 vCPU) sehat sampai 60 RPS; di 80 RPS p99 171 ms, di 100 RPS runtuh (503 karena PDP timeout). OPA di 100% CPU, gateway baru ~60%. Dengan OPA 3 vCPU + gateway 1 vCPU, pod sehat di 100 RPS dan mentok di ~225 RPS dengan latensi > 1 detik. **Target 300 RPS tidak tercapai.**
- Profil teratas: `decision.rego:27` (`json.match_schema` atas input di setiap keputusan), lalu pencocokan rule `decision.rego:62-64`, lalu `risk.rego:58`. Setiap request gateway butuh 2 keputusan (request dan response).

## Scope
- Validasi skema input di PEP (Go, sekali) atau skema yang dikompilasi sekali, bukan `json.match_schema` per keputusan. PDP tetap fail closed untuk input yang tidak valid.
- Indeks rule berdasarkan `channel`/`direction`, atau pre-filter, agar tidak semua rule dievaluasi.
- Pertimbangkan satu keputusan untuk response yang bersih (tanpa temuan) bila policy mengizinkan.
- Ukur ulang dengan `deploy/nfr/opa-bench.sh` dan `deploy/nfr/measure.sh` (ramp). Tetapkan pembagian vCPU sidecar/gateway di manifest sesuai hasil.

## Acceptance criteria
- [x] `opa bench` p99 ≤ 5 ms pada 1 vCPU. *(`deploy/nfr/opa-bench.sh` atas `decision.checked` dari bundle `policysvc.Build`, `GOGC=800`: median 1,65–1,70 ms, p99 **3,8–4,4 ms** di 3 run. Sebelumnya median 3,2 ms, p99 9,0 ms.)*
- [ ] Satu pod 4 vCPU ≥ 300 RPS teks dengan overhead p95 ≤ 80 ms dan p99 ≤ 200 ms. *(**Belum.** Gateway 2 + OPA 2 vCPU, decision log aktif: dalam target sampai **125 RPS** (p95 61 ms, p99 180 ms); 150 RPS p95 90 ms, p99 332 ms; runtuh di 175 RPS. Tiket 21 mengukur 60 RPS pada 3 + 1 tanpa decision log. CPU pada 60 RPS: OPA 91% → 66%, gateway tetap ~50%; artinya ~1,9 vCPU per 100 RPS, sehingga 4 vCPU mentok di ~200 RPS secara teoretis.)*

## Keputusan
- **Validasi skema di PEP.** `mcpgw.OPA.Decide` memvalidasi input dengan skema yang sama (`policy/wantimpres26/schema`, di-embed, dikompilasi sekali).
  - Input yang valid ditanyakan ke entrypoint baru `decision.checked` tanpa `json.match_schema`.
  - Input lain tetap ke `decision.result`, yang memvalidasi di OPA dan menjawab block `INPUT_SCHEMA_INVALID`. Jadi PDP tetap fail closed, dan app `fail_open` tidak bisa lolos lewat error.
  - Pemanggil lain (simulasi, PEP lain nanti) tetap memakai `result`. OPA hanya mendengarkan `127.0.0.1`.
  - `TestInputSchemaMatchesPDP` menjaga Go dan Rego tetap sepakat (corpus + 20 mutasi), dan memastikan `checked` sama dengan `result`.
  - Kalau sidecar masih memakai bundle lama tanpa `checked` (saat rollout), `Decide` jatuh ke `result` (`TestDecideFallsBackToResult`).
- **Bundle dioptimasi saat build** (`opa build -O=1` lewat paket `compile`, entrypoint `checked`).
  - Rule set sudah diketahui saat build, jadi loop atas rule dibuka. Hemat ~17% per keputusan.
  - Rule lain (`result`, query MCP, kills) tetap ada.
  - `TestOptimizedBundleDecidesAsSource` membandingkan bundle dengan sumber untuk 289 input: 3 arah × 4 sanction × 4 sensitivitas × 6 set kelas, plus agent.
  - Level optimasi ikut di hash revisi, supaya sidecar tidak menahan bundle lama.
- **Mask decision log.** Set `lower(forbidden)` sebelumnya dibangun ulang untuk setiap field yang di-walk. Sekarang dihitung sekali per keputusan: ~1 ms → 0,36 ms per keputusan. Ini sumber terbesar turunnya CPU OPA di server.
- **Sidecar OPA** memakai `GOGC=800` dan `GOMEMLIMIT=200MiB`. Ini menurunkan p99 eval dari ~6 ms ke ~4 ms. `GOGC=off` dan `GOMAXPROCS=1` diukur dan lebih buruk.
- **Pembagian vCPU pod:** gateway 2 + OPA 2 (sebelumnya limit OPA 1). Pada beban yang sama, OPA memakai CPU sedikit lebih banyak dari gateway.
- `sort_objects` (marshal/unmarshal JSON) diganti `sort` bawaan. `r.mode` diganti `object.get`, karena type checker optimizer melihat data rule.
- **Dicoba dan dibuang:**
  - Memoize nilai field per keputusan: lebih lambat, karena memaksa field `agent.*` dihitung.
  - `value()` dengan dispatch per segmen: tidak berpengaruh.
- **Harness:** decision log diaktifkan seperti produksi. Angka tiket 21 tanpa decision log, jadi terlalu optimistis.

## Hasil verifikasi lokal (2026-10-11)
- `opa test policy/` 54/54.
- `go test -race ./...` dengan Postgres 17 dan OpenSearch 2.19.3 hijau (termasuk lifecycle, catalog, dan agents yang memakai bundle teroptimasi lewat SDK OPA).
- golangci-lint v2.5.0 0 issue. `gofmt` juga merapikan `cmd/mcp-gateway/main.go` yang tertinggal dari tiket 46.
- Data mentah: `deploy/nfr/results/opa-bench.txt`, `t47-ramp-gw2-opa2-*.json`, `t47-cpu-60rps.txt`.
- Host juga dipakai proses lain (load 2–6), sehingga latensi ramp bising. Angka CPU per request lebih stabil.

## Sisa: 300 RPS per pod butuh keputusan
Per 100 RPS, gateway memakai ~0,8 vCPU (≈ 8 ms CPU per request: L1 in-process, JSON, tokenisasi) dan OPA ~1,1 vCPU (2 keputusan × ~5,5 ms, dengan eval hanya ~2 ms; sisanya HTTP, JSON, dan decision log console). Opsi, dari yang paling berdampak:
1. **Terima ~125 RPS/pod sebagai kapasitas dan skala horizontal.** ASM-2 puncaknya 20 RPS, jadi 2 pod (HA) masih punya headroom 6×. 100× ASM-2 ≈ 17 pod. Ubah target §13.1, atau buat keputusan terima risiko.
2. **Decision log OPA ke console** menduplikasi `decision_event` yang sudah ke Kafka, dan memakan ~35% CPU OPA (diukur: 76% vs 119% pada 100 RPS). Opsinya: matikan, atau kirim batch ke collector. Ini keputusan audit (FR-POL-9).
3. **Satu keputusan untuk response bersih** (tanpa kelas atau skor). Bisa memangkas hampir setengah beban OPA, tapi mengubah semantik event response. Perlu dicek apakah ada rule `direction: response` yang bisa cocok tanpa temuan.
4. **Profil CPU gateway** (L1 detection per request). Ini di luar PDP, kandidat tiket baru.
