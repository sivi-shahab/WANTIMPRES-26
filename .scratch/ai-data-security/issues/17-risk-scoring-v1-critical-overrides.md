# 17: Risk scoring v1 + critical overrides

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 11
Spec: `../spec.md` §4.9 FR-RISK-1..4

## Konteks
Severity incident dan sebagian policy bergantung pada skor risiko.

## Scope
- Implementasi rumus berbobot (f_sens, f_dest, f_attack, f_agency, f_volume, f_ident).
- Critical overrides FR-RISK-2.
- Bobot dan override berversi, dapat disimulasikan seperti policy.
- Skor agregat per user/app/agent dengan half-life 14 hari.

## Acceptance criteria
- [x] Test tabel untuk setiap faktor dan setiap override. *(`policy/wantimpres26/risk/risk_test.rego`: setiap nilai level per faktor, setiap override + near miss-nya, set vs floor.)*
- [x] Skor selalu dalam 0–100 (property test). *(`TestRiskScoreAlwaysInRange`: 500 input valid acak lewat query PDP; mutation check: level negatif tertangkap.)*
- [x] Versi bobot tercatat di setiap event. *(Output PDP selalu memuat `risk_version`, juga untuk input tidak valid; event membawa output PDP.)*

## Keputusan
- Skor dihitung di PDP (`policy/wantimpres26/risk`), bukan oleh PEP: satu implementasi untuk semua PEP, ikut bundle bertanda tangan, ikut simulasi policy (ticket 12). `risk_score` dihapus dari input; output menambah `risk_score`, `risk_overrides`, `risk_version`. Rule policy bisa memakai field `risk_score`.
- Bobot, level faktor, skor dan ambang override = data (`policy/wantimpres26/risk/config/data.json`, `risk-1`). Kondisi override FR-RISK-2 = Rego statis (generik data-driven ~3× lebih lambat).
- Field input baru (opsional): `content.jailbreak_score`, `exfil_score`, `volume_ratio` (vs baseline principal), `agent.action`, `agent.registered` (tidak dikirim = tidak terdaftar), `agent.session_injection_max`.
- Interpretasi spec: `f_sens` = level sensitivity saja (volume sudah di `f_volume`); `f_volume` bertingkat 2/4/8/16× baseline (Rego tidak punya log); `f_dest` = max(sanction, personal account → 1); `f_ident` = max(device, account, principal.risk); `under_review` dihitung seperti `unsanctioned`. Nilai device/account adalah tebakan awal, dikalibrasi di ticket 25.
- Input tidak valid → `risk_score` 0 (bug PEP, bukan risiko user; sudah ada `INPUT_SCHEMA_INVALID`).
- Agregat FR-RISK-4: `internal/risk.Agg`, mean berbobot 2^(-umur/14 hari), O(1) per event, benar untuk event yang terlambat. Dipakai consumer event (ticket 15/20).
- Builder bundle menolak publish bila `risk.config_errors` tidak kosong (Σw ≠ 1, level di luar [0,1], skor override di luar [0,100]).

## Hasil verifikasi lokal (2026-10-03)
- `opa test` 34/34, `opa check --strict`, `go test -race`, golangci-lint: lulus.
- Latensi: risk menambah kerja PDP. Ukuran di laptop ini terlalu bising (baseline sendiri 1,8–3,3 ms mean antar run); A/B berselang-seling: +0–80% mean eval. Target p99 5 ms (ticket 11) makin perlu diukur di hardware target (ticket 21).

## Sisa / follow-up
- PEP harus mengisi field baru (ticket 13, 28); `session_injection_max` butuh state sesi (Redis, mcp-gateway).
- Kalibrasi kuartalan dengan label SOC (ticket 25).
