<!-- source-sha256: 99ff489bea21898f -->
# 17: Risk scoring v1 + critical overrides

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 11
Spec: `../spec.md` §4.9 FR-RISK-1..4

## Context
Incident severity and some policies depend on the risk score.

## Scope
- Implementation of the weighted formula (f_sens, f_dest, f_attack, f_agency, f_volume, f_ident).
- Critical overrides FR-RISK-2.
- Weights and overrides are versioned and can be simulated like policy.
- Aggregate score per user/app/agent with a 14-day half-life.

## Acceptance criteria
- [x] Table tests for every factor and every override. *(`policy/wantimpres26/risk/risk_test.rego`: every level value per factor, every override + its near miss, set vs floor.)*
- [x] Score is always within 0–100 (property test). *(`TestRiskScoreAlwaysInRange`: 500 random valid inputs through the PDP query; mutation check: a negative level is caught.)*
- [x] Weights version is recorded in every event. *(PDP output always contains `risk_version`, also for invalid input; events carry the PDP output.)*

## Decisions
- The score is computed in the PDP (`policy/wantimpres26/risk`), not by the PEP: one implementation for all PEPs, shipped in the signed bundle, included in policy simulation (ticket 12). `risk_score` is removed from the input; the output adds `risk_score`, `risk_overrides`, `risk_version`. Policy rules can use the `risk_score` field.
- Weights, factor levels, scores, and override thresholds = data (`policy/wantimpres26/risk/config/data.json`, `risk-1`). The FR-RISK-2 override conditions = static Rego (generic data-driven is ~3× slower).
- New (optional) input fields: `content.jailbreak_score`, `exfil_score`, `volume_ratio` (vs principal baseline), `agent.action`, `agent.registered` (not sent = not registered), `agent.session_injection_max`.
- Spec interpretation: `f_sens` = sensitivity level only (volume is already in `f_volume`); `f_volume` is tiered at 2/4/8/16× baseline (Rego has no log); `f_dest` = max(sanction, personal account → 1); `f_ident` = max(device, account, principal.risk); `under_review` is counted like `unsanctioned`. The device/account values are initial guesses, calibrated in ticket 25.
- Invalid input → `risk_score` 0 (a PEP bug, not user risk; `INPUT_SCHEMA_INVALID` already exists).
- FR-RISK-4 aggregate: `internal/risk.Agg`, mean weighted by 2^(-age/14 days), O(1) per event, correct for late events. Used by the event consumer (ticket 15/20).
- The bundle builder refuses to publish if `risk.config_errors` is not empty (Σw ≠ 1, level outside [0,1], override score outside [0,100]).

## Local verification results (2026-10-03)
- `opa test` 34/34, `opa check --strict`, `go test -race`, golangci-lint: pass.
- Latency: risk adds PDP work. Measurements on this laptop are too noisy (the baseline itself varies 1.8–3.3 ms mean between runs); alternating A/B: +0–80% mean eval. The p99 5 ms target (ticket 11) increasingly needs to be measured on the target hardware (ticket 21).

## Remaining / follow-up
- PEPs must fill in the new fields (ticket 13, 28); `session_injection_max` needs session state (Redis, mcp-gateway).
- Quarterly calibration with SOC labels (ticket 25).
