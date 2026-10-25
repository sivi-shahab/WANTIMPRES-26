<!-- source-sha256: 262de0a71f39bb2d -->
# 25: Risk scoring calibration with SOC triage labels

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M2
Blocked by: 17, 18
Spec: `../spec.md` §4.9 FR-RISK-3

## Context
The initial weights need to be calibrated with real data.

## Scope
- TP/FP label pipeline from triage.
- Quarterly weight calibration analysis + simulation of the new weights version.
- Report on changes in the severity distribution.

## Acceptance criteria
- [x] A new weights version only becomes active after simulation and approval. *(`TestCalibration`: submit without simulation is rejected (`ErrState`), approval by the author is rejected (`ErrFourEyes`), approval by someone else activates the version and cuts a policy release in a single transaction. The decision then carries `risk_version = risk-cal-1`, and the next release from other modules still carries those weights.)*

## Decisions
- **Labels** (`riskcal.Labels`): a verdict per incident resolved within the window. Ever `Contained` = TP; `Investigating → Resolved` without containment = FP. An analyst's per-event class label (`tuning.labels`, ticket 38) overrides the incident verdict for that event.
- **Quarterly fit** (`POST /risk/versions {"propose": true}`, `policy.write`): logistic regression of the verdict against the six factors from `data.wantimpres26.risk` on the last 3 months of labels. Minimum 60 verdicts with ≥ 20 per class, otherwise `400`. A factor that is constant across all labels keeps its weight. The other factors are shifted halfway (`Shrink = 0.5`) toward the fit result, keeping their total mass. Weights are rounded to 2 decimals and still sum to 1. The fit basis (verdict count, coefficients, old weights, window) is stored in the version.
- **Manual config** (`{"config": {...}}`) is also possible. A config rejected by `risk.config_errors` never becomes a version.
- **Simulation** (`POST /risk/versions/{v}/simulate`): replays this quarter's labels plus the last 30 days of decision events (`search.Events`) under the current config and the candidate. The report contains the severity distribution, TP/FP per band, mean TP vs FP score, the number of events that moved up/down a band, and the number of events ≥ `incident.MinRisk`. The report is stored in the version for the approver to read.
- **State**: draft → simulated → pending_approval → active (the old one → retired). Reject → draft. Approve/reject use `policy.publish` (step-up + justification) with 4-eyes against the author. All steps are audited. One active version per tenant (unique index).
- The active version is included in every policy release via `lifecycle.AddExtra`, registered before other modules cut a release.

## Local verification results (2026-10-10)
- `go vet ./...` + `go test -race ./...` with Postgres 17 green. Synthetic data (50 TP = data to unsanctioned AI, 41 FP = injection-like text to a sanctioned assistant): mean TP/FP score 36.4/25.5 → 43.5/13.6. 17 events moved up a band, 0 down.

## Remaining
- No automatic quarterly scheduler yet: propose is triggered manually via the API (cron/CI can call the same endpoint).
- Calibration of the severity thresholds (`levels`) is not fitted yet, only the weights. They can be changed via manual config.
- Evaluation on the bank's real triage data after M2 has run for one quarter.
