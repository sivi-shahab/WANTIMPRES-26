<!-- source-sha256: f7d98d4f42a6d7bc -->
# 38: Per-tenant custom classifier & active learning

Status: needs-gitlab-run
Type: task
Priority: P2
Milestone: M4
Blocked by: 09, 10, 25 (dikerjakan lebih dulu atas permintaan; model untuk 09/10 menyusul)
Spec: `../spec.md` §9.3 isolasi; §9.4

## Context
Tuning detectors to the bank's needs without leaking data.

## Scope
- Active learning queue from triage feedback (redacted).
- Per-tenant fine-tuning with explicit opt-in, inside the tenant boundary.
- §9.4 model release gate + shadow → canary → 100% rollout.

## Acceptance criteria
- [x] A tenant model cannot be accessed across tenants (isolation test). *(`TestIsolationAndRollout`, two tenants in one DB: tenant B does not see A's events in the queue, cannot label A's events, cannot train with A's labels, does not see and cannot promote A's model, and A's model does not apply in tenant B's detection. Feature hashes are keyed with the tenant pepper: A's model under B's key loses its effect (`TestModelGate`).)*
- [x] No F1/FPR regression beyond the gate thresholds. *(The §9.4 gate runs on every training against a holdout frozen per quarter, compared with the active model or the detector as is: F1 must not drop > 1 point, FPR must not rise > 0.2 points, plus recall ≥ 0.98 (our addition: the model must not hide real findings). Synthetic data (QA test cards in Jira = FP, customer cards in ChatGPT = TP, 3% label noise): FPR 1.00 → 0.13, F1 0.66 → 0.94, recall 1.00. Retraining from corrupted labels has status `rejected` and cannot be promoted.)*

## Decisions
- **Model:** the ticket 09/10 models do not exist yet, so this custom classifier is a per-tenant logistic regression on top of the L1 detectors. The model predicts whether a finding of class X is real, and classes judged FP are dropped (`detect.Without`) before going to the PDP. Features: words and bigrams of the redacted snippet (crossed with the class), channel, direction, app, and confidence bucket; hashed with HMAC using the tenant pepper. Conservative threshold: ≥ 99% of TPs in the training data still pass, maximum 0.5.
- **Training data is only what is already in the event:** redacted snippets ≤ 200 characters and metadata. No raw content. `detect.Snippet` is the only snippet builder, for both PEP events and inference (detection-svc now returns `snippet`), so there is no train/serve skew.
- **Labels** (`POST /tuning/labels`, SOC `incident.write`): TP/FP per class per incident event owned by the tenant. **Active learning queue** (`GET /tuning/queue`): unlabeled findings, ordered by the live model's uncertainty (|p − threshold|), or by the distance of the detector's confidence from 0.8 if there is no model yet. This also provides the TP/FP label pipeline for ticket 25.
- **Explicit opt-in** (`PUT /tuning/optin`, DPO `compliance.write`, reason required, append-only). Without opt-in, training is rejected.
- **Training** (`POST /tuning/models`, `policy.write`): minimum 40 labels with ≥ 5 TP and FP in both train and holdout. The split per event uses HMAC (20% holdout). The **holdout is frozen per quarter** at the first training of that quarter (`tuning.holdout`, append-only). Finding during implementation: without freezing, holdout labels that are also corrupted let a broken model pass the gate.
- **Rollout** (`POST /tuning/models/{v}/stage`, `policy.publish`, 4-eyes against the trainer): candidate → shadow (only scores are reported) → canary (5% of texts, stable per text; the rest use the active model or detector) → active (the old active model is retired). Rollback = retired. All steps are audited.
- Serving: detection-svc loads the shadow/canary/active model and reloads when the stage changes (≤ 60 seconds). The response includes `tuning` (version, stage, score per class, suppressed classes, shadow report).

## Local verification results (2026-10-10)
- `go test -race ./...` with Postgres green (including `mcpgw` in this run). `datascan TestScan` once failed randomly because the leak check used `LIKE '%4111%'`, which can match a UUID or hash. Fixed to the full card number. golangci-lint 0 issues.

## Remaining
- Fine-tune per-tenant NER/injection models once tickets 09/10 have models (using the same queue, opt-in, frozen holdout, gate, and rollout).
- Eval on real bank data; double labeling κ ≥ 0.8 (§9.3) for labels that enter the holdout. Freezing protects the current quarter, but not labels that were already wrong before freezing.
- Shadow/canary metrics dashboard (the event stores the `tuning` report after the PEP fills it in).
- Postgres RLS for the tuning tables (isolation currently via a `tenant_id` filter in every query, same as other modules).
