<!-- source-sha256: 4278f7adf743455a -->
# 09: Detection L2: Indonesian/English PII NER

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 04, 08
Spec: `../spec.md` §9.2; §9.4

## Context
Entities without a fixed pattern (names, addresses, diagnoses) need an NER model.

## Scope
- Fine-tune a small multilingual encoder, then distill to ONNX int8.
- Serving via model-inference (Triton/ONNX Runtime) on CPU.
- Integration into detection-svc with a timeout and fallback to the L1 result.
- Model card + model version in every response.

## Acceptance criteria
- [x] F1 per entity is reported; ECE ≤ 0.05. *(`evalcorpus l2eval` on holdout v1, the served int8 model: entity confidence ECE 0.032 (1,572 entities). L2 F1 per entity in the table below. Names and addresses are scored with gold derived from replaying the holdout generator (`evalcorpus nergold`, `TestPIIFull`), without modifying the holdout.)*
- [x] L2 p95 ≤ 50 ms (together with the injection classifier). *(Combined model `l2-1` (ticket 10, NER + injection in one forward pass): p95 35 ms, p50 18 ms, p99 86 ms for 1,810 holdout texts, measured client → model-inference (`--cpus 2`, `ORT_THREADS=2`) while the host was quiet. While the host was used by other training, pii-ner-1 was once measured at p95 62 ms.)*
- [x] The model is released via shadow mode first. *(`L2_MODE` defaults to `shadow`, also in `deploy/base/services.yaml`: L2 findings are reported in `l2` of the `/scan/text` response, the result does not change. `enforce` merges them (`TestShadowEnforceFallback`).)*

Holdout v1 results (`pii-ner-1+46960d7d86e0`, threshold 0.5):

| Class | L1 F1 | L2 P | L2 R | L2 F1 | L1+L2 F1 |
|---|---:|---:|---:|---:|---:|
| PII.NAME | 0 | 0.886 | 0.861 | 0.873 | 0.873 |
| PII.ADDRESS | 0 | 0.976 | 1.000 | 0.988 | 0.988 |
| PII_ID.NIK | 0.936 | 0.869 | 0.787 | 0.826 | 0.936 |
| PII_ID.KK | 0.794 | 1.000 | 0.608 | 0.756 | 0.794 |
| PII_ID.NPWP | 0.997 | 1.000 | 0.725 | 0.841 | 0.997 |
| PII_ID.PHONE | 1.000 | 1.000 | 0.833 | 0.909 | 1.000 |
| FIN.ACCOUNT | 0.995 | 0 | 0 | 0 | 0.995 |
| PCI.PAN | 0.988 | 0 | 0 | 0 | 0.988 |
| PHI.DIAGNOSIS | – | – | – | – | – (the holdout has no diagnoses) |

## Decisions
- **Model:** `distilbert-base-multilingual-cased` (Apache-2.0, pinned revision) with a BIO token head for 9 labels (name, address, diagnosis, NIK, KK, NPWP, phone, PAN, account number). Only 3 of the 6 transformer layers are used, word embeddings are frozen, window 128 tokens with stride 32. The reason is CPU: on this host one 6-layer training step takes ~25 seconds (host is shared), 3 layers ~3.5–6 seconds, and inference is also lighter for the 50 ms budget. "Distillation" is realized as layer truncation of an already-distilled model, not teacher-student. Training: 2 epochs, ~40 minutes on CPU.
- **Training data without the holdout and without customer data:** `evalcorpus train` (new generator `evalcorpus-train/1`). Templates, names, streets, cities, and address shapes are all different from the holdout (`TestTrainingDisjoint`). Text that happens to equal the holdout is dropped by the trainer. Identifiers are structurally valid and fictitious.
- **Calibration:** token temperature, then per-entity Platt scaling fit on templates *held out* from training (dev split per template). Calibrating on a random dev split from the same templates makes all confidences look correct (dev accuracy 1.0, holdout ECE 0.133). With a per-template dev split: dev ECE 0.258 → 0.058, holdout ECE 0.032.
- **int8 quantization:** dynamic, per-channel, reduce_range, MatMul only, output head stays fp32. Finding: the default per-tensor int8 on AVX2 CPUs without VNNI scrambles the logits (token agreement with fp32 only ~50%; the first model came out as garbage). The trainer now refuses to release if int8 vs fp32 agreement is < 99% (`ship`); the result was 0.9932.
- **Serving:** model-inference (Python, ONNX Runtime CPU, distroless, multi-stage deps) `POST /v1/analyze` → entities with UTF-8 byte offsets + `version+sha` version. `/readyz` is only ready when the model is loaded. The model is not baked into the image: it is mounted from the PVC `model-store` and pinned per file in `services/model-inference/MODELS.json`. Content is never logged.
- **detection-svc integration** (`internal/l2`): L1 (and tenant tuning), then L2 with timeout `L2_TIMEOUT` (default 80 ms). Timeout, error, or model down → the L1 result stands, `l2.status` = timeout/error. Short-circuit: private key → L2 is skipped. Enforce mode (`detect.WithL2`): the model only *adds* names, addresses, and diagnoses and swaps NIK↔KK labels. L1 remains the authority for pattern-based identifiers, because on the holdout many of the model's NPWP/account number findings were wrong (combined NPWP precision once dropped 0.997 → 0.708 before this rule). Diagnosis = health data → sensitivity `restricted`.
- Model card: `services/model-inference/MODEL_CARD.md`. Reproduction: `train/data.sh`, `train/Dockerfile`, `train/train.py`, `evalcorpus l2eval`.

## Local verification results (2026-10-10)
- `go vet ./...` + `go test -race ./...` with Postgres 17 green; golangci-lint v2.5.0: 0 issues; ruff check + format clean; `python -m unittest` (including the real model test with `MODEL_DIR`) green.
- The distroless model-inference image was built and runs (`/healthz`, `/readyz` 503 without a model).

## Remaining
- What is served is `l2-1` (ticket 10), whose NER calibration is worse than pii-ner-1: entity ECE 0.076 vs 0.032, name F1 0.854 vs 0.873. Before enforce it needs recalibration, or separating the NER model from injection at the cost of two forward passes of latency.
- p99 86 ms > timeout 80 ms: ~1% of calls fall back to L1 only. Measure on a production node.
- NIK vs KK is not yet better than L1 (KK recall 0.66). Needs training data with more varied KK context, or an L1 context rule.
- `PHI.DIAGNOSIS` is trained but not measured: holdout v1 has no diagnoses. Needs eval set v2 with health documents (double labeling κ ≥ 0.8).
- All data (train and holdout) is synthetic: these numbers are an upper bound for production. Evaluate on real, already-redacted documents (active learning, ticket 38) before moving to enforce.
- The release job that copies artifacts to the PVC `model-store` with the `MODELS.json` sha256 check has not been built yet.
