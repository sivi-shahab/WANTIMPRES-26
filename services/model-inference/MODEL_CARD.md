# Model card: L2 detection (tickets 09-10)

One model per release, served by model-inference on CPU (ONNX Runtime, int8) and called by detection-svc under a
hard timeout with L1 as fallback. Version and artifact hash ship in every response (`l2.model`, e.g.
`pii-ner-1+3f2a…`). Pinned artifacts: `MODELS.json`.

## l2-1 (ticket 10): NER + prompt injection, one forward pass (served)

| | |
|---|---|
| Tasks | the pii-ner-1 token head, retrained jointly, plus a sequence head: P(injection) and attack types `direct`, `indirect`, `role_confusion`, `exfil_markdown`, `suffix` |
| Base | as pii-ner-1 (3 layers, frozen word embeddings) |
| Injection score | Platt scaling over [sequence logit, character-trigram perplexity of the last 8 KB] fitted on a dev split; the perplexity feature is the FR-PSEC-4 suffix signal |
| Views | detection-svc sends the normalized text and every decoded layer (base64, hex, URL, Unicode tags) besides the original; the worst view counts (FR-PSEC-3) |
| Untrusted content | `trust=untrusted` (RAG, tool results, e-mail, web) scores max(P(injection), P(indirect type)) (FR-PSEC-2) |
| Attack types | raw sigmoids, reported ≥ 0.5; not calibrated |
| Training data | train.jsonl (synthetic, train-only templates and attack phrasings; GCG suffix vocabulary disjoint from the holdout) + public sets with permissive licences, train splits only (MODELS.json) |
| Quantization | as pii-ner-1; token agreement measured on texts with NER supervision (0.9931), attack decision 1.0 |

Limitations
- Benign FPR on the holdout is above the 1% target at every policy threshold (1.36% at 0.9, 3.9% at 0.5), and the
  score's ECE is 0.090: the public training sets do not look like bank prompts.
- Weak on roleplay/persona jailbreaks and URL-encoded or tag-smuggled payloads when L1 does not decode them first.
- Joint training costs NER calibration: entity ECE 0.076 (pii-ner-1 alone: 0.032).

## pii-ner-1 (ticket 09)

| | |
|---|---|
| Task | Token classification (BIO) for personal data in Indonesian and English text |
| Labels | `PII.NAME`, `PII.ADDRESS`, `PHI.DIAGNOSIS`, `PII_ID.NIK`, `PII_ID.KK`, `PII_ID.NPWP`, `PII_ID.PHONE`, `PCI.PAN`, `FIN.ACCOUNT` |
| Base | `distilbert/distilbert-base-multilingual-cased` @ `45c032ab`, Apache-2.0; first 3 of 6 transformer layers, word embeddings frozen |
| Input | 128-token windows, stride 32, at most 16 windows per text |
| Output | spans (UTF-8 byte offsets) + calibrated confidence: token temperature, then entity-level Platt scaling fitted on templates held out of training; spans below 0.5 are not reported |
| Quantization | int8 dynamic, per-channel, reduced range, MatMul only, output heads fp32; shipped only if int8 agrees with fp32 on ≥ 99% of token labels (0.9932) |
| Training data | `evalcorpus train -seed 7` only: train-only templates, names, streets, cities (none shared with the holdout, `TestTrainingDisjoint`); identifiers structurally valid and fictitious, cards are published test numbers. No customer data. |
| Evaluation | Holdout `data/eval/v1` (never trained on), names and addresses labelled by replaying its generator (`evalcorpus nergold`) |
| Rollout | shadow (`L2_MODE=shadow`, default) → enforce after the §9.4 gate |

Results: see the ticket file (`.scratch/ai-data-security/issues/09-*.md`), reproduced by `evalcorpus l2eval`.

Limitations
- Trained on synthetic templates only: real documents (scans, long letters, mixed layouts) are out of distribution; the
  holdout is synthetic too, so its scores are an upper bound for production.
- `PHI.DIAGNOSIS` has no holdout gold (the frozen set has no diagnoses): reported, not measured.
- 3-layer encoder chosen for the CPU budget, not for accuracy.
- NIK versus KK: the model does not separate them better than L1's context words (KK F1 0.794 either way).
- Name spans sometimes run past a line break into the next label ("Rizky Halim\nNational ID").
- Merging (detection-svc, enforce mode): the model only adds names, addresses and diagnoses and relabels NIK/KK;
  L1 stays the authority for identifiers with a validator (the model's own NPWP/account findings were mostly wrong).

## Reproduce

```sh
sh services/model-inference/train/data.sh                       # Go: training data + holdout NER gold
docker build -t wantimpres26-train -f services/model-inference/train/Dockerfile services/model-inference
python3 services/model-inference/train/fetch_public.py                 # l2-1 only: public sets, pinned and hashed
docker run --rm -v $PWD:/repo -w /repo/services/model-inference/train wantimpres26-train \
  python train.py --tasks ner,injection --epochs 1 --version l2-1 --out /repo/services/model-inference/models/l2
# (pii-ner-1: --tasks ner --epochs 2). A refused int8 build is retried without retraining: train.py --requantize
docker run -d -p 8080:8080 -e MODEL_DIR=/m -v $PWD/services/model-inference/models/l2:/m:ro model-inference
go run ./cmd/evalcorpus l2eval -dir data/eval/v1 -url http://localhost:8080 -threshold 0.5
```
