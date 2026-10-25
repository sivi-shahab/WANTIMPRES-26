<!-- source-sha256: e2792f5c7b6c5f6e -->
# 10: Detection L2: prompt-injection & jailbreak classifier v1

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 04, 08
Spec: `../spec.md` §4.5 FR-PSEC-1..6, FR-PSEC-10; §9.2; §9.4

## Context
Detecting LLM attacks is beyond what regex can do.

## Scope
- Binary classifier + multi-label attack type (direct, indirect, role confusion, exfil markdown, suffix).
- Perplexity feature for adversarial suffixes.
- Input labeled `trust=untrusted` is treated separately.
- Detection of fake role markers and markdown links/images to external domains (companion L1 rule).
- Output `injection_score`, `attack_type[]`, redacted evidence.

## Acceptance criteria
- [ ] Benign FPR ≤ 1% on the benign corpus. *(Not yet. Holdout v1, 663 benign texts, model `l2-1` alone: 3.92% at threshold 0.5 (session taint), 2.87% at 0.7 (block untrusted), 1.36% at 0.9 (block). L1 alone 0.45% / 0.30% / 0%. Thresholds were not tuned on the holdout.)*
- [x] Detection rate per technique is reported (encoding, multilingual, indirect, suffix). *(Table below: `evalcorpus l2eval` per technique for L1, L2, and L1+L2 at each policy threshold.)*
- [ ] Calibration ECE ≤ 0.05. *(Not yet: injection score ECE on the holdout is 0.090. Platt was fit on the dev split, not the holdout.)*

Holdout v1, threshold 0.5 (detection rate):

| Technique | n | L1 | L2 | L1+L2 |
|---|---:|---:|---:|---:|
| direct | 77 | 88.3% | 75.3% | 92.2% |
| roleplay | 34 | 0% | 52.9% | 52.9% |
| multilingual (jv/su/mixed) | 22 | 18.2% | 72.7% | 81.8% |
| encoded (base64/hex/url/homoglyph/zero-width/tags) | 123 | 100% | 47–92% | 100% |
| indirect (html/email/pdf/tool) | 84 | 100% | 52.9–100% | 100% |
| role_confusion | 37 | 100% | 97.3% | 100% |
| exfil_markdown | 45 | 100% | 62.2% | 100% |
| gcg_suffix | 25 | 0% | 100% | 100% |
| public (deepset test) | 60 | 10.0% | 68.3% | 70.0% |
| **all** | 507 | 72.4% | 75.5% | 91.3% |
| benign FPR / hard negative | 663 / 209 | 0.45% / 1.4% | 3.92% / 5.7% | 4.22% / 6.7% |

Threshold 0.9 (block): all L1 15.6%, L2 55.0%, L1+L2 60.2%; FPR 0% / 1.36% / 1.36%. Threshold 0.7: 52.1% / 69.8% / 83.2%; FPR 0.30% / 2.87% / 3.02%. L2 attack type correct (the expected type is in `types`): 42.7% of 447. L2 latency (NER + injection, one forward pass, client → model-inference, `--cpus 2`): p50 18 ms, **p95 35 ms**, p99 86 ms (1,810 calls).

## Decisions
- **One model for 09 and 10** (`l2-1`): the same encoder as pii-ner-1, plus a sequence head (P(injection) + 5 attack types), trained jointly. One forward pass for two tasks gives a combined p95 of 35 ms (budget 50 ms).
- **Training data, without the holdout:** synthetic data with attack phrases, goals, leads, and GCG suffix vocabulary that differ from the holdout (`TestTrainingDisjoint`), plus permissively licensed public sets, train split only: deepset/prompt-injections (Apache-2.0; its test split is in the holdout), jackhhao/jailbreak-classification (Apache-2.0), SPML (MIT), and alpaca-id-cleaned (CC-BY-4.0) as Indonesian-language benign. Revisions and sha256 are recorded in `MODELS.json` (`train/fetch_public.py`). Text identical to the holdout is dropped.
- **Perplexity (FR-PSEC-4):** a character trigram LM over benign training text. Score = the 48-character window that is the most "not language" within the last 8 KB. Platt combines [logit, perplexity]. The holdout GCG suffixes (vocabulary never seen) are detected 100%, L1 0%.
- **Encoding (FR-PSEC-3):** the model cannot read base64. detection-svc sends `views` (the normalized text and every decode layer, `detect.Views`) and the worst-scoring view counts.
- **`trust=untrusted` (FR-PSEC-2):** passed from `context.trust` in `/scan/text`. For untrusted content, score = max(P(injection), P(indirect type)), because instructions for the AI inside data are the attack. Each piece of content is scored on its own, not merged with the user prompt.
- **Attack types** = raw sigmoid ≥ 0.5. A per-type temperature fit on dev (perfectly separated) fell to the lower bound of the grid and made every type 0/1 in the first build, so it was dropped.
- **Companion L1 rule:** a plain markdown link (not an image) whose query is a placeholder (`UPPER_SNAKE` or `{template}`) = `exfil_link` 0.6. Links with real query values remain safe. Fake role markers already exist in L1 (ticket 08).
- **Merging in detection-svc** (enforce): injection score = max(L1, L2), type = union (prefix `l2:`). Shadow remains the default.
- The int8 gate now measures token agreement only on texts that have NER supervision. On attack texts the token head is not trained, so near-ties there are meaningless. The result: token 0.9931, attack decision 1.0.

## Local verification results (2026-10-10)
- `go vet ./...` + `go test -race ./...` with Postgres 17 green; golangci-lint v2.5.0: 0 issues; ruff check + format clean; `python -m unittest` (with model `l2-1`) green.

## Remaining
- **FPR > 1% and ECE 0.090.** The public sets do not resemble bank prompts. Synthetic hard negatives show an FPR of 5.7% at 0.5. Next steps: more diverse Indonesian-language enterprise benign data (internal prompts already redacted via the ticket 38 queue), calibration on a production-like set, and policy thresholds/operating points chosen on a validation set, not the holdout. Until that is met, L2 stays in shadow. In enforce, merging max(L1, L2) at threshold 0.5 would raise FPR from 0.45% to 4.22%.
- Weak on roleplay/persona (53%) and URL/tag encoding without L1 decoding. Attack type is only 43% correct.
- Together these degrade NER calibration (entity ECE 0.076 vs 0.032 on pii-ner-1). The §9.4 release gate needs ECE per head before enforce.
- The AgentDojo e-banking scenarios and the monthly "fresh attacks" set are not yet in the eval.
