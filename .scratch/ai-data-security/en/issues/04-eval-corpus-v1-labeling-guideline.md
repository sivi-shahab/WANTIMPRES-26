<!-- source-sha256: 3a84ded38601fba2 -->
# 04: Eval corpus v1 & labeling guideline

Status: needs-signoff
Type: task
Priority: P0
Milestone: M0
Spec: `../spec.md` §9.3; §9.4

## Context
All detectors need a frozen eval set to gate model releases (§9.4).

## Scope
- Synthetic Indonesian PII generator: NIK (national ID number), KK (family card number), NPWP (tax ID), bank account numbers, phone numbers, and PAN (structurally valid, fictitious), inserted into bank document templates.
- Prompt injection/jailbreak corpus: direct, indirect (HTML/PDF/email), encoded, multilingual ID/EN, and GCG-style suffix, from openly licensed datasets + self-made.
- Enterprise-style benign corpus to measure FPR.
- Labeling guideline per class, double labeling, and target κ ≥ 0.8.
- Provenance of each dataset: source, license, version, hash.

## Acceptance criteria
- [x] Eval set holdout v1 is frozen and hashed. *(`data/eval/v1/`: 640 synthetic PII, 447 synthetic injection, 607 synthetic benign, 116 public samples (deepset/prompt-injections test, Apache-2.0, revision `4f61ecb`). `MANIFEST.json` records the source, license, revision/seed, and sha256 per file. `evalcorpus.Load` rejects changed files; `TestHoldoutFrozen` verifies that the synthetic files are identical to the output of the recorded generator+seed.)*
- [ ] Inter-annotator agreement report ≥ 0.8. *(The tool and process are ready: `evalcorpus sheet` (blind sheet), `evalcorpus kappa` (Cohen's κ per question, fails < 0.8), guideline `docs/labeling-guideline.md`. Waiting for two annotators from the bank; the result is stored in `data/eval/v1/AGREEMENT.md`.)*
- [x] No real customer data in the corpus. *(NIK/KK/NPWP/phone/account numbers = random digits that are structurally valid; cards = official card network test numbers (checked by test); names = combinations of common names. `TestPublicSetHasNoPII`: the public set has no sensitive data findings.)*

## Decisions
- **Deterministic Go generator** (`internal/evalcorpus`, `GeneratorVersion` + seed): ID/EN bank document templates (power of attorney, account opening form, CS chat, transfer summary, customer profile, etc.) with a byte span per entity; reference/invoice numbers prefixed with `00` serve as hard negatives whose labels are unambiguous. Attacks per technique (direct, roleplay, role confusion, indirect HTML/email/PDF/tool result, exfil markdown, 6 kinds of encoding, Javanese/Sundanese/mixed, GCG-style suffix), inserted into ordinary requests. Enterprise benign + 209 hard negatives (discussing injection, "ignore the previous email", notes for the team, internal markdown images).
- **Dev set** is created with a different seed (`evalcorpus freeze -dir <dir> -seed N`), not committed. Holdout v1 must not be used for tuning.
- **Runner** `evalcorpus score`: precision/recall/F1 per class (span level), benign FPR, detection rate per technique. The `Detector` shape is the same as `detect.Scan`, so L2 (09, 10) only needs to be wrapped.

## L1 detection baseline on holdout v1
Sensitive data: PHONE F1 1.00; NPWP 0.997; ACCOUNT 0.995; PAN 0.988; NIK 0.936 (precision 0.888); **KK recall 0.658**. Benign with PII findings: 0%. The NIK FPs and KK FNs come from the same cases: KK numbers (structure identical to NIK) are reported as NIK. This is input for ticket 09 (context/NER).

Injection at threshold 0.8 (risk floor): direct 88%, all encodings 100%, role confusion 35%, multilingual 18%, public 10%, while indirect, exfil, roleplay, and GCG are 0%. At threshold 0.6: indirect and role confusion 100%, exfil 76%. Benign FPR 0.30% (0.8) / 0.45% (0.6); on hard negatives 1.0% / 1.4%.

**Known bias:** the synthetic attack templates were written with knowledge of the L1 rules, so the indirect/encoding/role confusion numbers are too optimistic for L1. The public set number (10%) and the fresh red team set are the honest measures; the L2 classifier (ticket 10) must be judged mainly on those. The public set is in English/German, so ID/mixed still needs additional open sources.

## Remaining
- Double labeling by two bank annotators, adjudication, and `AGREEMENT.md` (κ ≥ 0.8).
- Additional Indonesian-language public datasets (none with a clear license found yet) and a monthly fresh attacks set from the red team.
