<!-- source-sha256: b6b43af46ecc8437 -->
# 08: Detection L1: normalization + regex + validators + secrets

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 04, 05
Spec: `../spec.md` §4.4 FR-CLS-1..4; §4.5 FR-PSEC-3; §9.1

## Context
Deterministic fast path with a budget of ≤ 10 ms. All PEPs depend on it.

## Scope
- Normalizer: NFKC, strip zero-width & Unicode tags, homoglyph map, layered decoding (base64/hex/URL/ROT13) with depth ≤ 3.
- Validators: NIK (region structure + birth date, women +40), KK, NPWP 15/16 digits, phone numbers +62/08, PAN (Luhn + BIN), bank account numbers (bank format).
- Secret detection: vendor API key patterns, PEM, JWT, connection strings + entropy.
- Output per match: `{type, confidence, span_offsets, validator_passed, context_score}` + sensitivity aggregation (FR-CLS-3).
- Endpoint `POST /scan/text` (without policy for now).

## Acceptance criteria
- [ ] Precision ≥ 0.95 and recall ≥ 0.90 on the P0 classes in eval set v1 (ticket 04). *(Eval set v1 did not exist yet. In the meantime `TestSyntheticEval`, 5,000 seeded synthetic documents (bank document templates + negatives: amounts, dates, ref/invoice numbers, "password: required" prose), enforces the per-class target: NIK, NPWP, phone, PAN, account number, AWS key, connection string all at P/R 1.000. Replace with holdout 04 once frozen.)*
- [x] p95 ≤ 10 ms for 8K-token text. *(`TestLatencyBudget`: 32 KB, p50 4.2 ms / p95 5.5 ms locally; skipped under `-race`. `BenchmarkScan8K` ±4.6 ms/op.)*
- [x] Tests for each validator: valid, invalid, and edge cases. *(`validators_test.go`: NIK (+40, 29 Feb, new Papua provinces, zero), KK, NPWP 15/16, PAN per issuer + length, phone per prefix/length.)*
- [x] Fuzz test of the normalizer/decoder. *(`FuzzScan`: offset map is consistent, spans are within the text, Redact does not panic; 60 seconds, ±550 thousand executions, clean.)*

## Decisions
- Package `internal/detect` (Go, no I/O); `detection-svc` exposes `POST /scan/text` (≤ 256 KB, 413 if larger) without policy. Response: `sensitivity`, `classes[{type,count,confidence}]` (the shape of the PDP input `content.classes`), `matches[{type, confidence, span_offsets, validator_passed, context_score, encoding}]`. The matched value is never returned or logged; `span_offsets` = UTF-8 bytes of the original text.
- NFKC normalization per segment with a per-byte offset map back to the original text, so detection runs on normalized text but redaction (`detect.Redact`) hits the original bytes (fullwidth, zero-width, and homoglyphs are removed too). Zero-width/bidi/variation selectors are dropped; Cyrillic/Greek homoglyphs and Arabic-Indic/Devanagari/Bengali/Thai digits are folded to ASCII.
- Layered decoding ≤ 3: base64 (std/url, padded/raw), hex, URL (`%XX`), plus ROT13 (secrets only, since ROT13 does not change digits) and Unicode tag characters (ASCII smuggling, decoded rather than just dropped). The decoded result must be ≥ 90% printable; a match inside a blob reports the span of the whole blob and the `encoding` (e.g. `base64/url`).
- Numbers: a single digit-run scanner (space/dot/dash separators), the longest group window with the highest confidence, so "NIK … 0812…" still yields two findings. Without context: NIK 0.85, PAN (Luhn + BIN + issuer length) 0.90, phone 0.90 (+62: 0.95), dotted-format NPWP 0.95. With a keyword within ±48 bytes: 0.95–0.99. KK, plain 15-digit NPWP, and account numbers require context. The bank name only pins the account number length (BCA/BNI/BSI 10, Mandiri 13, BRI 15), not the context, because the bank name appears in every bank document. The labels "ref/invoice/order/trx/resi" (tracking number) discard numbers that have no positive context.
- Secrets: vendor patterns (AWS, GitHub, GitLab, Slack, Google, OpenAI/Anthropic, Stripe), PEM private key, JWT (header must be JSON with `alg`), URL and ADO connection strings (password required), `password=` (not a placeholder, ≥ 2 character classes), and `api_key/secret/token=` with entropy ≥ 3.5 bits/character. Digits inside a secret are not reported as PII.
- Reporting threshold 0.8 (`detect.Threshold`). Sensitivity (FR-CLS-3): SECRET → `restricted`; PII/PCI/FIN → `confidential`; ≥ 10 distinct values of one type → `restricted`; no findings → `internal` (corporate content; `public` only via an external label, FR-CLS-6).
- Go regex (NFA) over the whole text turned out to be 10× over budget (p95 98 ms). Secret rules are now anchored (one pass over a first-byte table, then an `^` regex in a window of ≤ 8 KB), while digit runs and blob candidates are scanned manually.

## Local verification results (2026-10-03)
- `go test -race ./...` green; golangci-lint 0 issues; 60-second fuzz clean; the `detection-svc` image builds and `POST /scan/text` was smoke-tested (fullwidth NIK, BCA account number, AWS key inside base64).

## Remaining / follow-up
- Eval holdout v1 (ticket 04) for the real precision/recall AC.
- Other FR-CLS-1 classes (passport, CIF, BPJS/ICD-10, address/name) need a dictionary/NER: ticket 09.
- Other banks' account number formats (including Bank Mega) will be added to `accountLengths` once the formats are confirmed.
- `POST /scan/text` is not yet authenticated; it relies on cluster network isolation. Add NetworkPolicy/mTLS when the first PEP calls it (ticket 28).
