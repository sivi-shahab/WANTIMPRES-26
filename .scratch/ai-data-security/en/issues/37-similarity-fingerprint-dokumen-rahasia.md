<!-- source-sha256: 712d2d412902dc82 -->
# 37: Similarity & fingerprinting of confidential documents

Status: needs-gitlab-run
Type: task
Priority: P2
Milestone: M4
Blocked by: 08
Spec: `../spec.md` §4.4 Source Code/IP; §9.1 L3; §9.2

## Context
Detecting leaks of IP/confidential documents that have no pattern.

## Scope
- Confidential corpus registration; MinHash/SimHash near-dup + sentence embedding.
- Async path for files and optionally inline for short text.

## Acceptance criteria
- [x] Precision/recall on a synthetic confidential-document eval set. *(`TestEval`: 200 registered documents + 200 unregistered ones from the same generator, with the same bank-letter boilerplate (false positive trap). Recall 1.000 for whole documents, verbatim excerpts of 40 and 150 words inside a prompt, 80-word excerpts that were reformatted (uppercase, punctuation, newlines), and 120-word excerpts with 1 of 12 words replaced. Editing 1 of 6 words (outside the guarantee): recall 0.90. Overall precision 0.9992, i.e. 1 false positive out of 1,700 negatives (including 500 prompts that only share boilerplate). Paraphrase is not detected, see Remaining.)*
- [x] Inline stays within the latency budget. *(`TestLatency`: 6k-word text (~8K tokens) against 1,000 registered documents: p50 5–7 ms, p95 11–17 ms on a machine with load 8; assertion p95 ≤ 20 ms, within the L2 budget of 50 ms and the gateway overhead of 80 ms.)*

## Decisions
- **Winnowing, not MinHash/SimHash** (`internal/similarity`). A leak is usually a piece of a document inside a prompt. MinHash/SimHash measure whole-document similarity, so a short piece inside long text slips through. Winnowing (Schleimer et al., SIGMOD 2003) over 5-word shingles with window 4 **guarantees** that every verbatim run of ≥ 8 words produces a shared fingerprint, regardless of the length of the surrounding text (`TestWinnowGuarantee`). Words are lowercased and punctuation/whitespace are ignored.
- **Hit rule:** at least 3 shared fingerprints within 16 consecutive fingerprints (~40 words), meaning one passage of ~15+ words was copied. Coincidental collisions between unrelated texts are scattered one at a time and do not form clusters (in the eval, this rule lowered whole-document FPs from 4/200 to 1/200). Fingerprints that appear in ≥ 3 registered documents are treated as templates (letterhead, standard clauses) and ignored.
- **Privacy:** only HMAC'd fingerprints (tenant pepper) are stored, the text is discarded after fingerprinting; dedupe via content HMAC. Without the pepper, the fingerprint set cannot be matched against guessed text.
- **Output:** class `CODE.CONFIDENTIAL_DOC` (count = number of documents), matches with spans (usable by `Redact`; up to 3 words at the edge of a passage may not be covered), sensitivity raised to the document's sensitivity (`confidential`/`restricted`). Confidence = 0.8 + 0.2 × containment.
- **Registration** (control-plane, `policy.write` = DLP analyst): `POST /similarity/docs?name=&sensitivity=` (body = file; format per `internal/extract`, PDF needs `TIKA_URL`), `GET /similarity/docs` (`policy.read`), `DELETE /similarity/docs/{id}`. Register/unregister are audited in the same transaction.
- **Inline path:** `detection-svc POST /scan/text` adds hits to the L1 result plus `similar[]` (document id/name, shared, containment, coverage). Optional: without `DATABASE_URL` only L1.
- **Async file path:** data-at-rest scan (`datascan`, tickets 31–33), so copies of confidential documents in OneDrive/Drive/buckets are also classified and enter the exposure score.
- The index is in memory per replica, reloaded ≤ 60 seconds after the corpus changes; a failed reload keeps the old index.

## Local verification results (2026-10-10)
- `go test -race ./...` with Postgres: all green **except `internal/mcpgw` `TestKillSwitch`** (session cut at 2.9 s, limit 2 s). It also fails at HEAD before this ticket and mcpgw does not touch the changed packages: a pre-existing problem, needs to be checked separately. golangci-lint 0 issues.

## Remaining
- **Embedding similarity for paraphrase**: waiting for a self-hosted model in `model-inference` (tickets 09/10 have no model yet; DEC-4 forbids external APIs).
- `POST /scan/file` (§8.2) does not exist yet; files to AI apps are only covered in data-at-rest for now.
- The MCP gateway (tool results to the agent) does not use this index yet.
- A corpus of bank templates (letterhead, standard clauses) that can be registered as "not confidential" if FPs in production are higher than in the eval.
- The eval uses a synthetic corpus; repeat with real confidential document samples (in the bank's environment) before the `block` policy is enabled.
