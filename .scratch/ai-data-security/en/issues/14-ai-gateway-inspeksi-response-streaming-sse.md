<!-- source-sha256: e31709d62848a89a -->
# 14: AI Gateway: streaming (SSE) response inspection

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 13
Spec: `../spec.md` §4.6 FR-DLP-2; §7.1

## Context
Most chat applications use streaming, and responses can leak data or the system prompt.

## Scope
- Sliding window (default 256 tokens) + look-behind for entities split across chunks.
- Redact per window. A block mid-stream cuts the stream and sends a valid closing event per provider.
- Optional canary token in the system prompt of registered apps + system prompt n-gram overlap detection (FR-PSEC-5).

## Acceptance criteria
- [x] Test: a NIK split across 2 chunks is still redacted. *(`TestStreamEntitySplit`, OpenAI chat / Anthropic / Gemini: a NIK and PAN split across deltas and across windows (window reduced to 40 bytes) are redacted; the rest of the answer is identical and in order; the provider's closing event stays at the end. The default response policy does not redact NIK, so the test uses an extra bank rule; PAN uses the template `tpl.pci-pan-redact`.)*
- [x] Test: a block mid-stream → the SDK client receives a valid end of stream. *(`TestStreamBlockMidStream` per provider, plus `testdata/sdk_smoke.py` with the official SDKs: OpenAI → chunk `finish_reason: content_filter` + `[DONE]`; Anthropic → all blocks closed, a notice text block, `message_delta stop_reason: refusal`, `message_stop` (`get_final_message()` succeeds); Gemini → `finishReason: SAFETY`. The canary never reaches the client, not even half of it.)*
- [x] Overhead per window p95 ≤ 20 ms. *(`TestStreamWindowOverhead`: scan + real policy decision + release of one 256-token window, 300 windows: p50 4.2 ms, p95 7.3 ms. When the whole suite runs in parallel on one machine, p95 rises to ±29 ms because of CPU contention, so this test is skipped under `-short` like `TestOverhead`.)*

## Notes from ticket 13
- `internal/aigw` currently rejects `stream: true` with a provider-format 400. Non-streaming response inspection (`call.enforce` direction `response`) and the text roots per endpoint already exist to be reused per window.

## Decisions
- **Window per text channel** (OpenAI choice/tool call, Anthropic content block, Gemini candidate), default 256 tokens (1,024 bytes). A 128-byte tail is held back until the next text arrives, so entities split across chunks are whole when scanned; the release point never falls in the middle of a finding; 64 bytes of already-sent text are also scanned as keyword context. Every window is decided by the PDP (direction `response`).
- **The gateway synthesizes delta events** in the provider format for the released text. Structural events are forwarded in order: opening events (message_start, role, new tool call) after the preceding text is released; closing events (finish, stop, usage) after the text in that event. Text inside structural events (Gemini function call, etc.) is inspected whole.
- **One decision event per stream** (not per window): the strictest decision, findings merged, HMAC of the whole text, first snippet. Its ID is quoted in the block notice.
- **FR-PSEC-5:** `canary: true` per app plants a secret per-app marker (derived from the pepper) in the system prompt; a response containing it → `exfil_score` 1. Without a canary, word 8-gram overlap with the system prompt (8 shingles ≈ 15 consecutive words = score 1). New rule `tpl.system-prompt-leak`: a response with `exfil_score` ≥ 0.8 → block. Also applies to non-streaming responses.
- **Gemini** streaming via `:streamGenerateContent?alt=sse`. **OpenAI Responses API** streaming is still rejected (400): its snapshot events (`output_text.done`, `response.completed`) repeat the entire text and need to be rewritten separately.
- PDP down mid-stream: a `fail_open` app continues and it is recorded, a `fail_closed` app is stopped with a block closing.

## Remaining
- Responses API streaming.
- Redaction inside `partial_json` (tool arguments) can produce invalid JSON if the redacted value is an unquoted number.
- A 256-token window delays the first text by ±1 KB. If chat UX feels slow, make it a per-app setting.
