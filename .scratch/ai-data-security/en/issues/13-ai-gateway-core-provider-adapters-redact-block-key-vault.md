<!-- source-sha256: 4f71dbcc8d572efe -->
# 13: AI Gateway core: provider adapters, redact/block, key vault

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 08, 11
Spec: `../spec.md` §4.6; §5.4; §7.1; §8.7; §10.1 Secrets

## Context
The P0 PEP for app-to-LLM.

## Scope
- Compatible endpoints: `/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`, `/v1/messages`, `:generateContent`, and self-hosted passthrough.
- App AuthN via gateway key; provider keys are fetched from the vault and never sent to the client.
- Flow: normalize → scan → OPA → allow/warn/redact/block; redaction keeps the JSON and `messages[]` valid.
- Block uses HTTP 403 with a provider-format error body + headers `X-Wantimpres26-Decision-Id`, `X-Wantimpres26-Action`.
- Rate limit and token quota per app/user (FR-PSEC-9) via Redis.
- Fail mode configuration per app (§13.3).
- Inputs `destination.hosting_region` and `destination.ojk_approval_ref` from the catalog (ticket 16) are sent to OPA for the residency policy (ADR-0001).

## Acceptance criteria
- [x] Golden request/response contract test per provider. *(`TestContract` + `internal/aigw/testdata/`: OpenAI chat/responses/embeddings, self-hosted OpenAI-compatible, Anthropic messages, Gemini generateContent. The request reaches the provider intact with the provider key in the correct header, without the gateway key/app cookies; the response returns intact with the decision headers; the event per direction passes the schema.)*
- [x] Overhead p95 ≤ 80 ms, p99 ≤ 200 ms (text ≤ 8K tokens) under load test. *(`TestOverhead`, 32 KB prompt ≈ 8K tokens, 300 requests, real policy evaluated: p50 14.5 ms, p95 20.7 ms, p99 23.1 ms. Measured with an in-process PDP; the OPA sidecar adds one loopback hop. Multi-replica + Redis load test in ticket 21.)*
- [x] The official OpenAI/Anthropic SDKs do not crash when receiving a block. *(`testdata/sdk_smoke.py` with openai 3.28.0 and anthropic 1.13.0 against `TestServeForSDK`: block → `PermissionDeniedError` 403 with `x-wantimpres26-decision-id`; clean request → `ChatCompletion`/`Message` parsed; stream → `BadRequestError` 400.)*
- [x] Chaos test: detection/OPA down → behavior follows the fail mode. *(`TestFailMode`: PDP down → a `fail_closed` app gets a provider-format 503 and the provider is not called; a `fail_open` app is forwarded, event `FAIL_OPEN`, metric `aigw_fail_open_total`, alert `AIGatewayFailOpen`. Detection L1 runs in-process, so it cannot go down separately from the gateway.)*
- [x] A `restricted` prompt to an offshore provider is blocked; `confidential` is redacted before leaving. *(`TestResidency` with the real policy: 12 NIKs to OpenAI (region US from the catalog) → 403 `RESIDENCY_RESTRICTED_OFFSHORE`; NIK + phone → redacted, `messages[]` stays at 2 and the JSON is valid; a self-hosted model in region ID receives it as is. After redaction, the gateway rescans and blocks if the classes that had to be removed are still present (ADR-0001).)*

## Out of scope
Response streaming (ticket 14) and tokenize (ticket 24).

## Decisions
- **`internal/aigw` + `cmd/ai-gateway`.** Route `/<provider>/<API path>`; apps point the SDK `base_url` at it. Providers are configured in `AIGW_CONFIG_FILE` (kind `openai|anthropic|gemini`, upstream, `key_file`, catalog `app_id`, sanction/region fallback). Self-hosted (vLLM/Ollama) = kind `openai`. Azure OpenAI goes through path `/openai/v1` with `auth: api-key`.
- **App AuthN:** gateway key in the header its SDK normally uses (`Authorization: Bearer`, `x-api-key`, `x-goog-api-key`, `?key=`), stored as SHA-256 and compared in constant time. The app's auth headers, cookies, and `?key=` are never forwarded.
- **Provider keys from Vault agent files** (`KeyFiles`), re-read when the mtime changes. Rotation without restart.
- **Inspect only the text the model reads**: the root is defined per endpoint (`messages`, `input`/`instructions`, `system`, `contents`/`systemInstruction`; response `choices`/`output`/`content`/`candidates`). Roles, ids, and base64 media are skipped. The walk/scan/redact logic was moved from `mcpgw` to `internal/inspect` and is used by both gateways.
- **Actions:** allow/warn → forward; redact/tokenize → redact in place (tokenize = redact until ticket 24), then rescan and block if not yet clean; block/quarantine/require_approval → 403 in provider error format (`wantimpres26_policy_violation` / `permission_error` / `PERMISSION_DENIED`) with `X-Wantimpres26-Decision-Id` and `X-Wantimpres26-Action`. No content in the error message.
- **Non-streaming responses** are inspected with the same flow before reaching the app. Provider errors are forwarded as is. Embeddings are not inspected on the response side (the content is vectors).
- **Streaming is rejected** with a provider-format 400 until ticket 14, rather than forwarded without inspection.
- **Principal:** `X-Wantimpres26-User` from the app → `user` (HMAC); without it → `service` (HMAC of the app name). The calling app's name is recorded in the new event field `source_app` (schema, struct, OpenSearch index).
- **Rate limit and token quota (FR-PSEC-9):** rpm per app and per user (rejected requests are counted too), tokens per day per app and per user from the provider's `usage` (estimate as fallback). Counters in Redis (`REDIS_URL`, go-redis) or in-memory per replica. Redis down → no limiting, and it is logged: this is an availability control, not a data control. `content.tokens` is also sent to the PDP.
- **Fail mode per app** (`fail_open` | `fail_closed`, default `fail_closed`). Events `FAIL_OPEN`/`FAIL_CLOSED` with `policy_version: unavailable`, metrics at `/metrics`, alerts in `deploy/cluster/alerts.yaml`.
- **Residency:** the gateway sends `destination {app_id, sanction, region}`; `wantimpres26.dest` overrides sanction/region from the catalog and now also carries `ojk_approval_ref` (catalog release, input schema, rego tests).

## Remaining
- Streaming SSE (14), tokenize/detokenize (24), multi-replica load/soak/chaos + Redis + OPA sidecar (21).
- Detection of an expired OPA bundle > 24 hours → fail mode (§13.3) does not exist yet; currently the sidecar keeps using the last bundle and the alert `PolicyBundleLoadFailing` gives the signal.
- Trust labels for untrusted content in the request (tool/RAG results, FR-PSEC-2) are not yet distinguished from user instructions; the injection score is computed over all the text.
- `/metrics` is served on the same port as the API; separate it if apps must not see it (G1/ticket 40).
