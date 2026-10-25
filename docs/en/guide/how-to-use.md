---
title: How to Use
outline: [2, 3]
---

# How to Use WANTIMPRES-26

This guide is organised by task. Pick the section that fits your role:

| I want to… | Section | For |
|---|---|---|
| Try the platform on my laptop | [Try it locally](#try-it-locally) | Everyone |
| Connect an app to an LLM through the gateway | [Connect an app](#connect-an-app-to-the-ai-gateway) | AI engineers |
| Register a new app and provider | [Register apps](#register-apps-and-providers) | Security admins |
| Connect an agent to an MCP server | [Connect an agent](#connect-an-agent-through-the-mcp-gateway) | Agent owners |
| Write and release policies | [Manage policies](#manage-policies) | DLP analysts, policy approvers |
| Handle incidents and compliance evidence | [Operations](#soc-and-compliance-operations) | SOC, DPO, auditors |
| Map shadow AI and stored data | [Shadow AI & data at rest](#shadow-ai-and-data-at-rest) | Security admins |

::: info Conventions
Examples on this page use `aigw.example.internal` for the AI gateway, `mcpgw.example.internal` for the MCP gateway, and `cp.example.internal` for the control-plane. Replace them with the addresses in your environment.
:::

## Try it locally

The fastest route is the NFR harness. It runs the AI gateway with OPA, detection-svc, Kafka, Redis, OpenSearch, and a mock OpenAI-compatible provider. It needs Docker.

```sh
deploy/nfr/run.sh up      # build the images and a signed bundle, then start everything
```

The gateway listens on `localhost:18080`. Send a first request with the test app key `nfr-app-key`:

```sh
curl -i localhost:18080/openai/v1/chat/completions \
  -H 'Authorization: Bearer nfr-app-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"m","messages":[{"role":"user","content":"hello"}]}'
```

Look at the `X-Wantimpres26-Action` header in the response. It shows the action that was applied (`allow`, `redact`, and so on). Prometheus metrics are at `localhost:18080/metrics`.

```sh
deploy/nfr/run.sh down    # stop and clean up
```

::: warning Limits of the local stack
The harness only runs the gateway path. The control-plane and the MCP gateway are not started, no token vault is attached (so `tokenize` falls back to `redact`), and the L2 models are not active.
:::

## Connect an app to the AI gateway

Apps do not need a new SDK. Point the base URL at the gateway and use the app's **gateway key**, not the provider key. The gateway holds the provider key, and it never reaches the app.

### URL format

```text
https://aigw.example.internal/<provider-name>/<provider API path>
```

`<provider-name>` is the `name` in the gateway config (for example `openai`, `anthropic`, `gemini`). Supported endpoints:

| Provider `kind` | Endpoint | Streaming |
|---|---|---|
| `openai` | `POST v1/chat/completions` | Yes |
| `openai` | `POST v1/responses` | No |
| `openai` | `POST v1/embeddings` | No (the request is inspected, the returned vectors are not) |
| `anthropic` | `POST v1/messages` | Yes |
| `gemini` | `POST v1/models/<model>:generateContent` (or `v1beta`) | – |
| `gemini` | `POST …:streamGenerateContent?alt=sse` | Yes |

Self-hosted models (vLLM, Ollama, TGI) use `kind: openai`. The gateway does not choose or rewrite the model; the app still sets it in the request body.

### SDK examples

::: code-group

```python [OpenAI (Python)]
from openai import OpenAI

client = OpenAI(
    base_url="https://aigw.example.internal/openai/v1",
    api_key=GATEWAY_KEY,                              # gateway key, not an OpenAI key
    default_headers={"X-Wantimpres26-User": user_id}, # optional, for per-user limits
)
resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Summarise this document"}],
)
```

```python [Anthropic (Python)]
from anthropic import Anthropic

client = Anthropic(
    base_url="https://aigw.example.internal/anthropic",
    api_key=GATEWAY_KEY,
    default_headers={"X-Wantimpres26-User": user_id},
)
msg = client.messages.create(
    model="claude-sonnet-5-5",
    max_tokens=512,
    messages=[{"role": "user", "content": "Summarise this document"}],
)
```

```sh [Gemini (curl)]
curl https://aigw.example.internal/gemini/v1beta/models/gemini-2.5-flash:generateContent \
  -H "x-goog-api-key: $GATEWAY_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"contents":[{"parts":[{"text":"Summarise this document"}]}]}'
```

:::

The gateway takes the key from the first header it finds, in this order: `Authorization: Bearer`, `x-api-key`, `x-goog-api-key`, `api-key`, then the `?key=` parameter. Each SDK's default header therefore works as is.

The `X-Wantimpres26-User` header is optional. Its value is HMAC'd before it is stored and is used for per-user limits.

### Reading the gateway's decision

Every response carries two headers:

| Header | Contents |
|---|---|
| `X-Wantimpres26-Action` | The strictest action applied: `allow`, `warn`, `redact`, `tokenize`, or `block` |
| `X-Wantimpres26-Decision-Id` | The decision ID, for the security team to trace |

What the app sees for each action:

- **`redact`**: sensitive text is replaced with `[REDACTED:<TYPE>]` before it goes to the provider. The request still goes through.
- **`tokenize`**: sensitive numbers are replaced with format-preserving tokens (FPE). If the app is allowed to `detokenize`, tokens in the model's answer are swapped back to the real values.
- **`block`**: the gateway replies **403** in the provider's own error format, so the SDK raises its usual error. The message includes the reasons and the Decision ID. `quarantine` and `require_approval` also become a block on this channel, because it has no human approval step.

Example 403 body for an OpenAI app:

```json
{"error": {"message": "Request blocked by WANTIMPRES-26 policy [SECRET_TO_AI]. Decision ID: …. Contact the security team if this is unexpected.",
           "type": "wantimpres26_policy_violation", "param": null, "code": "wantimpres26_policy_block"}}
```

For Anthropic the type is `permission_error`, and for Gemini the status is `PERMISSION_DENIED`.

**Streaming.** If the model's answer breaks a policy mid-stream, the gateway ends the stream the same way the provider ends filtered content: `finish_reason: "content_filter"` (OpenAI), `stop_reason: "refusal"` (Anthropic), or `finishReason: "SAFETY"` (Gemini), with the notice `[WANTIMPRES-26: response stopped by policy …]`.

### Other error codes

| Status | Code | Meaning and what to do |
|---|---|---|
| 400 | `invalid_json`, `streaming_unavailable` | The body is not valid JSON, or streaming was requested on an endpoint that does not support it |
| 401 | `invalid_gateway_key` | The gateway key is missing or wrong |
| 403 | `provider_not_allowed` | The app is not allowed to use this provider |
| 403 | `wantimpres26_redaction_failed` | Redaction failed; the request was not sent |
| 404 | `unknown_provider`, `unsupported_endpoint` | Unknown provider name or path |
| 413 | `request_too_large` | The body is over 4 MiB |
| 429 | `rate_limit_exceeded` | Requests-per-minute limit; retry after `Retry-After` (60 seconds) |
| 429 | `token_quota_exceeded` | The daily token quota is used up |
| 502 | `upstream_unavailable` | The provider cannot be reached |
| 503 | `wantimpres26_policy_unavailable` | The policy decision point is unavailable and the app uses `fail_closed` |

## Register apps and providers

Apps and providers are registered in the JSON file that `AIGW_CONFIG_FILE` points to. Unknown fields are rejected.

```json
{
  "apps": [{
    "id": "chatbot-cs",
    "key_sha256": "<sha256 of the gateway key, 64 hex>",
    "providers": ["openai"],
    "fail_mode": "fail_closed",
    "rpm": 600, "user_rpm": 30,
    "tokens_per_day": 5000000, "user_tokens_per_day": 200000
  }],
  "providers": [{
    "name": "openai",
    "kind": "openai",
    "upstream": "https://api.openai.com",
    "key_file": "/secrets/openai.key",
    "app_id": "chatgpt", "sanction": "sanctioned", "region": "US"
  }]
}
```

Things to note:

- **Gateway keys** are not stored in plain form. Generate a random key, give it to the app team, and store its hash:
  ```sh
  printf %s "$GATEWAY_KEY" | sha256sum
  ```
- **`fail_mode`** defaults to `fail_closed`. Use `fail_open` only for apps that may keep running without policy checks; every occurrence is counted in the metrics.
- A **limit** of `0` means unlimited. The counters live in Redis; if Redis is down, requests are still served.
- Each **provider** must have `app_id`, `sanction`, and `region`. Policies use all three, for example to refuse `restricted` data to an offshore provider.
- **`key_file`** is re-read automatically when the file changes, so rotating a provider key needs no restart.
- Other per-app options: `canary` (a canary token to catch system prompt leaks), `detokenize`, and `token_ttl_minutes` (default 60).

Egress to LLM providers should be allowed only through the gateway. See the [AI gateway egress runbook](../../runbooks/egress-ai-gateway).

## Connect an agent through the MCP gateway

The MCP gateway sits between agents and MCP servers. It inspects tool call arguments and results, exchanges tokens, holds risky actions for approval, and enforces the kill switch.

### 1. Register the MCP server

Add the server to the `MCP_SERVERS_FILE` file:

```json
[{"name": "crm", "upstream": "https://crm-mcp.internal/mcp", "audience": "crm-mcp",
  "app_id": "crm-mcp", "sanction": "sanctioned", "region": "ID"}]
```

Agents then connect to `https://mcpgw.example.internal/mcp/crm` (Streamable HTTP).

### 2. Register the agent

Register the agent on the control-plane with `POST /agents`, including its workload identity (`spiffe`, `oidc_client`, or `managed_identity`) and the tools it may use with their risk levels. Agents without an owner are quarantined automatically. The full schema is in `internal/agents/store.go`.

### 3. Agent authentication

The agent sends `Authorization: Bearer <OAuth access token>`. The token's audience (`aud`) must equal the server's resource URI, here `https://mcpgw.example.internal/mcp/crm`. If the token is missing or wrong, the gateway replies 401 with a `WWW-Authenticate` header pointing to the metadata at `/.well-known/oauth-protected-resource/mcp/crm`, so a spec-compliant MCP client can find the authorization server on its own.

The agent's token is never passed on to the MCP server. The gateway exchanges it for a short-lived downstream token (RFC 8693).

### 4. Tool approval

When an agent calls `tools/list`, the gateway records a hash of each tool definition. Only approved tools are visible to the agent. Admins approve or reject tools with:

```text
POST /mcp/tools/{server}/{name}/approve
POST /mcp/tools/{server}/{name}/reject
```

If a tool's definition changes after approval (a *rug pull*), the tool must be approved again.

### 5. Human approval for risky actions

When a policy requires approval, the agent receives a JSON-RPC error with code `-32001` and the message `approval required: call again with the same arguments once approved`. The `data` field holds `approval_id`, `state`, and `expires_at`. A well-behaved agent shows this status to the user, then **calls again with exactly the same arguments** once approved.

Approvers decide on the control-plane:

```text
POST /approvals/{id}/approve   {"note": "…"}
POST /approvals/{id}/reject    {"note": "…"}
```

An approval is bound to the agent, server, tool, and argument hash, can be used once, and expires after 15 minutes (set `APPROVAL_TTL` to change this). Approvers can be notified through `APPROVAL_WEBHOOK_URL`.

### 6. Kill switch

```text
POST /agents/{id}/kill         {"reason": "…"}
POST /kills                    {"scope": "…", "target": "…", "reason": "…"}
POST /kills/global             {"reason": "…"}      # sensitive permission agent.kill.global
POST /kills/{id}/lift
```

Running sessions are cut off immediately. A caller hit by the kill switch gets 403 `stopped by kill switch`.

## Manage policies

### Rule shape

A policy is a list of rules expressed as data. Each rule has conditions (`when`), an action, and a reason. Two examples from the built-in templates:

```json
{"id": "tpl.secret-to-any-ai",
 "when": [{"field": "direction", "op": "in", "value": ["request", "tool_call"]},
          {"field": "content.classes", "op": "class_any", "value": ["SECRET.*"]}],
 "action": "block", "reason": "SECRET_TO_AI"}

{"id": "tpl.pci-pan-redact",
 "when": [{"field": "content.classes", "op": "class_any", "value": ["PCI.PAN"]}],
 "action": "redact", "obligations": [{"type": "redact", "classes": ["PCI.PAN"]}],
 "reason": "PCI_PAN"}
```

Actions from least to most strict: `allow` < `warn` < `redact` < `tokenize` < `require_approval` < `quarantine` < `block`. When several rules match, the strictest action wins. Add `"mode": "monitor"` to try a rule without enforcing it.

The built-in templates are in `policy/wantimpres26/rules/data.json`, and the decision engine is `policy/wantimpres26/decision.rego`.

### Release cycle

Every control-plane call uses an OIDC token with MFA. Sensitive permissions such as `policy.publish` also require a fresh login and a justification of at least 10 characters in the `X-Justification` header.

1. **Draft**: `POST /policies` with body `{"name": "…", "rules": [ … ]}`. The reply contains the `id` and `version: 1`. Later versions are created with `POST /policies/{id}/versions`.
2. **Simulate**: `POST /policies/{id}/simulate` with body `{"version": 1, "window": {"from": "…", "to": "…"}, "include_corpus": true}`. The result is at `GET /simulations/{id}` and shows how many decisions would change.
3. **Submit**: `POST /policies/{id}/versions/{v}/submit`.
4. **Approve**: `POST /policies/{id}/versions/{v}/approve`, by **someone other than** the author. The version becomes active at once and is distributed to every enforcement point as a signed bundle.
5. **Roll back** if needed: `POST /policies/{id}/rollback`.

Exceptions are created with `POST /exceptions` and must be approved (`POST /exceptions/{id}/approve`). Every exception must have an expiry date.

## SOC and compliance operations

| Task | Control-plane endpoint |
|---|---|
| List and triage incidents | `GET /incidents`, `POST /incidents/{id}/transition` |
| Containment | `POST /incidents/{id}/actions` |
| View evidence (redacted) | `GET /incidents/{id}/evidence/{eid}` |
| Open the original evidence | `POST /incidents/{id}/evidence/{eid}/unmask-requests`, approved by someone else, then `GET …/evidence/{eid}/raw` (permission `evidence.unmask`) |
| Data breach (UU PDP) | `POST /incidents/{id}/breach/declare`, then `…/breach/report` for the draft report |
| Posture | `GET /posture` |
| Compliance evidence | `GET /compliance/frameworks`, `…/controls`, `…/report`, `…/ai-register` |

Events are also sent to the SIEM by `siem-export` over syslog/TLS or HTTP (HEC/JSON), above the `SIEM_MIN_RISK` threshold (default 40).

Audit log integrity can be checked from the CLI:

```sh
control-plane audit anchor --day yesterday
control-plane audit verify --from 2026-10-01 --to 2026-10-25
```

## Shadow AI and data at rest

A **shadow AI map** is built from existing proxy or DNS logs, without installing anything on the network:

```sh
TENANT_PEPPER=… shadow-baseline -format squid -units units.csv -out report/ /var/log/squid/access.log*
```

Supported formats are `squid`, `dns`, and `jsonl`. The output is `report/shadow-baseline.json` and `.md`.

**Stored data** is scanned by `connector-worker`. Supported sources: Microsoft 365, Google Drive (including an OAuth grant audit), S3, GCS, Azure Blob, and the Claude and ChatGPT compliance APIs. Results are at `GET /data/assets` and `GET /data/summary`. Remediation (for example revoking a public link) is proposed with `POST /data/assets/{id}/remediations` and runs only after approval. Remediation is currently available for M365, Google Drive, and S3.

## Not available yet

- The browser extension, the web proxy (ICAP) adapter, and the endpoint agent are not built ([ticket 22](../tickets/22-browser-extension-prompt-paste-upload-coaching), [23](../tickets/23-web-proxy-adapter-icap-reqmod-respmod), [36](../tickets/36-endpoint-agent-windows-macos)).
- There is no admin UI yet; everything is managed through the control-plane API.
- L2 detection runs in *shadow mode* only ([ticket 49](../tickets/49-detection-l2-di-jalur-pep)).

The full list of environment variables per service is in `README.md` and `cmd/<service>/main.go`. Production deployment steps are in [ADR-0001](../../adr/0001-hosting-residency-build-scope) and the runbooks.
