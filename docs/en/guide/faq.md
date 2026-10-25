---
title: FAQ
outline: [2, 3]
---

# Frequently Asked Questions

## General

### What is WANTIMPRES-26?

An *Enterprise AI Data Security & AI Security Posture Management* platform. It inspects and weighs every AI interaction in the company (prompts, files, model responses, and agent tool calls) before sensitive data moves. The full picture is in [Why WANTIMPRES-26](./why).

### Is the name WANTIMPRES-26 related to a state institution?

No. The name is a technical acronym of the platform's functions (*Workforce AI Network Threat Inspection, Monitoring, Policy, Risk & Enforcement System*), and "26" means the 2026 edition. The platform is not affiliated with any institution, party, or political figure. See [Name & Logo Philosophy](../about/philosophy).

### Does WANTIMPRES-26 replace our existing DLP, CASB, or SWG?

Not necessarily. The v1 scope deliberately targets the channels those tools do not guard: the AI gateway, the MCP gateway for agents, local detectors, the policy engine, audit, incidents, compliance, and stored-data connectors. In v1, shadow AI is read passively from existing proxy/SWG/DNS logs. The browser extension, ICAP adapter, and endpoint agent are postponed until the existing vendor inventory is known. This decision is recorded in [ADR-0001](../../adr/0001-hosting-residency-build-scope).

### Can employees still use AI?

Yes. The goal is not to ban AI but to keep the data that travels with it under control. Prompts without sensitive data go through as usual. The built-in rules do use `block` often, but for clearly dangerous cases, such as credentials sent to any AI or `restricted` data sent to an offshore provider. Data such as card numbers (PAN) is simply redacted.

## Privacy and data

### Are prompts and answers stored?

Not by default. Only metadata, hashes, classifications, and redacted snippets are kept. Original content is stored only when a policy turns on *forensic capture*. In that case the content is encrypted per incident, and opening it needs an *unmask* request approved by someone else plus the `evidence.unmask` permission.

### Where is data processed and stored?

Every component runs on Kubernetes in the bank's data center and DRC in Indonesia, in line with POJK 11/2022. Detection models are self-hosted on CPU, so content is never sent to a third party for inspection. External feeds, such as the AI app catalog and detector models, are only pulled in and have their signatures verified.

### What about LLM providers abroad?

They are not banned outright but governed through the catalog and policy. For destinations hosted outside Indonesia, the defaults are:
- `restricted` content is blocked,
- `confidential` content (including customer personal data) is redacted or tokenized, or blocked if it cannot be redacted,
- `internal` and `public` content is allowed only for apps with `sanctioned` status.

Every decision is recorded in the audit log as evidence for OJK and UU PDP.

### Are employees personally monitored?

Monitoring is limited to interactions with AI services. User identities in analytics are pseudonymised with HMAC, and access to original evidence is restricted and logged. The impact assessment for employees is documented in the [employee AI monitoring DPIA](../../dpia-pemantauan-ai-karyawan).

## Integration

### Do our apps need to change to use the gateway?

Barely. Change the base URL to the gateway (`https://<gateway>/<provider-name>/v1`) and use a gateway key instead of the provider key. Existing OpenAI, Anthropic, and Gemini SDKs keep working. The steps are in [How to Use](./how-to-use#connect-an-app-to-the-ai-gateway).

### Which providers and models are supported?

The OpenAI API shape (chat completions, responses, embeddings), Anthropic (messages), and Gemini (generateContent, streamGenerateContent). Self-hosted models such as vLLM, Ollama, or TGI are supported through the OpenAI shape. The gateway does not choose or rewrite the model.

### Is streaming supported?

Yes, for OpenAI chat completions, Anthropic messages, and Gemini streamGenerateContent. The answer is inspected window by window as it streams. On a violation, the stream ends the same way the provider ends filtered content.

### How does an app know a request was blocked or redacted?

Every response carries the `X-Wantimpres26-Action` and `X-Wantimpres26-Decision-Id` headers. A blocked request gets 403 in the provider's own error format, so the SDK raises its usual error. The message includes the reasons and the Decision ID.

### How much latency does it add?

In the M1 measurements, the added p95 latency for 8K-token text was about 22 ms (target ≤ 80 ms). This was measured on a single host without mTLS and without the L2 models, so it must be measured again in production. Details are in the [M1 NFR report](../../nfr/m1-report).

### What about agents and MCP?

Agents connect to MCP servers through the MCP gateway with an OAuth token whose audience is the target server. The gateway exchanges that token for a short-lived one, shows only approved tools, holds risky actions for human approval, and enforces the kill switch. See [Connect an agent](./how-to-use#connect-an-agent-through-the-mcp-gateway).

## Policy and operations

### Who can change policies?

Policies are drafted, simulated, then submitted. A new version only becomes active once approved by **someone other than** its author who holds the `policy.publish` permission. That approval requires a fresh login and a written justification. Every step is in the audit log and can be rolled back.

### What happens if the policy engine is down?

It depends on the app's `fail_mode`. With `fail_closed` (the default), requests are refused with 503 `wantimpres26_policy_unavailable`. With `fail_open`, requests go through and every occurrence is counted in the metrics. After a restart, OPA serves again from its stored policy bundle within about 1 second.

### What happens if Kafka or Redis is down?

The gateway keeps serving. Decision events that cannot be sent are counted in the `decision_events_dropped_total` metric, and rate/quota limits are not enforced while Redis is down.

### How fast does the kill switch work?

In the M1 measurements the kill switch was effective end to end in about 1.2 seconds (target ≤ 10 seconds), and running MCP sessions were cut off in under 1 second.

### Can I try a rule without enforcing it?

Yes, in two ways. Simulate a policy version against past events to see how many decisions would change, or give a rule `"mode": "monitor"` so it is only recorded, not enforced.

## Compliance

### Which regulations and standards are mapped?

UU PDP (Law No. 27/2022) and PP 33/2026, POJK 11/POJK.03/2022, OJK's 2025 AI Governance Guide for Indonesian Banking, ISO/IEC 42001, NIST AI RMF, and the OWASP LLM Top 10 and Agentic Top 10. The mappings are versioned and can be exported per audit period. The ISO/IEC 42001 cells still need to be confirmed against a licensed copy of the standard.

### How does the platform help with the 72-hour breach notification duty?

An incident involving personal data can be declared a data breach. From then on a 72-hour timer runs and the system prepares a draft report covering the exposed data, when and how it happened, and the handling steps.

### How do we prove the audit log was not altered?

The audit log is append-only and hash-chained. A signed anchor is created every day and stored in object storage with object lock. Integrity can be checked at any time with `control-plane audit verify`.

## Project status

### Is it production-ready?

Not entirely. The M1 NFR gate is still awaiting sign-off, and several items are open:
- L2 detection runs in *shadow mode* only,
- file scanning inspects only the first 2 MiB of text,
- the failure mode for an expired policy bundle is not implemented,
- throughput per pod is 125 RPS against a 300 RPS target.

The full list is in [Current limitations](./why#current-limitations) and the [Ticket Overview](../tickets/).

### Is there an admin UI?

Not yet. Everything is managed through the control-plane API, secured with OIDC and MFA.

### Where do I report a problem or propose a feature?

Tickets are markdown files in `.scratch/ai-data-security/issues/` in the [GitHub repository](https://github.com/sivi-shahab/WANTIMPRES-26), one file per ticket. The status of each ticket is in the [Ticket Overview](../tickets/).
