---
title: Why WANTIMPRES-26
---

# Why WANTIMPRES-26

Employees already use AI, with or without permission. Internal apps are starting to call LLMs, and agents are starting to act on their own through tools. The question is no longer *whether* AI is used, but *whether the company knows and controls what data goes along with it*. WANTIMPRES-26 is built to answer that question.

## The problems it solves

| Problem | Without controls | What WANTIMPRES-26 does |
|---|---|---|
| **Shadow AI** | Customer data, code, and internal documents leave through personal GenAI accounts without a trace | An AI app catalog, shadow AI discovery from proxy/DNS logs, and a *sanctioned* status per app |
| **Legacy DLP is blind to AI context** | Prompts, streaming responses, RAG, and agent tool calls go unchecked | Inspection on AI channels: prompts, responses (including streaming), tool call arguments and results |
| **LLM-specific attacks** | Prompt injection, jailbreaks, and system prompt leakage slip past regex | Layered normalization and decoding, an injection detector, and architectural rules (least privilege, human approval) |
| **Oversharing of stored data** | Copilot/RAG "finds" files whose access is too loose | Data-at-rest connectors, ACL analysis, remediation with approval |
| **Autonomous agents** | Agents hold long-lived credentials and act without a trail | Agent registry, short-lived tokens, tool pinning, human approval, kill switch |
| **Regulatory obligations** | Hard to prove controls to OJK and auditors; the 72-hour breach notification window is missed | Hash-chained audit log, control mapping to UU PDP/POJK 11/OJK's AI guide, breach timer and draft report |

## Why not a classic DLP or an LLM gateway

| | Classic DLP/CASB | Single-vendor LLM gateway | **WANTIMPRES-26** |
|---|---|---|---|
| Understands prompts and streaming responses | Limited | Yes | Yes |
| Agent tool calls and MCP | No | Partly | Yes, through the MCP gateway |
| One policy for every channel | Per product | Gateway channel only | Yes, one OPA for every enforcement point |
| Indonesian data detectors (NIK, KK, NPWP, bank accounts) | Usually needs customization | Rare | Built in, with structural validation |
| Data stays in Indonesia | Depends on the vendor | Often processed abroad | Every component deploys in your own data center; detection models are self-hosted |
| Evidence for OJK and UU PDP | Generic reports | None | Control mapping and evidence export per audit period |
| Policies can be read and tested | Closed configuration | Closed configuration | Policy-as-code (Rego), simulation before publish, rollback |

WANTIMPRES-26 does not have to replace the SWG/CASB/DLP you already run. It can consume their logs and focus on the channels they do not guard (see [ADR-0001](../../adr/0001-hosting-residency-build-scope)).

## Principles that make it trustworthy

- **Decision separate from enforcement.** Every enforcement point asks the same policy decision point, so rules never fork between channels.
- **Defense in depth.** Deterministic rules, ML models, and architectural controls cover each other's gaps. No single detector is trusted alone.
- **Privacy by default.** Raw content is not stored by default; only metadata, hashes, and redacted snippets are kept.
- **Explainable decisions.** Every decision carries `reason_codes`, the policy version, and the model version.
- **Explicit failure modes.** Each app decides whether to close (`fail_closed`) or keep running with an alarm (`fail_open`) when the decision point is unavailable.

## Measured evidence

These figures come from the [M1 NFR gate report](../../nfr/m1-report). They were measured on a single Docker host, without mTLS/SASL and without the L2 models, so production numbers must be measured again.

| What was measured | Spec target | Result |
|---|---|---|
| Added gateway latency (8K-token text, p95) | ≤ 80 ms | **+22.2 ms** |
| OPA policy evaluation (p99) | ≤ 5 ms | **3.8–4.4 ms** |
| Kill switch effective end to end | ≤ 10 s | **1.19 s** |
| Policy publish/rollback to every enforcement point (p99) | ≤ 60 s | **15.2 s** |
| Event searchable in OpenSearch (p95) | ≤ 60 s | **4.8 s** |
| PostgreSQL RPO / RTO | ≤ 15 min / ≤ 4 h | **45.2 s / 20.9 s** |
| Gateway throughput per pod (4 vCPU) | ≥ 300 RPS | **125 RPS** within target; 300 RPS not yet reached |

Chaos tests also showed the gateway keeps serving when Kafka or Redis is down, and OPA serves again from its stored bundle within 1 second of a restart.

## Benefits by role

| Role | What they get |
|---|---|
| **CISO** | Posture scores and AI trends across the organisation, top risks, evidence for the board and regulators (through the posture API and compliance export; no admin UI yet) |
| **SOC** | Correlated, deduplicated incidents, redacted evidence, containment actions through the API, events into your existing SIEM |
| **DLP analyst** | Policy as code, impact simulation before publish, exceptions with expiry dates |
| **Compliance / DPO** | Control mapping to regulations, control history per audit period, draft data breach reports |
| **AI engineer** | Just point the base URL at the gateway; existing OpenAI/Anthropic SDKs keep working |
| **Agent owner** | Registered agents with minimum privileges, approval for risky actions, a full session trail |
| **Employees** | See why a request was blocked or redacted through `reason_codes`, and can request an exception |

## Current limitations

To set the right expectations, here is what was not finished when this documentation was written:

- L2 detection (the NER model and the injection classifier) runs in *shadow mode* only: its results are recorded in decision events, but decisions still come from deterministic L1 detection ([ticket 49](../tickets/49-detection-l2-di-jalur-pep)).
- File scanning only inspects the first 2 MiB of text ([ticket 50](../tickets/50-scan-file-hanya-2mib-teks-pertama)).
- The failure mode for a policy bundle older than 24 hours is not implemented ([ticket 51](../tickets/51-fail-mode-bundle-kedaluwarsa-24-jam)).
- Throughput is 125 RPS per pod, below the 300 RPS target; a sizing decision is needed ([ticket 47](../tickets/47-optimasi-pdp-throughput-per-pod)).
- There is no admin UI yet; everything is managed through the control-plane API.
- The endpoint agent (P2) is not built. WANTIMPRES-26 also cannot stop leaks with no technical path, such as photographing a screen with a personal phone.

The latest status of each item is in the [Ticket Overview](../tickets/).
