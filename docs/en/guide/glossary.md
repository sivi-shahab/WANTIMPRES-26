---
title: Glossary
outline: [2, 2]
---

# Glossary

Terms that come up often in the WANTIMPRES-26 documentation, with their meaning in the context of this platform. Use search (<kbd>Ctrl</kbd> <kbd>K</kbd>) to jump straight to a term.

## Platform concepts

| Term | Meaning |
|---|---|
| **AI-SPM** | *AI Security Posture Management*: finding, assessing, and fixing the security risks of AI use across an organisation. |
| **DSPM** | *Data Security Posture Management*: finding sensitive stored data and assessing who can access it. |
| **Enforcement point (PEP)** | *Policy Enforcement Point*: a component that captures interactions and carries out decisions, such as the AI gateway, the MCP gateway, and connectors. |
| **Policy decision point (PDP)** | The single place where decisions are made. In WANTIMPRES-26 this role is played by OPA. |
| **Hybrid enforcement** | An architecture with many enforcement points but one detection layer, one PDP, and one event pipeline. |
| **Channel** | The path data travels: `ai_gateway`, `mcp_gateway`, `connector`, and so on. |
| **Direction** | Where the data sits in an interaction: `request`, `response`, `tool_call`, `tool_result`, or `at_rest`. |
| **Control plane** | The management services: identity, policy, catalog, agents, incidents, compliance, and posture. Accessed through an API. |
| **Data plane** | The enforcement points that sit directly in the traffic path. |
| **Shadow AI** | AI apps or agents used without IT's visibility or approval. |
| **AI app catalog** | The list of AI apps with their approval status, hosting location, and risk attributes. |
| **Sanction status** | An app's approval status: `sanctioned`, `tolerated`, `unsanctioned`, `blocked`, or `under_review`. |

## Detection and classification

| Term | Meaning |
|---|---|
| **L1** | Fast, deterministic detection: text normalization, layered decoding, regex, validators (such as Luhn and NIK structure), and secret patterns. This is what currently drives decisions. |
| **L2** | ML-based detection: NER for personal data and a prompt injection classifier, run on CPU (ONNX int8). |
| **Shadow mode** | A model runs and its results are recorded, but it does not yet take part in decisions. L2 is currently in this mode. |
| **NER** | *Named Entity Recognition*: a model that recognises entities such as names, addresses, or ID numbers in free text. |
| **Data class** | The kind of data detected, for example `PII_ID.NIK`, `PCI.PAN`, or `SECRET.*`. |
| **Sensitivity** | How confidential content is: `public` < `internal` < `confidential` < `restricted`. |
| **Normalization** | Making text uniform before inspection (NFKC, removing invisible characters, mapping homoglyphs) so disguised attacks are still caught. |
| **Eval corpus** | A frozen, hash-pinned test set used to measure detector precision and recall before release. |
| **Precision / recall** | Precision: what share of findings are correct. Recall: what share of the sensitive data was found. |
| **ECE** | *Expected Calibration Error*: how far a model's confidence scores are from reality. Lower is better. |

## Threats to AI

| Term | Meaning |
|---|---|
| **Prompt injection** | Malicious instructions slipped in so the model ignores its original instructions. *Direct* means written by the user; *indirect* means hidden in outside content such as documents, web pages, or tool results. |
| **Jailbreak** | An attempt to make a model break its safety limits, for example through roleplay or a persona. |
| **System prompt leakage** | An app's system instructions leaking through the model's answers. |
| **Canary token** | A secret marker planted in the system prompt. If it appears in an answer, the system prompt has leaked. |
| **Adversarial suffix** | An optimised string appended to a prompt to break the model (for example the GCG attack). |
| **Excessive agency** | An agent holding more rights or capabilities than its task needs. |
| **Tool poisoning** | Malicious instructions hidden in an MCP tool's description. |
| **Rug pull** | A tool definition that silently changes after it was approved. |
| **Memory poisoning** | Malicious content written into an agent's long-term memory or vector store. |
| **OWASP LLM / ASI** | OWASP's top 10 risks for LLM applications (`LLM01`–`LLM10`, 2025) and agentic applications (`ASI01`–`ASI10`, 2026). |

## Policy and decisions

| Term | Meaning |
|---|---|
| **OPA** | *Open Policy Agent*: the open-source policy engine that acts as the PDP, running as a sidecar next to each enforcement point. |
| **Rego** | OPA's policy language. The WANTIMPRES-26 decision engine is in `policy/wantimpres26/decision.rego`. |
| **Policy as code** | Policies written as versioned code or data that can be reviewed, tested, and rolled back. |
| **Bundle** | A signed package of policy and data distributed to every OPA sidecar. |
| **Action** | The outcome of a decision, from least to most strict: `allow` < `warn` < `redact` < `tokenize` < `require_approval` < `quarantine` < `block`. When several rules match, the strictest action wins. |
| **Obligation** | An extra task that comes with an action, such as which data classes must be redacted. |
| **Reason code** | A code explaining a decision, such as `SECRET_TO_AI` or `PCI_PAN`. |
| **Decision ID** | A unique identifier for each decision, for the security team to trace. |
| **Monitor mode** | A rule that is only recorded, not enforced, to try out its impact. |
| **Simulation** | Running a new policy version against past events to see how many decisions would change. |
| **Exception** | A limited carve-out from a policy, with a required approver and expiry date. |
| **Four-eyes** | The two-person rule: the author and the approver cannot be the same person. |
| **Fail mode** | How an enforcement point behaves when the PDP is unavailable: `fail_closed` (refuse, the default) or `fail_open` (pass through and record in the metrics). |
| **Risk score** | A 0–100 score per event built from sensitivity, destination, attack signals, agent actions, volume, and identity. A *critical override* sets a high score directly for specific cases. |

## Data protection

| Term | Meaning |
|---|---|
| **Redact** | Replacing sensitive text with the marker `[REDACTED:<TYPE>]`. |
| **Tokenize** | Replacing a sensitive value with a token in the same format, so the app keeps working without seeing the real value. |
| **FPE / FF1** | *Format-Preserving Encryption*; FF1 is the NIST-standard FPE algorithm used by the token vault. |
| **Detokenize** | Turning a token back into the real value. Only for entitled apps or principals, and every occurrence is logged. |
| **Pseudonymization** | Replacing identities with a keyed HMAC value (a per-tenant *pepper*) so analytics never stores real identities. |
| **Forensic capture** | Storing original content, enabled only when a policy allows it; encrypted per incident. |
| **Unmask** | Opening an incident's original evidence. Needs a request approved by someone else and the `evidence.unmask` permission. |
| **Data at rest** | Stored data, for example in SharePoint, Google Drive, or cloud buckets. |
| **Oversharing** | Sensitive data whose access is too broad, such as a public link or an "all employees" group. |
| **Remediation** | Fixing oversharing, for example revoking a public link. Runs after approval. |
| **Data residency** | Rules on where data is processed and stored. This platform runs entirely in Indonesia. |

## Agents and MCP

| Term | Meaning |
|---|---|
| **Agent** | An AI program that acts on its own by calling tools or APIs. |
| **MCP** | *Model Context Protocol*: a standard protocol for connecting agents to tools and data sources. |
| **MCP server** | A service that exposes tools over MCP, for example CRM access. |
| **MCP gateway** | The WANTIMPRES-26 enforcement point between agents and MCP servers. |
| **Tool pinning** | Recording the hash of each approved tool definition so silent changes are detected. |
| **HITL** | *Human-in-the-loop*: risky actions are held until a person approves them. |
| **Kill switch** | An emergency stop per agent, tool, app, or globally. It revokes tokens and cuts off running sessions. |
| **Audience** (`aud`) | The token claim naming which service the token was issued for. Tokens with the wrong audience are refused. |
| **Token exchange** | Swapping the agent's token for a new short-lived token for the target service (RFC 8693), so the agent's token is never passed on. |
| **Agent registry** | The list of agents with their owners, identities, allowed tools, and status. |

## Identity and infrastructure

| Term | Meaning |
|---|---|
| **OIDC** | *OpenID Connect*: the login standard used by the control-plane, with Keycloak as the broker. |
| **SCIM** | A standard for syncing users and groups from the company directory. |
| **RBAC / ABAC** | Access control by role and by attributes, such as business unit or region. |
| **Break-glass** | An emergency account with full access whose every use is audited. |
| **mTLS** | Two-way TLS: both sides of a connection prove their identity. |
| **SPIFFE / SVID** | A workload identity standard. Every pod gets a short-lived certificate with an ID of the form `spiffe://wantimpres26.bank/…`. |
| **Tenant** | The unit of data isolation. WANTIMPRES-26 is deployed single-tenant but designed to be tenant-aware. |
| **RLS** | PostgreSQL *Row-Level Security*: every query is automatically limited to its tenant's data. |
| **Decision event** | The metadata record of each decision (`decision_event.v1`), sent through Kafka. It contains no raw content. |
| **Schema registry** | A service that stores event schemas (here Karapace) so producers and consumers agree on the format. |
| **Signed image** | A container image signed with cosign. The cluster only runs images like this. |
| **SBOM** | *Software Bill of Materials*: the list of components inside an image. |

## Audit, incidents, and operations

| Term | Meaning |
|---|---|
| **Hash-chained audit log** | An append-only log; each entry carries the hash of the previous one, so any change is detected. |
| **Anchor** | A signed daily summary hash of the audit log, stored in WORM object storage. |
| **WORM / object lock** | *Write Once Read Many*: objects cannot be changed or deleted during their retention period. |
| **Incident** | A group of related events for the SOC to handle, with a state, a severity, and evidence. |
| **Containment** | Limiting an incident's impact, for example blocking a user from an app or revoking an agent's tokens. |
| **Breach timer** | The 72-hour countdown that starts when a personal data breach is declared, per UU PDP Article 46. |
| **Posture** | The current security level per domain (discovery, data, prompt, agent, policy) and its trend. |
| **SIEM / SOAR / ITSM** | Security monitoring, response automation, and IT service ticketing systems that receive events from the platform. |
| **NFR** | *Non-Functional Requirements*: latency, throughput, availability, and recovery targets. See the [M1 NFR report](../../nfr/m1-report). |
| **p95 / p99** | Latency percentiles: 95% or 99% of requests finish within that time. |
| **RPO / RTO** | How much data may be lost (RPO) and how long recovery may take (RTO) in a disaster. |
| **DC / DRC** | *Data Center* and *Disaster Recovery Center*. |
| **Chaos test** | A resilience test that deliberately shuts down components such as OPA, Kafka, or Redis. |

## Regulations and standards

| Term | Meaning |
|---|---|
| **UU PDP** | Indonesia's Personal Data Protection Law (Law No. 27/2022). |
| **PP 33/2026** | The Government Regulation implementing UU PDP. |
| **OJK** | Otoritas Jasa Keuangan, Indonesia's Financial Services Authority. |
| **POJK 11/2022** | OJK Regulation 11/POJK.03/2022 on IT at commercial banks, including the requirement for a DC/DRC in Indonesia. |
| **OJK AI banking guide** | OJK's AI Governance Guide for Indonesian Banking (2025). |
| **ISO/IEC 42001** | The AI management system standard. |
| **NIST AI RMF** | NIST's AI risk management framework (Govern, Map, Measure, Manage). |
| **DPIA** | *Data Protection Impact Assessment*. See the [employee AI monitoring DPIA](../../dpia-pemantauan-ai-karyawan). |
| **DPO** | *Data Protection Officer*. |
| **NIK / KK / NPWP** | Indonesian national ID number, family card number, and tax ID. |
| **PAN** | *Primary Account Number*: a payment card number, validated with the Luhn algorithm. |

## Project terms

| Term | Meaning |
|---|---|
| **ADR** | *Architecture Decision Record*: a record of an architecture decision with its reasons and rejected alternatives. See [ADR-0001](../../adr/0001-hosting-residency-build-scope). |
| **DEC-n / ASM-n / U-n** | Spec markers for decisions, assumptions, and unknowns. |
| **FR-…** | Spec markers for functional requirements, for example `FR-POL-4`. |
| **M0–M4** | Roadmap milestones, from discovery (M0) to P2 features (M4). |
| **P0 / P1 / P2** | Priority: P0 is required for the MVP, P1 is the next phase, P2 comes later. |
| **Ticket status** | Values include `needs-triage`, `needs-signoff`, `needs-gitlab-run`, `deferred`, and `done`. See the [Ticket Overview](../tickets/). |
