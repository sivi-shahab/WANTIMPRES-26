---
title: Release Notes
outline: [2, 3]
---

# Release Notes

Release notes summarise the changes that matter to users and operators: new features, changes to watch for when upgrading, fixes, and limitations. The full per-commit list is in the [Changelog](../changelog).

## October 2026 preview

::: info No tagged release yet
This is a preview release from the `main` branch as of 26 October 2026, covering all work since the project started. Official version numbers begin when the first release tag is created. Most tickets are `needs-gitlab-run` (implemented and tested locally, awaiting the GitLab release pipeline) or `needs-signoff`. See the [Roadmap](./roadmap).
:::

### Highlights

- **AI gateway** from internal apps to OpenAI, Anthropic, Gemini, and self-hosted models, with request and streaming response inspection, redact, tokenize, block, and quotas.
- **MCP gateway** for agents: token audience validation, token exchange, tool pinning, human approval, and a kill switch.
- **One policy decision point (OPA)** with signed bundles, simulation, the two-person rule, and rollback.
- **Compliance evidence**: a hash-chained audit log, a UU PDP data breach timer, and control mapping to Indonesian regulations.
- **Measured M1 NFR gate**: +22.2 ms added p95 latency, a 1.19-second kill switch, and a 45.2-second PostgreSQL RPO ([report](../../nfr/m1-report)).

### New features

**AI gateway and detection**
- Provider adapters (OpenAI, Anthropic, Gemini, self-hosted), inspection, redact/block, and per-app and per-user quotas ([13](../tickets/13-ai-gateway-core-provider-adapters-redact-block-key-vault)).
- Streaming response inspection and system prompt leak detection with a canary ([14](../tickets/14-ai-gateway-inspeksi-response-streaming-sse)).
- FF1 tokenization vault with tokenize/detokenize in the gateway ([24](../tickets/24-tokenization-vault-fpe-detokenisasi-response)).
- L1 detection: normalization, NIK/KK/NPWP/PAN validators, secret detection, and the `/scan/text` endpoint ([08](../tickets/08-detection-l1-normalisasi-regex-validator-secrets)).
- L2 detection: personal data NER and a prompt injection classifier in one pass, on CPU, in *shadow mode* ([09](../tickets/09-detection-l2-ner-pii-indonesia-inggris), [10](../tickets/10-detection-l2-prompt-injection-jailbreak-classifier-v1)).
- Confidential document fingerprinting, inline and at rest ([37](../tickets/37-similarity-fingerprint-dokumen-rahasia)).
- Per-tenant detector tuning with active learning and gated rollout ([38](../tickets/38-custom-classifier-per-tenant-active-learning)).

**Agents and MCP**
- MCP gateway: token audience, token exchange, tool policy, and inspection ([28](../tickets/28-mcp-gateway-core-authz-token-exchange-inspeksi)).
- Tool pinning, tool poisoning scans, and re-approval when a tool definition changes ([29](../tickets/29-mcp-scan-tool-description-deteksi-rug-pull)).
- Human approval (HITL) and kill switches ([30](../tickets/30-hitl-approval-kill-switch)).
- Agent registry with workload identity and a shadow agent queue ([27](../tickets/27-agent-registry-workload-identity)).
- Inspection of agent memory writes ([44](../tickets/44-memory-context-poisoning-agent)) and agent behavior analytics ([39](../tickets/39-agent-behavior-analytics)).

**Policy and risk**
- OPA as the PDP, signed policy bundles, and the Policy Service ([11](../tickets/11-opa-pdp-input-kanonik-precedence-bundle-bertanda-tangan)).
- Policy lifecycle: versions, the two-person rule, simulation, rollback, and exceptions ([12](../tickets/12-policy-lifecycle-versi-4-eyes-simulasi-rollback-exception)).
- Risk scoring with critical overrides and 14-day aggregation ([17](../tickets/17-risk-scoring-v1-critical-overrides)), plus weight calibration from SOC triage verdicts ([25](../tickets/25-kalibrasi-risk-scoring-dengan-label-triage-soc)).

**Stored data and shadow AI**
- Connector SDK, M365 connector, file extraction, and oversharing scans ([31](../tickets/31-connector-sdk-m365-connector-analisis-oversharing)).
- Google Drive, object storage, and AI compliance API connectors ([32](../tickets/32-connectors-google-workspace-cloud-storage)).
- Remediation with approval, dry run, and undo ([33](../tickets/33-remediation-actions-untuk-data-at-rest)).
- Shadow AI baseline from proxy and DNS logs ([03](../tickets/03-baseline-shadow-ai-dari-log-proxy-swg-dns)), an AI app catalog with a signed feed ([16](../tickets/16-ai-app-catalog-status-sanction)), and gateway bypass detection ([43](../tickets/43-paksa-trafik-llm-lewat-ai-gateway)).

**Incidents, audit, and compliance**
- Incident management: dedup, state machine, SLA, and audited unmask ([18](../tickets/18-incident-management-dasar)).
- Incident chains, the UU PDP data breach timer, containment, and ITSM/SOAR ([26](../tickets/26-incident-lanjut-korelasi-breach-timer-uu-pdp-soar-itsm)).
- Append-only, hash-chained audit log with WORM anchors ([07](../tickets/07-audit-log-append-only-dengan-hash-chain-anchor-worm)).
- Compliance module: framework library, evidence, control history, and reports ([34](../tickets/34-compliance-module-framework-library-evidence-report)).
- Posture API ([20](../tickets/20-posture-dashboard-v1)), SIEM export ([19](../tickets/19-integrasi-siem-cef-syslog-http)), and the `decision_event` pipeline through Kafka, a schema registry, and OpenSearch ([15](../tickets/15-event-pipeline-kafka-schema-opensearch-retensi)).

**Identity and platform security**
- SSO through Keycloak, SCIM, RBAC/ABAC, and step-up for sensitive permissions ([06](../tickets/06-identity-sso-oidc-saml-scim-rbac-abac)).
- Service-to-service mTLS, default-deny NetworkPolicy, and bundle signing through KMS ([40](../tickets/40-service-authn-mtls-networkpolicy-bundle-key-hsm)).
- Mandatory TLS and SASL for Kafka and OpenSearch ([41](../tickets/41-kafka-opensearch-tls-sasl-acl)), and PostgreSQL row-level security per tenant ([42](../tickets/42-postgres-rls-tenant)).
- Unmask limited by unit, region, and clearance, with the two-person rule for `restricted` data ([45](../tickets/45-unmask-abuse-volume-abac-four-eyes)).

**Operations**
- GitLab pipeline and signed-image admission ([05](../tickets/05-repo-skeleton-pipeline-ci-cd-supply-chain)); a GitHub Actions workflow mirroring lint, test, and scan.
- NFR harness (load, chaos, soak, DR) and the M1 gate report ([21](../tickets/21-nfr-gate-m1-load-soak-chaos-dr)).
- An interactive architecture diagram and a bilingual documentation site.

### Changes to watch for

- **The project was renamed from `aisec` to WANTIMPRES-26.** Every identifier now uses `wantimpres26`: the Go module, the Rego package, the Kubernetes namespace, Kafka topics, index names, and the `X-Wantimpres26-*` HTTP headers. Integrations that read the old headers or topics need updating.
- **The system prompt canary prefix** is now `WTP26-`.
- **The SPIFFE trust domain** is now `wantimpres26.bank`; the model-inference test PKI was reissued.
- **Go 1.26** is now required, both for local builds and CI.

### Fixes and performance

- The gateway no longer stops serving when Kafka is down; events are sent asynchronously and dropped events are counted in `decision_events_dropped_total` ([46](../tickets/46-gateway-hang-saat-kafka-down)).
- The Redis wait is bounded with a per-replica fallback, so p95 stays low while Redis is down ([48](../tickets/48-latensi-gateway-saat-redis-down)).
- The OPA cost per decision was halved: p99 3.8–4.4 ms and 125 RPS per pod ([47](../tickets/47-optimasi-pdp-throughput-per-pod)).
- Fixes for two tests failing under `-race`, the quarantine folder slug in the remediation test, and the MinIO image in GitHub CI.

### Security

- **CVE-2026-78669** is fixed by moving to Go 1.26 and `golang.org/x/net` v0.60.0. govulncheck no longer reports a reachable vulnerability.
- Every scanner exception (gitleaks, Semgrep, Trivy) has been reviewed and scoped to its site.
- A new security policy: report vulnerabilities through GitHub private vulnerability reporting ([Security Policy](./security)).

### Known limitations

- L2 detection runs in *shadow mode* only ([49](../tickets/49-detection-l2-di-jalur-pep)).
- File scanning inspects only the first 2 MiB of text ([50](../tickets/50-scan-file-hanya-2mib-teks-pertama)).
- The failure mode for a policy bundle older than 24 hours is not implemented ([51](../tickets/51-fail-mode-bundle-kedaluwarsa-24-jam)).
- Throughput is 125 RPS per pod, below the 300 RPS target ([47](../tickets/47-optimasi-pdp-throughput-per-pod)).
- The browser extension, ICAP adapter, and endpoint agent are deferred ([22](../tickets/22-browser-extension-prompt-paste-upload-coaching), [23](../tickets/23-web-proxy-adapter-icap-reqmod-respmod), [36](../tickets/36-endpoint-agent-windows-macos)). There is no admin UI yet.
