# WANTIMPRES-26 — Enterprise AI Data Security & AI-SPM

**W**orkforce **A**I **N**etwork **T**hreat **I**nspection, **M**onitoring, **P**olicy, **R**isk & **E**nforcement
**S**ystem, 2026 edition. Identifier in code, policy and deploy: `wantimpres26`.

A platform that controls sensitive data moving to, from, and through AI: public GenAI apps, internal LLM apps, and
AI agents. Every channel (prompts, file uploads, responses, agent tool calls, data at rest that AI can reach) is
discovered, classified, risk-scored, and put under one policy.

Full spec: [`.scratch/ai-data-security/spec.md`](.scratch/ai-data-security/spec.md) (Indonesian). Interactive
architecture diagram, live at <https://sivi-shahab.github.io/AI-Security/> (search, focus, route probe, Live
trace; deployed from `.archify/` by `.github/workflows/pages.yml`):
[`.archify/architecture-wantimpres26-platform-20261017-133119/wantimpres26-platform.html`](.archify/architecture-wantimpres26-platform-20261017-133119/wantimpres26-platform.html).

## Architecture

Hybrid enforcement (spec DEC-1): many enforcement points (PEPs), one detection plane, one policy decision point
(OPA), one event pipeline.

```text
Internal AI apps ──► ai-gateway ───┐
AI agents ─────────► mcp-gateway ──┤
SaaS / cloud ──────► connector-worker ┼─► detection (L1 in-process, L2 model-inference) ─► OPA (signed bundle)
                                   │                                                     │
                                   │      allow | warn | redact | tokenize |             │
                                   │      require_approval | quarantine | block ◄────────┘
                                   ▼
          decision_event ─► Kafka ─► event-ingest ─► OpenSearch ─► posture / incidents / compliance / SIEM
```

The strictest matching action wins (DEC-2). Raw content is never stored by default: only metadata, hashes, and
redacted snippets (P4). Each PEP has an explicit `fail_open | fail_closed` mode per app/policy (P7).

## Services (`cmd/`)

| Command | Role |
|---|---|
| `ai-gateway` | PEP between internal apps and LLM providers (OpenAI, Anthropic, Gemini shapes). Inspects request and streaming response, redacts/tokenizes/blocks, rate and token limits. |
| `mcp-gateway` | PEP between AI agents and MCP servers: authz, token exchange, tool pinning (rug-pull detection), argument inspection, kill switch. |
| `detection-svc` | Detection API: L1 (normalize, decode, regex + validators, secrets) plus L2 calls to `model-inference`. |
| `control-plane` | Admin API: identity (OIDC, SCIM), policy lifecycle and signed OPA bundles, catalog, agents, incidents, approvals, compliance, posture. `control-plane audit anchor\|verify` runs the audit-log CLI. |
| `token-vault` | Format-preserving tokenization vault (FPE) with detokenization of responses. |
| `event-ingest` | Kafka consumer: validates `decision_event` against the schema registry, indexes into OpenSearch. |
| `connector-worker` | Data-at-rest scanning and remediation: M365, Google Drive, S3/GCS/Azure Blob, ChatGPT/Claude compliance APIs. |
| `siem-export` | Sends events and incidents to the SIEM (CEF over syslog/TLS or HTTP) and SOAR webhooks. |
| `shadow-baseline` | Offline: measures shadow AI use from SWG/proxy/DNS logs against the app catalog. |
| `evalcorpus` | Offline: freezes, scores and labels the detector eval corpus (`data/eval/`). |

`services/model-inference/` is the Python L2 service (ONNX int8 on CPU): Indonesian/English NER PII and the
prompt-injection classifier. Training is reproducible from `services/model-inference/train/`; artifacts are pinned
by hash in `MODELS.json` and are not committed. See its `MODEL_CARD.md`.

## Repository layout

```text
cmd/            service entrypoints (one binary each)
internal/       domain packages (aigw, mcpgw, detect, l2, policysvc, lifecycle, incident, audit, tokvault, ...)
policy/         Rego (policy/wantimpres26/decision.rego is the PDP) and default data, embedded into the bundle
services/       Python model-inference service and its training pipeline
data/eval/      frozen detector eval sets, hash-pinned by MANIFEST.json
deploy/base/    Kustomize manifests (namespace wantimpres26, NetworkPolicy, OPA sidecar config)
deploy/cluster/ cluster-wide policy: signed-image admission, alerts, workload identity
deploy/nfr/     NFR harness (load, chaos, soak, DR) and recorded results
build/          Dockerfiles (one shared Go image, OPA, Tika)
docs/           ADRs, threat model, DPIA, labeling guideline, runbooks, NFR report
.scratch/       spec and issue tickets
```

## Getting started

Requires Go 1.26, Docker, and Python 3 for `services/model-inference`.

```sh
go build ./...
go vet ./...
go test -race ./...                              # unit tests; Rego tests run through Go as well
cd services/model-inference && pip install -r requirements.txt && python -m unittest -v
```

Integration tests (audit log, event pipeline, object storage) need real backends and skip locally unless their
env vars are set. CI runs them against Postgres 17, MinIO, Kafka 3.9, Karapace, OpenSearch 2.19 and Azurite; the
variables are in `.gitlab-ci.yml` (`AUDIT_TEST_*`, `IT_KAFKA_*`, `IT_SCHEMA_REGISTRY_URL`, `IT_OPENSEARCH_URL`,
`OBJSTORE_TEST_AZURITE`).

Build a service image:

```sh
docker build --build-arg SERVICE=ai-gateway -f build/go.Dockerfile .
```

### Local stack

The NFR harness is the quickest way to run the gateway with OPA, detection, Kafka, Redis, OpenSearch and a mock
OpenAI-compatible provider:

```sh
deploy/nfr/run.sh up      # build images and the signed bundle, start everything (gateway on :18080)
deploy/nfr/measure.sh     # load; also chaos.sh, soak.sh, dr.sh, opa-bench.sh
deploy/nfr/run.sh down
```

Gateway apps and providers are configured in `deploy/nfr/config/aigw.json`.

## Configuration

All services are configured through environment variables; secrets are passed as files (`*_FILE`) or as SHA-256
hashes of bearer tokens (`*_TOKEN_SHA256`). Common ones:

| Variable | Used by | Meaning |
|---|---|---|
| `TENANT_ID`, `TENANT_PEPPER` | most | Tenant UUID; HMAC pepper used to pseudonymize users in events |
| `DATABASE_URL` | control-plane, detection-svc, token-vault, connector-worker, siem-export | PostgreSQL (row-level security per tenant, ADR-0003) |
| `OPA_URL` | ai-gateway, mcp-gateway | OPA sidecar |
| `KAFKA_BROKERS`, `KAFKA_SASL_*`, `KAFKA_CA_FILE` | event producers/consumers | Event bus (TLS + SASL; `KAFKA_PLAINTEXT=true` for local only) |
| `SCHEMA_REGISTRY_URL` | event producers/consumers | Karapace / schema registry for `decision_event.v1` |
| `MTLS_DIR`, `MTLS_ALLOW` | internal services | SPIFFE certificates and allowed peer IDs |
| `AIGW_CONFIG_FILE` | ai-gateway | Apps, keys, providers, limits, fail mode |
| `DETECTION_URL`, `VAULT_URLS`, `REDIS_URL` | ai-gateway | Detection, token vault, rate-limit store |
| `MODEL_INFERENCE_URL`, `L2_MODE`, `L2_TIMEOUT` | detection-svc | L2 model service |
| `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_MFA_ACR`, `SCIM_TOKEN_SHA256` | control-plane | Identity (Keycloak broker, ADR-0002) |
| `SIEM_SYSLOG_ADDR`, `SIEM_HTTP_URL`, `SIEM_MIN_RISK` | siem-export | SIEM destinations |

The complete list for each service is the `os.Getenv` / `env(...)` calls in its `cmd/<name>/main.go`, and the
production values are in `deploy/base/`.

## Deployment

```sh
kubectl apply -k deploy/base
```

Production assumes: cert-manager `csi-driver-spiffe` for workload mTLS, Vault Transit for bundle signing (key
rotation: `docs/runbooks/rotasi-kunci-bundle.md`), signed images enforced by `deploy/cluster/require-signed-images.yaml`,
and egress to LLM providers allowed only through ai-gateway (`docs/runbooks/egress-ai-gateway.md`). Hosting and data
residency decisions are in `docs/adr/0001-hosting-residency-build-scope.md`.

## CI

GitLab (`.gitlab-ci.yml`, the release pipeline): `lint` (gofmt, golangci-lint, ruff) → `test` (Go with race detector + integration services, Python) → `scan`
(Semgrep, Trivy vuln/license, gitleaks over full history, IaC) → `build` (BuildKit) → `publish` (SBOM) → `sign`.

GitHub Actions (`.github/workflows/ci.yml`) mirrors lint, test (same integration backends) and scan on pushes to
`main` and pull requests; build, SBOM and signing stay on GitLab.

## Documentation

- [Threat model](docs/threat-model.md) — STRIDE, OWASP LLM Top 10, OWASP Agentic
- [ADRs](docs/adr/) — hosting/residency, identity, PostgreSQL RLS
- [M1 NFR report](docs/nfr/m1-report.md) — latency, throughput, chaos, DR results against spec §13
- [DPIA](docs/dpia-pemantauan-ai-karyawan.md) — employee AI monitoring
- [Labeling guideline](docs/labeling-guideline.md) — eval corpus annotation
- Compliance framework mappings (UU PDP, POJK 11/2022, OJK AI guide, ISO 42001, NIST AI RMF, OWASP) live in
  `internal/compliance/library/`.

## Work tracking

Issues are local markdown under `.scratch/ai-data-security/issues/` (numbered tickets; commits reference them as
"ticket NN").
