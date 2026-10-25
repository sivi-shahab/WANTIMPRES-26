---
title: Installation
outline: [2, 3]
---

# Installation

The source code is on GitHub: **[github.com/sivi-shahab/WANTIMPRES-26](https://github.com/sivi-shahab/WANTIMPRES-26)**.

This page covers two paths:

- **[Development environment](#development-environment):** build, test, and run on a laptop.
- **[Production installation](#production-installation):** deploy to Kubernetes in your own data center, as decided in [ADR-0001](../../adr/0001-hosting-residency-build-scope).

## Development environment

### Requirements

| Tool | Version | For |
|---|---|---|
| Go | 1.26 | Every service except model-inference |
| Docker (with Compose v2) | recent | Building images and the local stack |
| Python | 3 | `services/model-inference` (the L2 model service) |
| Node.js | 22 | The documentation site (optional) |

### Get the code and build

```sh
git clone https://github.com/sivi-shahab/WANTIMPRES-26.git
cd WANTIMPRES-26

go build ./...
go vet ./...
go test -race ./...    # unit tests; Rego tests run through Go as well
```

The L2 model service is tested separately:

```sh
cd services/model-inference
pip install -r requirements.txt
python -m unittest -v
```

Integration tests (audit log, event pipeline, object storage) need real backends and are skipped locally unless their environment variables are set. The variables are listed in `.gitlab-ci.yml` (`AUDIT_TEST_*`, `IT_KAFKA_*`, `IT_SCHEMA_REGISTRY_URL`, `IT_OPENSEARCH_URL`, `OBJSTORE_TEST_AZURITE`).

### Run the local stack

```sh
deploy/nfr/run.sh up      # gateway on localhost:18080
deploy/nfr/run.sh down
```

The script runs Go inside the `golang:1.26` image, so the host only needs Docker. To send a first request, see [How to Use](./how-to-use#try-it-locally).

### Run the documentation site

```sh
npm ci
npm run docs:dev          # http://localhost:5173
```

## Production installation

Production runs on your own Kubernetes and uses only standard open-source components, with no managed service that locks you into one cloud.

### 1. Prepare the dependencies

| Component | Version tested in CI | Role |
|---|---|---|
| Kubernetes | – | Main platform, namespace `wantimpres26` |
| PostgreSQL (HA, e.g. Patroni) | 17 | Control-plane data, row-level security per tenant ([ADR-0003](../../adr/0003-rls-postgresql-per-tenant)) |
| Kafka + schema registry (Karapace) | 3.9 | `decision_event.v1` events (TLS + SASL) |
| OpenSearch | 2.19 | Event search and investigation |
| Redis | – | Gateway rate limits and quotas |
| S3-compatible object storage with object lock | – | Audit log anchors (WORM) and evidence |
| Keycloak | – | OIDC identity broker for admins ([ADR-0002](../../adr/0002-identity-keycloak-broker)) |
| Vault (Transit) | – | Signs policy bundles; the private key never enters a pod |
| cert-manager + csi-driver-spiffe | – | Workload identity and service-to-service mTLS |
| Kyverno | – | Admits signed images only |

### 2. Prepare the cluster (once per cluster)

1. **Workload identity.** Install cert-manager and csi-driver-spiffe with the trust domain `wantimpres26.bank` and a dedicated intermediate CA signed by your internal CA. The full guide, including a Helm example, is in `deploy/cluster/workload-identity.md`.
2. **Signed-image policy:**
   ```sh
   kubectl apply -f deploy/cluster/require-signed-images.yaml
   ```
3. **Alerts** (optional, a `PrometheusRule` for the Prometheus Operator): `deploy/cluster/alerts.yaml`.

### 3. Build, sign, and publish the images

Every Go service uses one shared Dockerfile:

```sh
docker build --build-arg SERVICE=ai-gateway -f build/go.Dockerfile -t <registry>/wantimpres26/ai-gateway:<tag> .
```

Repeat for `control-plane`, `mcp-gateway`, `detection-svc`, `token-vault`, `event-ingest`, `connector-worker`, and `siem-export`. The OPA and Tika images come from `build/opa.Dockerfile` and `build/tika.Dockerfile`, and model-inference from `services/model-inference/Dockerfile`.

The L2 model artifacts are not in the image or the repository. They are rebuilt from `services/model-inference/train/`, pinned by sha256 in `MODELS.json`, and mounted from the model store at `MODEL_DIR`.

Because the cluster admits only signed images, sign them (cosign) before deploying. The official release pipeline is in GitLab (`.gitlab-ci.yml`): lint → test → scan → build → SBOM → sign.

### 4. Prepare Secrets and ConfigMaps

The manifests in `deploy/base` contain no secrets. Every Secret is created out of band, preferably through Vault or whatever secret manager your platform team uses.

**Per-service configuration Secrets.** Each Deployment reads its environment variables from a Secret with the same name: `ai-gateway`, `control-plane`, `mcp-gateway`, `token-vault`, `event-ingest`, `connector-worker`, `siem-export`, and `audit-anchor`. They hold values such as `DATABASE_URL`, `KAFKA_BROKERS`, `SCHEMA_REGISTRY_URL`, `OPENSEARCH_URL`, `REDIS_URL`, `OIDC_ISSUER`, `TENANT_ID`, and `TENANT_PEPPER`. The variables each service reads are noted in the manifest comments and in `cmd/<service>/main.go`; the configuration table in `README.md` summarises them.

**File Secrets:**

| Secret | Contents |
|---|---|
| `<service>-bus` | Kafka SASL password and Kafka/OpenSearch CA per service |
| `ai-gateway-provider-keys` | LLM provider API keys (re-read automatically when they change) |
| `bundle-signer-token` | A Vault token allowed only `transit/sign` on the bundle key |
| `incident-kek`, `token-vault-kek` | Key-wrapping keys for incident evidence and the tokenization vault |
| `audit-anchor-key` | The key that signs the daily audit log anchor |
| `connector-worker-files`, `siem-export-files` | Connector credentials and SIEM certificates |

**ConfigMaps:**

| ConfigMap | Contents |
|---|---|
| `ai-gateway-config` | Gateway apps and providers (`AIGW_CONFIG_FILE`); see [Register apps](./how-to-use#register-apps-and-providers) |
| `mcp-servers` | The MCP server list for the MCP gateway |
| `policy-bundle-pubkey` | Public keys `wantimpres26-policy-a.pub` and `wantimpres26-policy-b.pub` for bundle verification |

`opa-config` is generated by Kustomize from `deploy/base/opa/opa.yaml`.

### 5. Deploy

The base manifests point at `registry.local/wantimpres26/<service>:dev`. Replace them with your registry and tag through a Kustomize overlay, for example:

```yaml
# overlays/prod/kustomization.yaml (example)
resources:
  - ../../deploy/base
images:
  - name: registry.local/wantimpres26/ai-gateway
    newName: registry.example.internal/wantimpres26/ai-gateway
    newTag: "1.0.0"
  # repeat for every service
```

Then apply:

```sh
kubectl apply -k overlays/prod     # or: kubectl apply -k deploy/base
kubectl -n wantimpres26 get pods
```

Every service serves `/healthz` for readiness and liveness probes. The audit anchor runs as a CronJob every day at 00:15 Jakarta time (`Asia/Jakarta`).

### 6. After installation

1. **Force LLM traffic through the gateway.** Block direct egress to LLM providers; see the [AI gateway egress runbook](../../runbooks/egress-ai-gateway).
2. **Initial policy.** On an empty database the built-in templates are loaded automatically as the `builtin` policy. Adjust them through the [policy release cycle](./how-to-use#manage-policies).
3. **Register your first apps, providers, MCP servers, and agents** ([How to Use](./how-to-use)).
4. **Set up bundle key rotation** following the [bundle key rotation runbook](../../runbooks/rotasi-kunci-bundle).
5. **Re-test the non-functional targets** in production; the figures in the [M1 NFR report](../../nfr/m1-report) were measured on a single host.

::: tip Help
Common installation and operations questions are in the [FAQ](./faq). Issues and proposals are tracked as tickets in `.scratch/ai-data-security/issues/` in the [GitHub repository](https://github.com/sivi-shahab/WANTIMPRES-26).
:::
