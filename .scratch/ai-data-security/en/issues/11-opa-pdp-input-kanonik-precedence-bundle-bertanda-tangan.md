<!-- source-sha256: 850c88c4b556a9b8 -->
# 11: OPA PDP: canonical input, precedence, signed bundles

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 05
Spec: `../spec.md` §4.7 FR-POL-1..4, FR-POL-9; §13.1

## Context
One PDP for all PEPs (principle P2).

## Scope
- Canonical input/output schema (FR-POL-2/3) as versioned JSON Schema.
- Rego library for precedence: `block > quarantine > require_approval > tokenize > redact > warn > allow` + obligations merging.
- The Policy Service builds and signs bundles; the OPA sidecar verifies them and long-polls.
- Decision log with masking of sensitive fields.
- Built-in policy templates (FR-POL-8), including the ADR-0001 residency template: offshore destination → `restricted` block, `confidential` redact/tokenize, `internal`/`public` allow only for `sanctioned` apps.

## Acceptance criteria
- [x] `opa test` for precedence and every template. *(18 tests; also run by `go test ./internal/policysvc`, so it is part of the `test:go` job.)*
- [ ] `opa bench`: eval p99 ≤ 5 ms in the sidecar. *(WSL2 laptop: mean ~2 ms, p99 4.0–5.4 ms; does not convincingly pass yet. Re-measure on the target node, ticket 21.)*
- [x] A bundle with an invalid signature is rejected and triggers an alert.
- [x] `opa test` for the residency template on every combination of sensitivity × `hosting_region` × sanction status. *(80 combinations.)*

## Decisions
- Rules = data (`policy/wantimpres26/rules/data.json`), generic engine `policy/wantimpres26/decision.rego`. Input that is invalid against the JSON Schema → `block` + `INPUT_SCHEMA_INVALID` (fail closed).
- Policy Service = control-plane (`internal/policysvc`): build + sign bundle (ES256, key id `wantimpres26-policy`) at start, serve `GET /bundles/wantimpres26.tar.gz` with ETag + long-poll. Refuses to publish if `rule_errors` is not empty. Without a signing key, the control-plane does not start.
- OPA library v1.19.0 (v1.20+ needs Go 1.26); OPA sidecar 1.21.1, image rebuilt via `build/opa.Dockerfile` so it is covered by SBOM + cosign (Kyverno).
- Sidecar: `persist: true` (the last verified bundle survives restarts), readiness `/health?bundles`, decision log masked by `system/log/mask.rego` with the list `internal/privacy/forbidden_fields.txt` injected by the builder.
- `json.match_schema` recompiles the schema on every eval (~0.9 ms). A native Rego validator was tried and was slower (~2 ms), so it is not used.

## Local verification results (2026-10-03)
- `opa test` 18/18, `opa check --strict`, `go test -race`, golangci-lint, trivy config: passed.
- Docker e2e (control-plane + OPA 1.21.1): bundle activated, long-poll holds the request (1 load, not thousands), the decision log removes `/input/prompt`.
- A bundle signed by another key → `invalid ECDSA signature`; data.json changed with the old signature → `digest mismatch`. Both are rejected, OPA keeps using the old bundle, `bundle_failed_load_counter` increases → alert `PolicyBundleSignatureInvalid` (`deploy/cluster/alerts.yaml`).

## Remaining / follow-up
- Provision the Secret `policy-bundle-signing` + ConfigMap `policy-bundle-pubkey` (ideally the key in Vault/HSM); PrometheusRule needs prometheus-operator.
- Alerts to SIEM (ticket 19); decision log to the event pipeline (ticket 15), currently to stdout.
- Bench p99 on the target hardware (ticket 21). Option if it fails: strip schema annotations at build time (~25% faster validation).
- ~~Bundle is built once at start~~: ticket 12 builds the bundle from releases in Postgres on every replica.
