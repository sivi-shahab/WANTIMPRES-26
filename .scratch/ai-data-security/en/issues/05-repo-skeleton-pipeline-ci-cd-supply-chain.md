<!-- source-sha256: f7960bda34805caf -->
# 05: Repo skeleton + CI/CD pipeline & supply chain

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 01
Spec: `../spec.md` §5.3 DEC-3; §12.2

## Context
Build foundation for all services. The control plane is a modular monolith; PEP and detection are separate.

## Scope
- Repo structure: control-plane (modular monolith), ai-gateway, detection-svc, model-inference, deploy/ (Helm/Kustomize).
- Pipeline: lint → unit → SAST → SCA → secret scan → distroless build → CycloneDX SBOM → cosign sign → IaC scan.
- Admission policy in the cluster: only signed images.
- Shared privacy test: assert that logs/traces do not contain forbidden content fields.

## Acceptance criteria
- [ ] The pipeline is green for a hello-world service in each component. *(Locally: every lint/test/scan job passes with the same CI image; build/sbom/sign are tested equivalently with docker + cosign. Not yet run on GitLab.)*
- [x] SBOM and signature are attached to every image.
- [x] Deploying an unsigned image is rejected by the cluster.

## Decisions
- CI: **self-managed GitLab** (on-prem runner + registry).
- Language: **Go** for control-plane, ai-gateway, detection-svc; **Python** for model-inference. Rust is not used until there is evidence of a latency need.
- One Go module (`wantimpres26`) with `cmd/<service>`; one `build/go.Dockerfile` for all Go services.
- Trivy replaces Checkov/tfsec (SCA + license + IaC + image scan in one tool).
- cosign key-based, `--tlog-upload=false`, legacy `.sig/.att` format (Kyverno 1.19 does not read the cosign v3 bundle yet).

## Local verification results (2026-10-02)
- `go test -race`, Python unittest, golangci-lint v2.5.0, ruff, semgrep p/default, trivy fs/config, gitleaks (history + dir): passed.
- Shared privacy test: `internal/privacy` (Go) and `services/model-inference/test_app.py` read the same list `internal/privacy/forbidden_fields.txt`.
- kind (k8s 1.33) + Kyverno 1.19.1: 4 signed deployments run (tag mutated to digest); unsigned pod rejected; unsigned initContainer rejected.

## Remaining / follow-up
- Run the pipeline on GitLab; fill in `MIRROR`, `COSIGN_KEY` (protected, ideally a KMS/HSM URI), `COSIGN_PASSWORD`; replace the public key placeholder in the policy.
- SLSA L3 provenance does not exist yet.
- Admission does not verify the SBOM attestation yet: Kyverno 1.19 ivpol rejects attestations without a tlog. Needs an on-prem Rekor or an upstream fix.
