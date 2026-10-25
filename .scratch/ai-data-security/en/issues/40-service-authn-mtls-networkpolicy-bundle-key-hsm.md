<!-- source-sha256: 34f2041545070c6a -->
# 40: Service-to-service authN, NetworkPolicy default-deny, bundle key in KMS/HSM

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M2
Spec: `../spec.md` §10.1 AuthN (SPIFFE/mTLS), Self-protection; `docs/threat-model.md` G1

## Context
Threat model (ticket 02) G1: detection-svc and model-inference accept requests from any pod in the cluster (an oracle for evading the detectors). `GET /bundles/wantimpres26.tar.gz` is public, so catalog data, the agent registry, and exceptions can be read from the network. The bundle signing key is a Secret file, not KMS/HSM.

## Scope
- mTLS between services (SPIFFE/SVID via a mesh or cert-manager), or at minimum a default-deny NetworkPolicy in the `wantimpres26` namespace with explicit allows per flow in §5.2.
- `/bundles` only for the OPA sidecar (workload identity).
- Bundle signing through KMS/HSM; the private key is never a file in the pod.

## Acceptance criteria
- [x] A pod without an authorized identity is rejected when calling detection-svc, model-inference, and `/bundles` (test). *(Evidence per service:)*
  - *detection-svc, `TestScanOnlyForPEPs`: ai-gateway may scan. siem-export, event-ingest, tika, and `default` are rejected at the handshake.*
  - *model-inference, `test_mtls.py`: detection-svc is served. siem-export, a client without a certificate, and a certificate from another CA are rejected. The service refuses to start without `MTLS_DIR`/`MTLS_ALLOW`.*
  - *`/bundles`, `TestBundleOnlyForSidecarsAndKeyRotation`: the OPA SDK with `deploy/base/opa/opa.yaml` as-is gets the bundle as ai-gateway, whereas as siem-export it never becomes ready. `/bundles` was removed from the admin API (`TestRouteMatrix`).*
  - *Shared layer, `TestWorkloadTLS`: rejects IDs outside the list, no certificate, and a foreign CA. The client also checks the server ID. Certificates are rotated in place without a restart.*
- [ ] NetworkPolicy default-deny is active; the §5.2 flows still pass the smoke test. *(The manifest is already active: `deploy/base/networkpolicy.yaml`, default-deny Ingress+Egress plus an allow per flow. Verified **statically** by `deploy/netpol_test.go`, which evaluates NetworkPolicy semantics over the manifests: all §5.2 flows are open (BUN→OPA, PEP→DS, DS→MI, GW→TV, admin ingress, Alertmanager, Prometheus, DNS, external data services), while the oracle/exfiltration paths are closed (other pods → detection/model/`/bundles`, model-inference/tika → outside). The test also ensures every workload has its own ServiceAccount and that `MTLS_ALLOW` is consistent with the network. kubeconform: 46 resources valid; kustomize build OK. **The smoke test on a real cluster has not been run**, see Remaining.)*
- [x] Bundle key rotation without downtime is documented. *(`docs/runbooks/rotasi-kunci-bundle.md`. Tested: `TestTransitSignerAndRotation` (slot a = file, slot b = fake Vault transit; both verify when both slots are trusted; slot b is rejected before the sidecar knows it; a rogue key claiming slot a is rejected) and the end-to-end OPA SDK test (release signed by a, then b, active without restarting the sidecar; a rogue-key bundle does not replace the last valid one).)*

## Decisions
- **Workload identity:** X.509 SVIDs from cert-manager csi-driver-spiffe (`spiffe://wantimpres26.bank/ns/wantimpres26/sa/<sa>`), with one ServiceAccount per workload. No mesh: far fewer components for 3 flows that need authN. The SVID private key is generated on the node and rotated in place. The Go server (`internal/server`) and Python (`mtls.py`) re-read the files when they change. Cluster setup: `deploy/cluster/workload-identity.md`.
- **Workload-only routes are split by port:** `server.RunMTLS` serves workload routes only on `:8443` (TLS 1.3, client certificate required, SPIFFE ID ∈ `MTLS_ALLOW`, rejected at the handshake). `:8080` is only for kubelet probes; on the control-plane it also carries the admin API behind the ingress. Without `MTLS_DIR`, the service refuses to start unless `MTLS_INSECURE=true` (local dev).
- **Allowed callers:** `/bundles` and detection-svc for ai-gateway and mcp-gateway; model-inference for detection-svc. `server.MTLSClient` is provided for detection-svc → model-inference (tickets 09/10 use it when calling the model). The OPA sidecar uses OPA's built-in `client_tls` with `cert_reread_interval_seconds: 300`.
- **NetworkPolicy:** default-deny Ingress+Egress, DNS to kube-dns, an allow per flow in §5.2, and egress outside the cluster only for pods labeled `wantimpres26.bank/egress: external`. model-inference and tika are not labeled, so they cannot send data out. External egress `0.0.0.0/0` is marked `ponytail:` to be narrowed to the data service CIDRs per site. Outside namespaces are matched via `kubernetes.io/metadata.name` (`ingress-nginx`, `monitoring`, `kube-system`). control-plane → tika was added because PDF registration (ticket 37) would otherwise have been blocked by `tika-isolated`.
- **Bundle key:** `policysvc.Signer` wraps `crypto.Signer`. The production implementation is Vault transit (`TransitSigner`, can be HSM-backed via a managed key), and the file key is for dev/test only. This choice avoids PKCS#11 (cgo) in the distroless image. The bundle remains a standard ES256 JWS with `kid` = slot, verified by OPA's default verifier. At start, the control-plane signs a probe and verifies it with the configured public key, so a wrong Vault configuration is detected before the first release.
- **Rotation:** two fixed slots (`wantimpres26-policy-a`/`-b`) in all sidecars, and `signing.keyid` is removed from `opa.yaml` so the bundle's `kid` selects the key. Rotation only requires changing the public-key ConfigMap and the control-plane env, without changing the sidecar args or config.
- **Python test PKI fixtures** in `services/model-inference/testdata/pki` (valid for 100 years, trusted by no deployment) are allowlisted in `.gitleaks.toml`. The default gitleaks rules still apply to other paths. The Go tests create their own PKI at runtime.

## Local verification results (2026-10-10)
- gofmt clean, `go vet ./...` clean, golangci-lint v2.5.0 0 issues. Python: `python -m unittest` (3 tests) and ruff check/format clean.
- This ticket's tests are green: `internal/server` (`TestWorkloadTLS`, `TestMTLSClientNeedsCertificates`), `cmd/detection-svc` (`TestScanOnlyForPEPs`), `cmd/control-plane` (`TestBundleOnlyForSidecarsAndKeyRotation`, `TestRouteMatrix`), `internal/policysvc` (`TestTransitSignerAndRotation`, and the old bundle tests with the new signer), `deploy` (`TestNetworkPolicy`), and `test_mtls.py`.
- `go test -race ./...` with Postgres 17: 35 packages green in the full run. Two time-based tests failed when the host load average was ~50 from parallel work: `mcpgw.TestKillSwitch` (4.9 seconds) and the `policysvc.TestRegoPolicies` timeout. Both are green when rerun on their own with `-race` (together with `lifecycle`, `server`, `cmd/...`, `deploy`).
- kubeconform v0.6.7 `-strict`: 46/46 valid. kustomize v5.4.3 build OK. gitleaks v8.28.0: 0 findings with `.gitleaks.toml` (4 without the config, namely the test fixtures).

## Remaining
- **Smoke test on a real cluster** (kind/k3d with cert-manager + csi-driver-spiffe + a CNI that enforces NetworkPolicy, all images built) has not been run. It needs to be run on a staging cluster before the 2nd AC is checked.
- Install cert-manager + csi-driver-spiffe with the `wantimpres26` intermediate CA in the HSM (platform team, `deploy/cluster/workload-identity.md`). Create the Vault transit key, a sign-only token, and the `policy-bundle-pubkey` ConfigMap with two slots.
- Narrow the egress `0.0.0.0/0` to the bank's data service CIDRs per site (overlay).
- Other PEPs (web-proxy adapter, browser extension backend) that call detection-svc need a ServiceAccount, an SVID volume, and an `MTLS_ALLOW`/NetworkPolicy entry when they are built.
- token-vault still uses the application bearer token (ticket 24) plus NetworkPolicy, not mTLS yet.
