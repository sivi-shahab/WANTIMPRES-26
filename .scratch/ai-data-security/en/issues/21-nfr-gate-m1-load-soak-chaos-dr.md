<!-- source-sha256: e6d6c7bd4475733a -->
# 21: NFR gate M1: load, soak, chaos, DR

Status: needs-signoff
Type: task
Priority: P0
Milestone: M1
Blocked by: 13, 14, 15, 18
Spec: `../spec.md` §12.1 DR; §13; §15

## Context
Gate before the MVP is used in production.

## Scope
- Load test against the §13.1 targets + 24-hour soak.
- Chaos: kill OPA, detection, Kafka, and Redis; verify fail modes.
- DR drill for Postgres + object storage; measure RPO ≤ 15 minutes and RTO ≤ 4 hours.
- Initial sizing based on ASM-2.

## Acceptance criteria
- [x] Report of results vs the §13.1 targets. *(`docs/nfr/m1-report.md`: every §13.1 row with measured figures, method, raw data in `deploy/nfr/results/`, and host limitations.)*
- [ ] All deviations have a ticket or a risk-acceptance decision. *(Seven deviations have new tickets: 46 Kafka down → gateway stops serving (P0), 47 OPA p99 and per-pod throughput, 48 latency when Redis is down, 49 L2/detection-svc not in the PEP path, 50 file scan only the first 2 MiB, 51 bundle fail mode > 24 hours. Three other items (RA-1 availability via production SLO, RA-2 24-hour soak in staging before wide rollout, RA-3 rerun in staging with mTLS/SASL/L2) are written as **proposed decisions** and await sign-off by the risk owner. This AC is checked after sign-off.)*

## Decisions
- **Harness:** `deploy/nfr/` contains Docker Compose built from the repo's service images (gateway + OPA sidecar with a signed bundle and `persist`, Kafka, karapace, Redis, OpenSearch, event-ingest, detection-svc, mock provider), one Go tool `deploy/nfr/nfr` (mock, bundle file server, bundle builder, open/closed loop load generator, event → OpenSearch latency, file scan timing), and the scripts `run.sh`, `measure.sh`, `opa-bench.sh`, `chaos.sh`, `soak.sh`, `dr.sh`, `timing-tests.sh`. Test pod = gateway 3 vCPU + OPA 1 vCPU (4 vCPU §13.1). Only dev flags already provided by the services are used.
- **Overhead** is measured as the difference for the same load through the gateway vs directly to the mock. Policy propagation and the kill switch use the tests that already measure them (`TestPropagation`, `TestKillSwitchPropagation`, `mcpgw TestKillSwitch`), rerun on a quiet host.
- **Event topic** is created by the platform in production. The harness creates it (3 partitions) because without the topic every `Emit` waits 2 seconds in the request path. This finding leads to ticket 46.
- Status `needs-signoff` because the proposals RA-1..3 need a human decision. No risk has been accepted on behalf of the risk owner.

## Local verification results (2026-10-10)
Host 16 vCPU / 15 GB, the only heavy load. Summary (details in the report):
- Overhead at 20 RPS: 1K tok p95 +19.6 ms / p99 +22.5 ms; 8K tok p95 +22.2 ms / p99 +24.9 ms ✅. Streaming +17.7 ms per 20-chunk answer ✅.
- OPA `opa bench` 1 vCPU p99 9.0 ms ❌. Healthy pod throughput 60 RPS (split manifest) / 100 RPS (OPA 3 vCPU) vs 300 ❌.
- File scan 5 MB p95 0.38 s, 49 MB 0.37 s ✅*, but only the first 2 MiB of text is examined (ticket 50).
- Policy propagation p99 15.2 s ✅. Kill switch 1.19 s ✅. Event → OpenSearch p95 4.8 s ✅.
- Chaos: OPA down and bundle cache per §13.3 ✅. Kafka down: gateway stops serving ❌. Redis down: p95 416 ms ❌. detection-svc not in the PEP path ❌.
- Soak 30 minutes at 50 RPS: 0 errors, p95 stable at 22–25 ms, memory stable ✅ (shortened).
- DR (`dr.sh`): Postgres PITR from MinIO (WAL + base backup), RPO 45.2 s ✅, RTO 20.9 s ✅ (small DB; repeat at the DRC with production size). Audit WORM bucket: delete rejected, restored from the replica in 6.8 s, contents identical, retention applied ✅.
- New Go (`deploy/nfr/nfr`): gofmt, `go vet`, golangci-lint v2.5.0 clean.

## Remaining
- Sign-off of RA-1..3 (see report §6).
- 24-hour soak: `DURATION=24h deploy/nfr/soak.sh` in staging.
- Rerun `measure.sh`/`chaos.sh` in Kubernetes staging with mTLS, SASL/TLS, NetworkPolicy, and the L2 model installed.
- The event path to SIEM (siem-export) and files via Tika are not yet measured.
- After tickets 46–51 are done, rerun the gate.
