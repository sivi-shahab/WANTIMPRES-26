<!-- source-sha256: 607270c6bfe07bf6 -->
# 47: PDP optimization: OPA eval p99 and gateway throughput per pod

Status: needs-signoff
Type: task
Priority: P1
Milestone: M1
Blocked by: -
Spec: `../spec.md` §13.1 (OPA eval p99 ≤ 5 ms; gateway throughput per 4 vCPU pod ≥ 300 RPS); finding from ticket 21 (`docs/nfr/m1-report.md`)

## Context
Results of ticket 21 (default bundle, typical gateway input):
- `opa bench` on 1 vCPU: median 3.2 ms, p95 7.8 ms, **p99 9.0 ms** (target 5 ms).
- A single pod (gateway 3 vCPU + OPA 1 vCPU) is healthy up to 60 RPS; at 80 RPS p99 is 171 ms, at 100 RPS it collapses (503 because of PDP timeout). OPA is at 100% CPU, the gateway only ~60%. With OPA 3 vCPU + gateway 1 vCPU, the pod is healthy at 100 RPS and tops out at ~225 RPS with latency > 1 second. **The 300 RPS target is not reached.**
- Top of the profile: `decision.rego:27` (`json.match_schema` over the input on every decision), then rule matching at `decision.rego:62-64`, then `risk.rego:58`. Each gateway request needs 2 decisions (request and response).

## Scope
- Validate the input schema in the PEP (Go, once) or use a schema compiled once, rather than `json.match_schema` per decision. The PDP still fails closed for invalid input.
- Index rules by `channel`/`direction`, or pre-filter, so that not all rules are evaluated.
- Consider a single decision for a clean response (no findings) if policy allows.
- Remeasure with `deploy/nfr/opa-bench.sh` and `deploy/nfr/measure.sh` (ramp). Set the sidecar/gateway vCPU split in the manifest according to the results.

## Acceptance criteria
- [x] `opa bench` p99 ≤ 5 ms on 1 vCPU. *(`deploy/nfr/opa-bench.sh` over `decision.checked` from the `policysvc.Build` bundle, `GOGC=800`: median 1.65–1.70 ms, p99 **3.8–4.4 ms** in 3 runs. Before: median 3.2 ms, p99 9.0 ms.)*
- [ ] A single 4 vCPU pod ≥ 300 RPS text with p95 overhead ≤ 80 ms and p99 ≤ 200 ms. *(**Not yet.** Gateway 2 + OPA 2 vCPU, decision log enabled: within target up to **125 RPS** (p95 61 ms, p99 180 ms); 150 RPS p95 90 ms, p99 332 ms; collapses at 175 RPS. Ticket 21 measured 60 RPS on 3 + 1 without the decision log. CPU at 60 RPS: OPA 91% → 66%, gateway stays ~50%; meaning ~1.9 vCPU per 100 RPS, so 4 vCPU tops out at ~200 RPS in theory.)*

## Decisions
- **Schema validation in the PEP.** `mcpgw.OPA.Decide` validates the input with the same schema (`policy/wantimpres26/schema`, embedded, compiled once).
  - Valid input is queried against the new entrypoint `decision.checked` without `json.match_schema`.
  - Any other input still goes to `decision.result`, which validates in OPA and answers block `INPUT_SCHEMA_INVALID`. So the PDP still fails closed, and a `fail_open` app cannot slip through via an error.
  - Other callers (simulation, other PEPs later) still use `result`. OPA only listens on `127.0.0.1`.
  - `TestInputSchemaMatchesPDP` keeps Go and Rego in agreement (corpus + 20 mutations), and ensures `checked` equals `result`.
  - If the sidecar still uses the old bundle without `checked` (during rollout), `Decide` falls back to `result` (`TestDecideFallsBackToResult`).
- **The bundle is optimized at build time** (`opa build -O=1` via the `compile` package, entrypoint `checked`).
  - The rule set is already known at build time, so the loop over rules is unrolled. Saves ~17% per decision.
  - Other rules (`result`, MCP queries, kills) remain.
  - `TestOptimizedBundleDecidesAsSource` compares the bundle with the source for 289 inputs: 3 directions × 4 sanctions × 4 sensitivities × 6 class sets, plus agent.
  - The optimization level is part of the revision hash, so the sidecar does not hold on to an old bundle.
- **Decision log mask.** The `lower(forbidden)` set was previously rebuilt for every walked field. It is now computed once per decision: ~1 ms → 0.36 ms per decision. This is the biggest source of the drop in OPA CPU on the server.
- **OPA sidecar** uses `GOGC=800` and `GOMEMLIMIT=200MiB`. This lowers eval p99 from ~6 ms to ~4 ms. `GOGC=off` and `GOMAXPROCS=1` were measured and are worse.
- **Pod vCPU split:** gateway 2 + OPA 2 (previously the OPA limit was 1). At the same load, OPA uses slightly more CPU than the gateway.
- `sort_objects` (JSON marshal/unmarshal) was replaced with the built-in `sort`. `r.mode` was replaced with `object.get`, because the optimizer's type checker sees the rule data.
- **Tried and discarded:**
  - Memoizing field values per decision: slower, because it forces `agent.*` fields to be computed.
  - `value()` with per-segment dispatch: no effect.
- **Harness:** the decision log is enabled as in production. Ticket 21's numbers were without the decision log, so they were too optimistic.

## Local verification results (2026-10-11)
- `opa test policy/` 54/54.
- `go test -race ./...` with Postgres 17 and OpenSearch 2.19.3 green (including lifecycle, catalog, and agents, which use the optimized bundle through the OPA SDK).
- golangci-lint v2.5.0 0 issues. `gofmt` also tidied `cmd/mcp-gateway/main.go`, which was left over from ticket 46.
- Raw data: `deploy/nfr/results/opa-bench.txt`, `t47-ramp-gw2-opa2-*.json`, `t47-cpu-60rps.txt`.
- The host was also used by other processes (load 2–6), so ramp latency is noisy. The CPU-per-request figures are more stable.

## Remaining: 300 RPS per pod needs a decision
Per 100 RPS, the gateway uses ~0.8 vCPU (≈ 8 ms CPU per request: in-process L1, JSON, tokenization) and OPA ~1.1 vCPU (2 decisions × ~5.5 ms, with eval only ~2 ms; the rest is HTTP, JSON, and the console decision log). Options, from most impactful:
1. **Accept ~125 RPS/pod as the capacity and scale horizontally.** The ASM-2 peak is 20 RPS, so 2 pods (HA) still have 6× headroom. 100× ASM-2 ≈ 17 pods. Change the §13.1 target, or make a risk-acceptance decision.
2. **The OPA decision log to console** duplicates the `decision_event` that already goes to Kafka, and consumes ~35% of OPA CPU (measured: 76% vs 119% at 100 RPS). The options are to turn it off, or to send it in batches to a collector. This is an audit decision (FR-POL-9).
3. **A single decision for a clean response** (no classes or score). This could cut almost half the OPA load, but changes the semantics of the response event. We need to check whether any `direction: response` rule can match without findings.
4. **CPU profile of the gateway** (L1 detection per request). This is outside the PDP, a candidate for a new ticket.
