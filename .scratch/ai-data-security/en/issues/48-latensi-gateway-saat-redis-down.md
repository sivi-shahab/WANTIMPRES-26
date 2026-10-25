<!-- source-sha256: 7f8517b550a0392f -->
# 48: AI gateway latency rises ~400 ms when Redis is unavailable

Status: needs-gitlab-run
Type: bug
Priority: P2
Milestone: M2
Blocked by: -
Spec: `../spec.md` §13.1 (overhead p95 ≤ 80 ms, p99 ≤ 200 ms); §13.3; finding from ticket 21 (`docs/nfr/m1-report.md`)

## Context
Chaos in ticket 21: with Redis down, requests are still served (limits are not enforced and this is logged, per the `withinLimits` design), but p95 rises from 26 ms to **416 ms** (p99 440 ms) because every request waits for the default go-redis dial/read timeout for the rate counter and quota. There were 7,192 error log lines in 30 seconds.

Repeat on 2026-10-10 (after ticket 46, Redis-only scenario, 30 s, 30 RPS `fail_closed` app), with highly variable results:
- New code, 5 runs: 3 runs p95 0.4–0.8 s; 2 runs p95 3.3–3.8 s, p99 5–6.5 s, with **163–204 503 responses**.
- Old code (before ticket 46), 4 runs: p95 0.4–1.2 s, no 503.

A latency tail of several seconds matches the default go-redis dial timeout (5 s). The mechanism behind the 503s is not confirmed; my guess is that the PDP deadline expires behind the counter. A link to the async produce of ticket 46 also cannot be ruled out with 9 samples. Proposal: raise the priority, because Redis being down can apparently reject `fail_closed` traffic, not just slow it down.

## Scope
- A short Redis timeout (dial/read ≤ 50 ms) in `cmd/ai-gateway`, plus a circuit breaker: after N failures, skip Redis for T seconds and use a per-replica counter (`MemoryCounter`) as the degraded mode.
- Rate-limited logging and a metric `rate_counter_unavailable_total` + alert, instead of one error per request.

## Acceptance criteria
- [x] `deploy/nfr/chaos.sh` Redis scenario: overhead p95 ≤ 80 ms, p99 ≤ 200 ms while Redis is down. *(5 Redis-only runs from a clean start with warm-up: p95 17–59 ms, p99 20–149 ms. Before: p95 416 ms up to 3.8 s. Full `chaos.sh` run: p95 99 ms, p99 224 ms. The same run also showed a ~1 s tail in the scenarios without Redis (`opa cached`, `redis back`, `detection down`) because the host was being used by other processes (load 4–5; ticket 21 measured at load < 1). Needs to be reconfirmed on staging (RA-3).)*
- [x] No 503 for `fail_closed` apps while Redis is down, repeated ≥ 5 times from a clean start. *(10 of 10 runs without 503: 5 without warm-up and 5 with warm-up.)*

## Decisions
- **Redis timeout of 50 ms** for dial, read, write, and pool, with no retries (`cmd/ai-gateway`). Values in `REDIS_URL` (`dial_timeout`, `read_timeout`, `max_retries`) still win.
- **`aigw.Degraded`** wraps `RedisCounter`. When Redis fails, that request uses the per-replica `MemoryCounter`, and Redis is skipped for 5 s before being tried again. So one outage costs only one timeout per 5 s, not one per request. Limits are still enforced per replica (with N replicas, effectively N× the limit), which is better than not being enforced at all. Failures caused by the caller having already canceled the context are not counted as an outage.
- **Logging** one line per cooldown period (6 per 30 s; previously ~7,000). Metric `aigw_rate_counter_unavailable_total`, alert `AIGatewayRateCounterDegraded` (warning).
- **Breaker without an N-failure threshold:** a single failure opens the breaker immediately. With a 5 s cooldown, a Redis that stutters once only causes local limits for 5 s, so a threshold is unnecessary.
- **Harness finding:** right after `run.sh up`, with no disruption at all, the gateway can give p95 1.4 s and 503s (OPA and the JVM are still cold). The 503s recorded in ticket 46 almost certainly come from this, not from the async produce. `run.sh up` now waits until the `fail_closed` app gets a 200, then applies 15 s of load for warm-up.

## Local verification results (2026-10-11)
- `go vet ./...`, golangci-lint v2.5.0 0 issues, `go test -race ./internal/aigw` green (including `TestDegradedCounter`).
- The ticket 21 harness as above. `results/chaos-*` updated from the full run of 2026-10-11.

## Remaining
- Confirm the numbers on staging with a host that is not shared (RA-3).
- If the per-replica limit during an outage is too loose for certain apps, the option is to reject (fail closed) for that app. Currently the limit is an availability control, not a data control, per the `withinLimits` design.
