<!-- source-sha256: b9da08d04d99180f -->
# 46: AI gateway stops serving when Kafka is unavailable

Status: needs-gitlab-run
Type: bug
Priority: P0
Milestone: M1
Blocked by: -
Spec: `../spec.md` §13.1 data plane availability 99.95%; §13.3; finding from ticket 21 (`docs/nfr/m1-report.md`)

## Context
Chaos in ticket 21: when the Kafka broker is shut down, **all** requests through the AI gateway, for `fail_open` and `fail_closed` apps alike, do not complete within 30 seconds (client timeout). Requests only complete after Kafka is back up. `Emit` (`cmd/ai-gateway/main.go`) calls `Producer.Publish` (`kgo.ProduceSync`) synchronously in the request path with a 2-second context. However, franz-go does not cancel records that are already buffered or in flight when the context expires, so the request waits until the record delivery timeout. The `context deadline exceeded` error is only logged after the broker comes back. A disruption in the event bus becomes a data plane disruption.

## Scope
- Decouple event delivery from the request path: async produce (`kc.Produce` + callback) with a bounded buffer and a short `kgo.RecordDeliveryTimeout`/`ProduceRequestTimeout`. Failed events are recorded in a metric (`decision_events_dropped_total`) and an alert, or spooled to local disk for replay.
- Also applies to the MCP gateway (the same `emit` pattern).
- Add a chaos test: broker down → gateway p99 stays within target and the lost events are counted.

## Acceptance criteria
- [x] With Kafka down, requests through the gateway still complete (p99 overhead ≤ 200 ms) and events that are not delivered are counted in a metric and an alert. *(Chaos 30 s, 30 RPS per app: 899/899 200 for `fail_closed` and `fail_open`, p95 20 ms, p99 25 ms (total, the mock provider answers instantly). `decision_events_dropped_total` +3,592, about 2 events per request × 1,798 requests. Alert `DecisionEventsDropped` (critical, security) in `deploy/cluster/alerts.yaml`. Unit test `TestPublishKafkaDown`: broker down, 3 Publish calls < 100 ms, all three counted (2 rejected because the buffer was full, 1 after the delivery timeout), an event that violates the schema is still rejected synchronously.)*
- [x] The Kafka scenario in `deploy/nfr/chaos.sh` is green. *(`results/chaos-summary.txt` 2026-10-10; the scenario now prints the difference in `decision_events_dropped_total`.)*

## Decisions
- **The root cause is fixed in `events.Producer.Publish`**, the only produce path for both gateways: schema validation remains synchronous, then `TryProduce` to the client buffer and return immediately, never waiting for Kafka. The record's context is `Background`, because the request context ends together with the response, long before the record is delivered.
- **Limits:** `MaxBufferedRecords` 10,000 (about 8 minutes at the ASM-2 peak of 20 RPS × 2 events, tens of MB) and `RecordDeliveryTimeout` 30 s. Older records fail, and new ones are rejected when the buffer is full. Both go into `decision_events_dropped_total`. Kafka options from env can still override.
- **No disk spool.** The metric and alert flag the audit trail gap. A local spool for replay will only be built if Kafka outages longer than the buffer turn out to be frequent.
- **Metric:** ai-gateway adds it to its own `/metrics` (`Gateway.Metrics`). mcp-gateway did not have a `/metrics` before, so it now uses `Producer.ServeMetrics`.
- `Close` flushes the buffer (max 5 s) before disconnecting, so events are not lost on a normal shutdown.
- **NFR harness fixed:**
  - The karapace image healthcheck needs `KARAPACE_ADVERTISED_PROTOCOL`, which is now set.
  - The gateway exited until karapace had a primary, so OPA (which shares a network namespace with the gateway) got stuck in a dead namespace. `run.sh up` now recreates OPA after the gateway is serving.

## Local verification results (2026-10-10)
- `go build`, `go vet`, golangci-lint v2.5.0 0 issues. `go test -race` for `events`, `aigw`, `mcpgw` green, and `ingest` (Kafka + OpenSearch) green.
- Full chaos on the ticket 21 harness: all scenarios the same as before, except Kafka, which is now green. Redis down shows large variation, with 503s in 2 of 5 runs of the new code and none in 4 runs of the old code. Ticket 48 later found that a freshly started harness gives 503s even without any disruption (cold OPA/JVM), so those 503s almost certainly are not a result of this change.

## Remaining
- The MCP gateway has no chaos scenario in the harness. Its behavior follows the same producer and is tested in unit tests.
- A Prometheus scrape of the gateway `/metrics` (ServiceMonitor/PodMonitor) does not exist yet in `deploy/`, same as the other gateway metrics. The new alert only becomes active once the scrape is installed.
