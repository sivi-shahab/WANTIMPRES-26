<!-- source-sha256: fbcdf7a35cc14765 -->
# 15: Event pipeline: Kafka schema, OpenSearch, retention

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 05
Spec: `../spec.md` §5.1 Analytics; §6 catatan; §10.2; §12.3

## Context
All PEPs write `decision_event` to a single pipeline.

## Scope
- Versioned event schema in the schema registry (metadata + HMAC hash + redacted snippet ≤ 200 characters).
- Consumer into OpenSearch (index per tenant if needed) + daily partitions + TTL (90 days hot, 400 days total).
- `trace_id` propagation from the PEP.
- Pipeline validator that rejects events containing raw content fields.

## Acceptance criteria
- [x] Event appears in search ≤ 60 s p95. *(Integration of Kafka 3.9 + Karapace + OpenSearch 2.19: p50 3.4 s, p95 5.5 s for 200 events; dominated by the 5 s `refresh_interval`. Histogram `event_index_delay_seconds` + SLO alert.)*
- [x] Privacy test: events with raw content are rejected and counted in a metric. *(`events_rejected_total{reason}`: `raw_content`, `unredacted_snippet`, `schema`, `wire_format`, `unknown_schema`; covered by unit + integration tests, none reach the index.)*
- [x] `kafka_consumer_lag` metric is available. *(Per partition from the committed group offsets, refreshed every 10 s; `/metrics` on event-ingest.)*

## Decisions
- Apache Kafka 3.9 (KRaft) + **Karapace** (Apache-2.0, Confluent API) as the schema registry. Confluent SR (community license) and Redpanda (BSL) do not meet the "standard OSS" requirement of ADR-0001.
- `internal/events` contract: JSON Schema `decision_event.v1.json` (closed: `additionalProperties: false`), subject `wantimpres26.decision_event.v1-value`, Confluent wire format. The producer (for PEPs) registers the schema, validates before sending, key = tenant_id.
- The consumer only accepts schema ids registered under our subject: loose schemas from other subjects are rejected (`unknown_schema`).
- Raw content = a forbidden field name anywhere (the same list as for logs, `internal/privacy`), or a snippet containing ≥ 12 consecutive digits (NIK/PAN not yet redacted). Rejected events are only counted and their partition/offset logged; they are not stored.
- At-least-once: offsets are committed after the OpenSearch bulk succeeds; `_id` = `event_id`, so redelivery does not create duplicates. Registry unreachable → the process restarts; it does not reject valid events.
- Daily index `wantimpres26-events-YYYY.MM.DD` (UTC), one pattern for all tenants (`tenant_id` field), `strict` mapping. ISM: hot 90 days → read-only + force-merge → delete at 400 days, automatically via `ism_template`.
- `trace_id` (W3C, 32 hex) is required in the event and indexed; the `traceparent` header waits for OTel (no valid span id yet).
- franz-go v1.21.7 / kadm v1.18.0: the latest versions need Go 1.26 (same as OPA in ticket 11).

## Local verification results (2026-10-03)
- `go test -race ./...` with all integration services (Postgres, MinIO, Kafka, Karapace, OpenSearch), golangci-lint, trivy config, gitleaks: pass.
- The `event-ingest` image runs, joins the consumer group, and `/metrics` shows lag for 3 partitions.

## Remaining / follow-up
- No PEP calls `events.Producer` yet (ticket 13 ai-gateway, 28 mcp-gateway).
- Production Kafka/Karapace/OpenSearch (TLS, SASL/mTLS, OpenSearch auth) are provisioned by the platform team; the client does not yet configure Kafka TLS/SASL.
- Warm tier on dedicated nodes (allocation) if the cluster has warm nodes; per-tenant indexes if any tier needs them.
- Consider bumping to Go 1.26 to use the latest OPA/franz-go.
- `DECISION_EVENT` in Postgres for incident/sampling events: ticket 18.
- Ticket 12 adds optional PDP input metadata fields to `decision_event` v1 and the OpenSearch mapping, for policy simulation.
