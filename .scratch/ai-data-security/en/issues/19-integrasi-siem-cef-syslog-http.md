<!-- source-sha256: c0debfb544571eb1 -->
# 19: SIEM integration (CEF/syslog, HTTP)

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 15
Spec: `../spec.md` §11; §12.3 Security telemetry

## Context
The bank's SOC works from its existing SIEM.

## Scope
- Export events and incidents to CEF/syslog and HTTP (HEC/Sentinel/Elastic).
- Platform security telemetry: policy changes, unmask, kill switch, and bundle signature failures.
- Retry + dead-letter queue.

## Acceptance criteria
- [ ] Integration test with at least 1 bank target SIEM. *(Local: `siem-export` image → **syslog-ng 4.8 over TLS** (the standard collector in front of QRadar/ArcSight), RFC 5424 + CEF parsed, 4/4 records received: block event, allow event risk 50, unmask audit, bundle signature alert; allow event risk 10 filtered. The bank's target SIEM is not yet known: rerun against the bank's SIEM in staging.)*
- [x] No raw content in the export payload. *(Records are built from a field allowlist, snippets are not exported, free text (e.g. unmask justification) is masked if it contains NIK/PAN digit runs, forbidden keys in the audit target are replaced with `[REDACTED]`, and `Record.Check` rejects (→ DLQ) anything that still looks like content. Unit-tested for CEF, HEC, and JSON; e2e: 0 NIK/snippet matches in the syslog-ng output.)*

## Decisions
- New `siem-export` service with three sources: decision events from Kafka (only non-allow or risk ≥ `SIEM_MIN_RISK`, default 40), **audit log tail** (cursor in Postgres, one replica holds the cursor via `FOR UPDATE SKIP LOCKED`), and the Alertmanager webhook (bearer token). The audit log already contains policy changes, unmask, role changes, break-glass, incident transitions; this ticket adds `incident.open` and `incident.escalate`. The kill switch follows (ticket 30) through the same audit path.
- Bundle signature failures come from OPA metrics, so they are sent via Alertmanager → `siem-export` (`POST /alertmanager`).
- Sinks: CEF over syslog RFC 5424, TLS, octet-counting RFC 6587/5425 (in syslog-ng: the `syslog()` driver, not `network()`); HTTP Splunk HEC or JSON array (Logstash/Elastic HTTP input, Sentinel DCR). 2xx is delivered, 4xx (except 408/429) is permanent.
- Exponential retry (6 attempts, starting at 1 s), then DLQ topic `wantimpres26.siem.dlq.v1` (the already-sanitized record + sink + reason). The offset/cursor only advances after delivery or after landing in the DLQ; if the DLQ fails, it does not advance.
- CEF severity: event = risk/10; audit: break-glass and denial 9, unmask/role/publish/incident 7; alerts from the severity label. `externalId` is stable so the SIEM can drop duplicates after retries. The audit entry hash is included, so the copy in the SIEM can be matched against the chain.
- Metrics: `siem_records_sent_total`, `siem_send_retries_total`, `siem_records_dead_lettered_total`, `siem_audit_cursor`, `siem_audit_lag` + alert.

## Local verification results (2026-10-03)
- Unit (CEF escaping, framing, no-raw-content, retry/DLQ, HTTP sink, webhook, syslog TLS + reconnect + untrusted CA rejected), Postgres integration (audit tail once-per-entry with 2 replicas), entire suite with `-race`; golangci-lint clean.
- E2E as above. Finding: with the wrong syslog-ng driver (`network()`), 4 records were "delivered" without error but not processed: syslog TCP has no application-level ack.

## Remaining / follow-up
- Test against the bank's SIEM (QRadar/Splunk/Sentinel/Elastic) in staging; confirm format (CEF vs JSON) and field mapping with the SOC team.
- Syslog without ack: consider RELP or an HTTP sink if the SIEM must confirm receipt.
- The Sentinel Logs Ingestion API needs an AAD token (not yet); DLQ replay is still manual.
- TLS client certificate (mTLS) to the collector if required.
