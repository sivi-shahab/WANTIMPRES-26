<!-- source-sha256: eee9b84254558769 -->
# 41: Kafka/OpenSearch: TLS, SASL/mTLS client, per-producer topic ACLs

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M2
Blocked by: 15
Spec: `../spec.md` §10.1 Encryption; `docs/threat-model.md` G2

## Context
Threat model (ticket 02) G2: the Kafka clients do not yet configure TLS/SASL (note on ticket 15). Anyone on the network can produce fake decision events (fake incidents, or a flood to mask an attack) or read events. OpenSearch is not yet authenticated from the clients.

## Scope
- Configure TLS + SASL (SCRAM or mTLS) in the producers/consumers (`internal/events`, event-ingest, incident, siem-export).
- Topic ACLs: only PEPs may produce to `decision_event`, one consumer per group.
- OpenSearch client with TLS + auth.

## Acceptance criteria
- [x] A producer without credentials is rejected by the broker (integration test). *(`TestBrokerACLs` against a real Kafka 3.9 (SASL listener + `StandardAuthorizer`): a client without SASL and a client with a wrong password fail to produce, and the topic contains only records from PEPs.)*
- [x] An event from a non-PEP principal is rejected or flagged. *(Rejected by the broker. In the same test, the authenticated `siem-export` account (SCRAM-SHA-512, with only a consume grant) is rejected with `CLUSTER_AUTHORIZATION_FAILED`: an idempotent producer without topic WRITE already fails at InitProducerID, before reaching the topic. The production grant list is in `cmd/event-ingest` (`grants`): only `ai-gateway` and `mcp-gateway` may produce to `wantimpres26.decision_event.v1`.)*
- [x] A plaintext connection to Kafka/OpenSearch fails in the production configuration. *(The default is TLS. `events.KafkaOpts` rejects a configuration without a client identity and always uses TLS unless `KAFKA_PLAINTEXT=true`. `ingest.OpenSearchFromEnv` rejects `http://` and a configuration without user/password unless `OPENSEARCH_PLAINTEXT=true`. `TestKafkaTLSVerifiesBroker` and `TestOpenSearchFromEnv`: the server certificate is verified against the configured CA, and another CA is rejected.)*

## Decisions
- **One connection function per backend:** `events.KafkaOpts(os.Getenv)` is used by all Kafka services (ai-gateway, mcp-gateway, control-plane, event-ingest, siem-export). It configures TLS 1.2+ (`KAFKA_CA_FILE`), SASL `SCRAM-SHA-512` (default) or `PLAIN` (`KAFKA_SASL_USER` + `KAFKA_SASL_PASSWORD_FILE`), and/or a client mTLS certificate (`KAFKA_CERT_FILE`/`KAFKA_KEY_FILE`). `ingest.OpenSearchFromEnv` is used by event-ingest and control-plane (https, basic auth, `OPENSEARCH_CA_FILE`). The plaintext opt-out is allowed only for local/CI and must be explicit (`*_PLAINTEXT=true`).
- **ACLs as data:** `events.Grant` + `events.ApplyACLs` (kadm, idempotent). `event-ingest kafka-acls` is run once as a Job with broker admin credentials. The broker must use an authorizer without `allow.everyone.if.no.acl.found`, so anything not granted is rejected. Principal = the per-service SASL user (the service name).
- **Deploy:** each Kafka service uses `KAFKA_SASL_USER` = the service name, and the CA/password files come from the Secret `<service>-bus` mounted at `/bus`.
- `events.NewProducer` now accepts connection options (including brokers) from the caller. `DLQTopic` moved to `siem.DLQTopic` so it can be referenced by the grants.
- **CI:** the Kafka broker gets a `SASL` listener (:9094, PLAIN for admin + SCRAM-SHA-512) and `StandardAuthorizer`. The PLAINTEXT listener remains for the old pipeline tests (ANONYMOUS = super user, CI only). New variables: `IT_KAFKA_SASL_BROKERS`, `IT_KAFKA_ADMIN_PASSWORD`.

## Local verification results (2026-10-10)
- Kafka 3.9.0 broker configured exactly like `.gitlab-ci.yml` (+ karapace, OpenSearch 2.19.3): `go vet ./...` clean, and `go test -race ./...` with all IT_* env vars green, including `TestPipelineIntegration` (ingest) against a broker whose authorizer is active. golangci-lint v2.5.0: 0 issues.
- When the full suite ran concurrently with other work (load average ~35 on 16 cores), `mcpgw TestKillSwitch` (2-second budget) and two Rego tests (evaluation deadline) failed because of timeouts. Those packages were not touched. On rerun: `policysvc` green, and `TestKillSwitch` alone passes (1.95 seconds).

## Remaining
- TLS to the *real* broker and OpenSearch is only tested through a local TLS stand-in (CA verification on the client side). A real SSL/HTTPS listener in CI needs certificates that cannot be injected into the GitLab services. It needs testing on staging with the bank's CA.
- The schema registry (karapace) is still without TLS/auth from the client (`sr.NewClient` takes only a URL). This is outside this ticket's scope, but a fake registry could corrupt decoding. A follow-up ticket is needed.
- Kafka and OpenSearch themselves (TLS listeners, SCRAM users, security plugin roles, the `kafka-acls` Job) are managed by the platform team. The repo only provides the client side, the grant list, and the expected Secrets.
