<!-- source-sha256: 2a582f1cb7df4e7f -->
# 42: PostgreSQL RLS per tenant (ADR-0001 U11)

Status: needs-gitlab-run
Type: task
Priority: P2
Milestone: M2
Spec: `../spec.md` §10.1 Tenant isolation; `docs/adr/0001-hosting-residency-build-scope.md` U11; `docs/threat-model.md` G3

## Context
ADR-0001 U11 establishes `tenant_id` + RLS on all tables as defense-in-depth. Currently there is not a single RLS policy; isolation depends on the filter in every query, and `authz.Caller` does not carry a tenant.

## Scope
- Decide: apply RLS (`SET app.tenant_id` per transaction + a policy per table), or amend the ADR if single-tenant is considered sufficient.
- If applied: an application DB role without `BYPASSRLS`; an automated test that a query without tenant context returns no rows.

## Acceptance criteria
- [x] The decision is recorded (a new ADR or an amendment to U11). *(`docs/adr/0003-rls-postgresql-per-tenant.md`. U11 in ADR-0001 was given an amendment note.)*
- [x] If RLS: an isolation test for every schema that has `tenant_id`. *(`internal/tenantdb` `TestRowLevelSecurity`, using an application role `NOSUPERUSER NOBYPASSRLS` that owns the tables. Schemas tested: `incident`, `riskcal`, `similarity`, `tokvault`, `tuning`. Structure: every table with `tenant_id`, and every table with a foreign key to such a table, must have RLS + FORCE + a `tenant` policy with the correct expression. A new table that forgets isolation makes the test fail; `audit.audit_log` is excluded for a written reason. Behavior, for 16 tables: without a tenant 0 rows; as tenant A only its own 1 row, no rows of other tenants; insert/update into tenant B is rejected with "row-level security"; update/delete of B's rows hits 0 rows; `tenantdb.Pool` rejects a superuser unless `DATABASE_ALLOW_BYPASSRLS=true`, and also rejects an invalid tenant id.)*

## Decisions
- **RLS on per-tenant data** (ADR-0003). There are 10 tables with `tenant_id` (`incident.incidents`, `incident.blocks`, `riskcal.versions`, `similarity.docs`, `tokvault.keys`, `tokvault.tokens`, `tuning.optin/labels/models/holdout`) with the policy `tenant_id = current_setting('app.tenant_id', true)::uuid` (USING + WITH CHECK). Six incident child tables (`incident_events`, `evidence`, `transitions`, `actions`, `tickets`, `unmask_requests`) use a policy through their parent. All are `ENABLE` + `FORCE`, installed idempotently by `tenantdb.Isolate`/`IsolateChild` in each module's `Open`. The DDL runs only if it does not already exist, with an advisory lock for replicas that start at the same time.
- **The tenant is pinned per connection** via the startup parameter `app.tenant_id` in `tenantdb.Pool`, used by control-plane, token-vault, connector-worker, and detection-svc. One process serves one tenant (`TENANT_ID`). Without the setting: fail closed (0 rows). Superuser/`BYPASSRLS` is rejected except for development. The event consumer in control-plane drops other tenants' events (`events.OnlyTenant`), because otherwise an insert rejected by RLS would halt the consumer.
- **Configuration tables without `tenant_id` (~30) are unchanged:** their tenant boundary is the database (one deployment = one bank). Review trigger: a subsidiary starts using the same database.
- **`audit.audit_log` is outside RLS:** a single hash chain across tenants that is read in full by verification, the WORM anchor, and the SIEM tail. It remains append-only, and is read through `audit.read`.
- siem-export (audit log only) and `audit.Open` are unchanged.

## Local verification results (2026-10-10)
- `TestRowLevelSecurity` and `TestOnlyTenant` green. `go vet ./...`: clean. golangci-lint v2.5.0: 0 issues.
- `go test -race ./...` with Postgres 17 + OpenSearch 2.19.3: all packages green except `mcpgw.TestKillSwitch` (timing, session cut off at 2.9–3.9 seconds against a 2-second limit). That test does not use the database or the packages changed by this ticket, and the host was at load ~16–23 from parallel work. Same as reported in tickets 41, 44, and 45. It needs to be run on a quiet host or CI.
- Other tests that connect as a superuser still run because a superuser bypasses RLS. In production, the application role must be `NOSUPERUSER NOBYPASSRLS`; `tenantdb.Pool` refuses to start otherwise.

## Remaining
- Separate the owner/migration role (DDL) from the application role (DML only). Currently the application owns the tables, so with SQL injection it could in theory run `ALTER TABLE … NO FORCE ROW LEVEL SECURITY`.
- Provisioning the application role (`NOSUPERUSER NOBYPASSRLS`) in Patroni is recorded in the deploy runbook by the platform team.
- If a process serves multiple tenants: `set_config` per transaction (marked `ponytail:` in `tenantdb.Pool`).
