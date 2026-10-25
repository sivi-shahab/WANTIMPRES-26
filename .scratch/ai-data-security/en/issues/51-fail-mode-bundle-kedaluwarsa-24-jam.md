<!-- source-sha256: 104a69c2f784837e -->
# 51: Fail mode when the policy bundle has expired for > 24 hours

Status: needs-triage
Type: task
Priority: P2
Milestone: M2
Blocked by: -
Spec: `../spec.md` §13.3 ("Jika bundle kedaluwarsa > 24 jam, PEP masuk mode fail-mode policy"); finding from ticket 21 (`docs/nfr/m1-report.md`)

## Context
Chaos in ticket 21 proved the first part of §13.3: an OPA restarted while the Policy Service is down serves again within 1 second from the stored bundle (`persist: true`). The second part does not exist yet. No PEP code (`internal/aigw`, `internal/mcpgw`) or OPA configuration checks the age of the active bundle, so a PEP can keep enforcing an old policy indefinitely when the Policy Service cannot be reached.

## Scope
- The PEP reads the age of the last bundle activation (OPA status API `/health?bundles` or `/v1/status` → `last_successful_activation`, or the metric `bundle_loaded_timestamp`). More than 24 hours is treated like the PDP being unavailable (`fail_closed`/`fail_open` per app) plus a metric and alert `policy_bundle_stale`.
- An earlier alert (e.g. > 1 hour without a new activation) in `deploy/cluster/alerts.yaml`.

## Acceptance criteria
- [ ] Test: a bundle whose last activation was > 24 hours ago makes `fail_closed` apps reject and `fail_open` apps forward with `fail_open_total`.
- [ ] A stale bundle alert with a metric test.
