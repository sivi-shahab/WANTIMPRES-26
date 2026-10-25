<!-- source-sha256: 16b51009fa4cdd44 -->
# 06: Identity: SSO OIDC/SAML, SCIM, RBAC/ABAC

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 05
Spec: `../spec.md` §2; §10.1 AuthN/AuthZ

## Context
The admin UI/API needs identity and authorization before other features can be used.

## Scope
- OIDC/SAML login with mandatory MFA for admins.
- SCIM 2.0 for user/group provisioning.
- Built-in roles per the personas in §2 + ABAC attributes (business unit, region, sensitivity).
- Sensitive permissions (`evidence.unmask`, `policy.publish`, `agent.kill.global`) require re-auth + justification.
- Break-glass account.

## Acceptance criteria
- [x] Role × endpoint matrix test (deny by default). *(`cmd/control-plane/routes_test.go`: every registered route × 12 roles + a user without bindings + no token, via the production route table; the public surface is pinned; a route without a permission cannot be registered.)*
- [x] Every role change is recorded in the audit log (ticket 07). *(Bind/unbind, SCIM group membership (added/removed), user activation/deactivation, user and group create/delete, in the same transaction as the change.)*

## Decisions
- **ADR-0002**: Keycloak as the broker to the bank's IdP (OIDC/SAML), MFA, and break-glass. Our code only validates Keycloak access tokens (JWKS, `iss`, `aud`, `exp`, `typ=Bearer`, `acr` for MFA, `auth_time` for step-up).
- Authorization in the application: users/groups from SCIM 2.0 (`/scim/v2/Users|Groups`, own token, the subset used by Entra/Okta), roles bound to a user or group in `identity.role_bindings`, with ABAC attributes (business unit, region, sensitivity clearance) and an expiry period (time-boxed auditor). Token `preferred_username` = SCIM `userName` (case-insensitive). Inactive or unknown users have no permissions.
- Built-in roles = the personas in §2, plus `policy_approver` (4-eyes: no role can both write and publish a policy, tested) and `break_glass`.
- Sensitive permissions (`evidence.unmask`, `policy.publish`, `agent.kill.global`, `identity.admin`): login ≤ 5 minutes ago (step-up, `WWW-Authenticate: insufficient_user_authentication`), justification ≥ 10 characters, every attempt (accepted/rejected) is audited; no audit, no access.
- Break-glass: `sub` from configuration, every request is audited, metric `breakglass_requests_total` + critical alert. Break-glass cannot unmask evidence or publish policy (to keep the platform running, not for data access).
- Raw evidence moves to `GET /incidents/{id}/evidence/{eid}/raw` (permission per route); `AUTH_MODE=trusted-proxy` from ticket 18 is removed.

## Local verification results (2026-10-03)
- Unit (authz, route matrix), Postgres integration (SCIM + binding + audit, incident API with the new auth), the whole suite with `-race`; golangci-lint, trivy config clean.
- Real Keycloak 26.4: authorization-code login produces an access token with `typ=Bearer`, `aud` from the audience mapper, `acr`, `auth_time`; the verifier accepts that token and rejects ID tokens, tampered tokens, and other audiences. The password grant does not carry `auth_time` (the verifier fails closed: step-up is always rejected).

## Remaining / follow-up
- Keycloak realm as code shared with the IAM team: bank IdP federation, OTP/WebAuthn for admins, ACR → LoA mapping (the value for `OIDC_MFA_ACR`), audience mapper, break-glass account.
- ABAC is only used via `Caller.Can(perm, Resource{...})`; resources that carry business unit/region/sensitivity (apps, agents, incidents) use it when those fields are present (tickets 13, 16, 27).
- SCIM: pagination (`startIndex`/`count`), filters other than `eq`, and ETag do not exist yet; enough for basic Entra/Okta provisioning.
- Service identity (SPIFFE/mTLS) for sidecar/PEP: outside this ticket.
