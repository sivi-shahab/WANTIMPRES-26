---
title: Security
outline: [2, 3]
---

# Security Policy

WANTIMPRES-26 is a security platform, so a vulnerability in it can directly affect customer data and company secrets. We greatly value reports made responsibly.

## Reporting a vulnerability

::: danger Do not report publicly
Do not report vulnerabilities through GitHub issues, pull requests, tickets in `.scratch/`, or any other public forum.
:::

Report privately through GitHub's **private vulnerability reporting**:

1. Open the [repository's Security tab](https://github.com/sivi-shahab/WANTIMPRES-26/security).
2. Click **Report a vulnerability**, or go straight to the [report form](https://github.com/sivi-shahab/WANTIMPRES-26/security/advisories/new).
3. The report is visible only to you and the maintainers.

To help us act quickly, include:

- **The affected component**, for example `ai-gateway`, `mcp-gateway`, `control-plane`, a Rego policy, or a deploy manifest, and the commit you tested.
- **Reproduction steps** that can be repeated, including the configuration used.
- **Impact**: what an attacker could achieve, such as bypassing policy, leaking content, breaking tenant isolation, or damaging audit log integrity.
- **A minimal proof of concept.** Do not include personal data or real customer data.

### Research guidelines

- Test in your own environment, such as the [local stack](./install#run-the-local-stack). Do not test someone else's deployment without written permission.
- Do not access, modify, or keep more data than needed to demonstrate the issue.
- No denial-of-service attacks, social engineering, or physical access.
- Give us time to fix the issue before its details are published.

## After a report arrives

1. **Acknowledgement:** a maintainer confirms the report was received and follows up in the same advisory thread.
2. **Triage:** impact is rated with the same scale as the [threat model](../../threat-model). *High* means large-scale customer data leakage, bypassable enforcement, or broken audit/policy integrity.
3. **Fix:** the fix is developed privately and tested through the same pipeline as any other change.
4. **Coordinated disclosure:** once a fix is available, the details are published as a GitHub Security Advisory (with a CVE where relevant), and the reporter is credited if they wish.

## Supported versions

The current release is `v0.1.0`, a preview. Security fixes go to the `main` branch and ship in the next release; there are no backports to older releases yet.

| Version | Supported |
|---|---|
| `main` (latest) | Yes |
| Latest release (`v0.1.0`) | Yes, through the next release |
| Older commits or forks | No |

## Scope

**In scope:**

- Service code in `cmd/`, `internal/`, and `services/`.
- Policies in `policy/`, including ways to bypass decisions or forge bundles.
- Deploy manifests and configuration in `deploy/`, when used as described in the installation guide.
- CI/CD workflows in `.github/` and `.gitlab-ci.yml`.

**Out of scope:**

- Vulnerabilities in third-party dependencies that cannot be exploited through WANTIMPRES-26; report them to the upstream project.
- Deployments that deviate from the recommended configuration, for example without mTLS or with `MTLS_INSECURE`.
- Volumetric attacks (DoS), social engineering, and physical access.
- The [known limitations](#known-limitations) below.

## Platform security controls

A summary of the main controls. The full per-component analysis (STRIDE, OWASP LLM Top 10, and OWASP Agentic Top 10) is in the [threat model](../../threat-model).

| Area | Control |
|---|---|
| Service-to-service identity | mTLS with short-lived SPIFFE identities; default-deny NetworkPolicy |
| Admin identity | OIDC with MFA through Keycloak; fresh login and justification for sensitive permissions; audited break-glass accounts |
| Policy integrity | Bundles signed through Vault Transit (the private key never enters a pod) and verified by every OPA sidecar |
| Policy changes | Two-person rule: author and approver must differ; simulation before release; rollback |
| Data isolation | PostgreSQL row-level security per tenant |
| Privacy | No raw content in logs, traces, or events (enforced by the shared privacy test); HMAC pseudonymization |
| Incident evidence | Encrypted per incident; opened only through an *unmask* request approved by someone else |
| Audit | Append-only, hash-chained audit log with signed daily anchors in WORM object storage |
| Agents | Token exchange without passing the agent's token on, tool pinning, human approval, kill switch |
| Failure | Explicit failure mode per app (`fail_closed` by default) |

## Supply chain security

- **Signed images:** the cluster only runs images signed with cosign (a Kyverno policy). Every image ships with an SBOM.
- **Scanning on every change:** Semgrep (SAST), Trivy (vulnerabilities, licences, IaC), and gitleaks over the full git history.
- **Scanner exceptions** must be reviewed, justified, and limited to a specific path or line (`.trivyignore.yaml`, `nosemgrep: … -- reason`).
- **GitHub Actions** are pinned to commit SHAs.
- **The GitHub repository** has secret scanning and push protection enabled.
- **Detection models** are pinned by sha256 in `MODELS.json`, and external feeds have their signatures verified.

## Known limitations

These are already tracked and being worked on, so there is no need to report them as new findings:

- L2 detection runs in *shadow mode* only; decisions still come from L1 detection ([ticket 49](../tickets/49-detection-l2-di-jalur-pep)).
- File scanning inspects only the first 2 MiB of text ([ticket 50](../tickets/50-scan-file-hanya-2mib-teks-pertama)).
- The failure mode for a policy bundle older than 24 hours is not implemented ([ticket 51](../tickets/51-fail-mode-bundle-kedaluwarsa-24-jam)).
- While Redis is unavailable, rate limits and token quotas are not enforced.

The latest list is on the [Roadmap](./roadmap) and in the [Ticket Overview](../tickets/).
