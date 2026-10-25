---
title: Contributing
outline: [2, 3]
---

# Contributing

Thanks for wanting to help with WANTIMPRES-26. This page explains how work happens in the repository [github.com/sivi-shahab/WANTIMPRES-26](https://github.com/sivi-shahab/WANTIMPRES-26), from a ticket to your change being merged.

## The short version

1. **Pick or create a ticket** in `.scratch/ai-data-security/issues/` ([see the format](#tickets)).
2. **Set up your environment** following [Installation](./install#development-environment).
3. **Make the change** with its tests, following the [code standards](#code-standards).
4. **Run the local checks** ([command list](#checks-before-committing)).
5. **Commit** with a [good message](#commit-messages), then open a pull request against `main`.
6. **GitHub CI** runs lint, test, and scan. After review and merge, the official release (image build, SBOM, signing) runs in the GitLab pipeline.

## Tickets

Work is tracked as markdown files, one file per ticket, in `.scratch/ai-data-security/issues/NN-<slug>.md`. Numbers are sequential from `01`. Never combine several tickets in one file.

The top of the file holds fields that this site reads. Write them exactly like this example:

```md
# 52: Short ticket title

Status: needs-triage
Type: task
Priority: P1
Milestone: M2
Blocked by: 49, 50
Spec: `../spec.md` §9.1; §13.3

## Konteks
Why this work is needed.

## Scope
- What will be done.

## Acceptance criteria
- [ ] A condition that proves the work is done.
```

- **`Status`** is one of `needs-triage`, `needs-gitlab-run`, `needs-signoff`, `deferred`, or `done`. Their meanings are on the [Roadmap](./roadmap#what-the-statuses-mean). Roadmap progress and the ticket board are computed from this field.
- **`Blocked by`** lists other ticket numbers, separated by commas. Remove the line if there are none.
- **Discussion and history** are appended at the very bottom, under a `## Comments` heading.
- **Work results** usually go in sections such as `## Keputusan` (decisions), `## Hasil verifikasi lokal (date)` (local verification results), and `## Sisa` (remaining), so the next reader knows what has and has not been done.

Tickets are written in Bahasa Indonesia. Their English translations live in `.scratch/ai-data-security/en/issues/` ([see translations](#documentation-and-translations)).

## Code standards

- **Follow the surrounding code's style:** the same naming, comment density, and idioms as the file you are changing.
- **Go** must pass `gofmt` and `golangci-lint`. **Python** (`services/`) must pass `ruff check` and `ruff format --check`.
- **Every non-trivial piece of logic has a test.** This applies especially to policy decisions, parsers, validators, and security paths.
- **No raw content in logs, traces, or events.** The shared privacy test in `internal/privacy` runs with `go test` and fails if this rule is broken.
- **No secrets in the repository.** gitleaks checks the entire git history. Secrets are supplied at deploy time through Kubernetes Secrets or Vault.
- **Deliberate simplifications** (such as a size limit or an incomplete behavior) are marked with a `ponytail:` comment naming the limit and how to lift it, for example:
  ```go
  // ponytail: per-object ACLs (AWS legacy ACLs, GCS fine-grained) are not read.
  ```
- **Scanner exceptions must be reviewed and justified**, with the narrowest possible scope:
  - Semgrep: `// nosemgrep: <rule> -- <reason>` on the line concerned.
  - Trivy: an entry in `.trivyignore.yaml` with `paths` and a `statement`.

## Checks before committing

Run the same checks as CI:

```sh
gofmt -l .                       # must be empty
golangci-lint run ./...
go vet ./...
go test -race ./...              # includes the Rego tests and the privacy test

ruff check services
ruff format --check services
(cd services/model-inference && python -m unittest -v)
```

If you changed the documentation:

```sh
npm run docs:build               # fails on dead links
```

Integration tests need real backends (PostgreSQL, Kafka, OpenSearch, MinIO, Azurite) and are skipped locally. CI runs them for you; the variables are listed in `.gitlab-ci.yml`.

## Commit messages

- **Subject in English, imperative, short:** `Bound the AI gateway's Redis wait and fall back per replica`.
- **Reference the ticket** as `(ticket NN)` or `(tickets 09 and 40)`. These references become links in the [Changelog](../changelog) automatically.
- **The body explains why**, rather than repeating the diff: what problem is solved and what was decided.
- **One commit, one complete change.** Keep formatting fixes or refactors separate from behavior changes.

An example from the repository history (commit `e19c7de`):

```text
Publish decision events without waiting on Kafka (ticket 46)

ProduceSync in the request path did not stop at its 2 s context, so a
Kafka outage hung every gateway request. Publish now validates and hands
the record to a bounded buffer (10k records, 30 s delivery timeout);
failures count as decision_events_dropped_total, alerted as an audit
gap. Both gateways expose the counter.
```

## Changing policies

The built-in policies live in `policy/wantimpres26/`: the decision engine in `decision.rego` and the rule templates in `rules/data.json`.

- Add or update their tests. Rego tests run through `go test ./...`.
- For a new rule, consider `"mode": "monitor"` first, then check its impact with a [simulation](./how-to-use#release-cycle) before enforcing it.
- Policy changes in a running environment still go through the control-plane release cycle (draft, simulate, submit, then approval by someone else), not through a commit.

## Documentation and translations

This site is built with VitePress from the `docs/` folder. Run `npm run docs:dev` to see changes live.

- **New pages** are registered in the sidebar in `docs/.vitepress/config.mts` for both languages. Indonesian pages live in `docs/`, English pages in `docs/en/` at the same path.
- **The spec and tickets** in Bahasa Indonesia are the source of truth. After changing them, update the translation in `.scratch/ai-data-security/en/` and mark it as current:
  ```sh
  npm run docs:stamp -- .scratch/ai-data-security/en/issues/52-short-title.md
  ```
  If a translation falls behind, the build prints an `[i18n]` warning and that ticket's English page gets a banner.
- **The changelog and roadmap progress** are generated from git and ticket status, so they need no manual edits.

## Architecture decisions

Decisions that are hard to reverse, such as hosting, identity, or the data model, are recorded as ADRs in `docs/adr/NNNN-<slug>.md`. Follow the existing ADR structure: context, the decision with its rejected alternatives, review triggers, and impact on tickets. See [ADR-0001](../../adr/0001-hosting-residency-build-scope) for an example.

## Reporting vulnerabilities

Do not report security vulnerabilities through a ticket or a public issue. Contact the security team directly through internal channels, include reproduction steps and the impact, and wait for a fix before sharing details.

## Need help?

Start with the [FAQ](./faq) and the [Glossary](./glossary). For deeper technical context, read the [Specification](../spec) and the [threat model](../../threat-model).
