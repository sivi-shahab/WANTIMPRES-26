---
title: Roadmap
outline: [2, 3]
---

<script setup>
import { data as tickets } from '../tickets/tickets.data'

const milestones = [
  { id: 'M0', title: 'M0 · Discovery & baseline', estimate: '12 pw', scope: 'Hosting and build-scope decision, threat model, shadow AI baseline from logs, initial eval corpus.' },
  { id: 'M1', title: 'M1 · MVP (P0)', estimate: '110 pw', scope: 'AI gateway with streaming, L1/L2 detection, OPA and the policy lifecycle, catalog, events, incidents, posture, identity, audit log, SIEM, NFR gate.' },
  { id: 'M2', title: 'M2 · P1-a', estimate: '70 pw', scope: 'Tokenization, risk scoring and its calibration, incident correlation with the breach timer, SOAR/ITSM, DPIA. The browser extension and ICAP adapter are deferred (ADR-0001).' },
  { id: 'M3', title: 'M3 · P1-b', estimate: '85 pw', scope: 'MCP gateway, agent registry, human approval, kill switch, M365/Google/cloud connectors, remediation, compliance module.' },
  { id: 'M4', title: 'M4 · P2', estimate: '90 pw', scope: 'Confidential document similarity, per-tenant classifiers, agent behavior analytics. The endpoint agent is deferred.' },
]

const statusLabels = {
  'done': 'done',
  'needs-gitlab-run': 'implemented, awaiting the GitLab pipeline',
  'needs-signoff': 'awaiting sign-off',
  'needs-triage': 'not started',
  'deferred': 'deferred',
}
</script>

# Roadmap

The WANTIMPRES-26 roadmap has five milestones, M0 to M4. The plan and estimates come from [§16 of the specification](../spec#_16-roadmap-estimates). The progress below is computed from the [ticket](../tickets/) statuses on every site build, so it always reflects the latest state.

## What the statuses mean

| Status | Meaning |
|---|---|
| `done` | Finished and accepted. |
| `needs-gitlab-run` | Implemented and tested locally; it only needs to run in the GitLab release pipeline. |
| `needs-signoff` | Work is finished and awaits approval from the responsible party (for example the CISO, a security architect, or the DPO). |
| `needs-triage` | A new finding or piece of work that has not started. |
| `deferred` | Deliberately postponed, with the reason recorded in the ticket. |

## Progress by milestone

<RoadmapProgress
  :tickets="tickets"
  :milestones="milestones"
  :status-labels="statusLabels"
  ticket-base="/en/tickets/"
  :labels="{ done: 'worked on', open: 'Tickets still open', tickets: 'tickets', estimate: 'initial estimate' }"
/>

"Worked on" covers the `done`, `needs-gitlab-run`, and `needs-signoff` statuses.

## Decisions pending

Several next steps depend on decisions rather than engineering work:

| Decision | Owner | Ticket |
|---|---|---|
| Sign-off of the platform threat model | CISO / security architect | [02](../tickets/02-threat-model-platform-stride-owasp-llm-asi) |
| Sign-off of the eval corpus and labeling guideline | Detection team / compliance | [04](../tickets/04-eval-corpus-v1-labeling-guideline) |
| Sign-off of the M1 NFR gate, including proposals RA-1 to RA-3 (availability, 24-hour soak, re-measuring with mTLS) | CISO / platform | [21](../tickets/21-nfr-gate-m1-load-soak-chaos-dr) |
| Sign-off of the DPIA before rolling out inline monitoring | DPO / Legal / HR | [35](../tickets/35-dpia-komunikasi-ke-karyawan-sebelum-rollout-inline) |
| Throughput target per pod: accept 125 RPS with more replicas, or optimise further toward 300 RPS | Platform / architect | [47](../tickets/47-optimasi-pdp-throughput-per-pod) |
| Inventory of SWG/CASB/DLP vendors (ASM-5), to re-evaluate the browser extension, ICAP adapter, and endpoint agent | Infra / procurement | [01](../tickets/01-keputusan-hosting-data-residency-build-vs-buy), [22](../tickets/22-browser-extension-prompt-paste-upload-coaching), [23](../tickets/23-web-proxy-adapter-icap-reqmod-respmod), [36](../tickets/36-endpoint-agent-windows-macos) |

## Next work

Findings from the M1 NFR gate that have not started:

- **[Ticket 49](../tickets/49-detection-l2-di-jalur-pep):** let L2 detection take part in decisions on the gateway path, with a 150 ms timeout and fallback to L1. Today L2 runs in *shadow mode*.
- **[Ticket 50](../tickets/50-scan-file-hanya-2mib-teks-pertama):** file scanning inspects only the first 2 MiB of text.
- **[Ticket 51](../tickets/51-fail-mode-bundle-kedaluwarsa-24-jam):** the failure mode when a policy bundle is more than 24 hours old.

## Initial plan

Rough estimates from the spec, in *person-weeks* (pw), assuming a team of 8–10 engineers:

| Milestone | Planned duration | Estimate |
|---|---|---|
| M0 Discovery & baseline | ≈ 4 weeks | 12 pw |
| M1 MVP (P0) | ≈ 16 weeks | 110 pw |
| M2 P1-a | ≈ 12 weeks | 70 pw |
| M3 P1-b | ≈ 12 weeks | 85 pw |
| M4 P2 | ≈ 16 weeks | 90 pw |
| Ongoing: red team, AI catalog, model refresh, pentest | – | ≈ 1 FTE |

M2 and M3 can run in parallel with a team of at least 10. Day-by-day changes are in the [Changelog](../changelog).
