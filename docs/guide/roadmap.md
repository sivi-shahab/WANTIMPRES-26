---
title: Roadmap
outline: [2, 3]
---

<script setup>
import { data as tickets } from '../tickets/tickets.data'

const milestones = [
  { id: 'M0', title: 'M0 · Discovery & baseline', estimate: '12 pw', scope: 'Keputusan hosting dan cakupan build, threat model, baseline shadow AI dari log, eval corpus awal.' },
  { id: 'M1', title: 'M1 · MVP (P0)', estimate: '110 pw', scope: 'AI gateway dengan streaming, deteksi L1/L2, OPA dan siklus kebijakan, katalog, event, insiden, posture, identitas, audit log, SIEM, gate NFR.' },
  { id: 'M2', title: 'M2 · P1-a', estimate: '70 pw', scope: 'Tokenisasi, risk scoring dan kalibrasinya, korelasi insiden dengan breach timer, SOAR/ITSM, DPIA. Browser extension dan adapter ICAP ditunda (ADR-0001).' },
  { id: 'M3', title: 'M3 · P1-b', estimate: '85 pw', scope: 'MCP gateway, agent registry, persetujuan manusia, kill switch, connector M365/Google/cloud, remediation, modul compliance.' },
  { id: 'M4', title: 'M4 · P2', estimate: '90 pw', scope: 'Similarity dokumen rahasia, classifier per tenant, analitik perilaku agent. Endpoint agent ditunda.' },
]

const statusLabels = {
  'done': 'selesai',
  'needs-gitlab-run': 'terimplementasi, menunggu pipeline GitLab',
  'needs-signoff': 'menunggu sign-off',
  'needs-triage': 'belum dikerjakan',
  'deferred': 'ditunda',
}
</script>

# Roadmap

Roadmap WANTIMPRES-26 dibagi ke lima milestone, M0 sampai M4. Rencana dan estimasinya berasal dari [§16 spesifikasi](../spec#_16-roadmap-estimasi). Progres di bawah dihitung langsung dari status [tiket](../tickets/) setiap kali situs di-build, jadi selalu sesuai kondisi terakhir.

## Arti status

| Status | Arti |
|---|---|
| `done` | Selesai dan diterima. |
| `needs-gitlab-run` | Sudah diimplementasikan dan diuji di lokal; tinggal dijalankan di pipeline rilis GitLab. |
| `needs-signoff` | Pekerjaan selesai, menunggu persetujuan pihak berwenang (misalnya CISO, arsitek keamanan, atau DPO). |
| `needs-triage` | Temuan atau pekerjaan baru yang belum dikerjakan. |
| `deferred` | Sengaja ditunda, dengan alasan tercatat di tiketnya. |

## Progres per milestone

<RoadmapProgress
  :tickets="tickets"
  :milestones="milestones"
  :status-labels="statusLabels"
  ticket-base="/tickets/"
  :labels="{ done: 'sudah dikerjakan', open: 'Tiket yang masih terbuka', tickets: 'tiket', estimate: 'estimasi awal' }"
/>

"Sudah dikerjakan" mencakup status `done`, `needs-gitlab-run`, dan `needs-signoff`.

## Keputusan yang ditunggu

Beberapa langkah berikutnya bergantung pada keputusan, bukan pada pekerjaan engineering:

| Keputusan | Pemilik | Tiket |
|---|---|---|
| Sign-off threat model platform | CISO / arsitek keamanan | [02](../tickets/02-threat-model-platform-stride-owasp-llm-asi) |
| Sign-off eval corpus dan guideline labeling | Tim deteksi / compliance | [04](../tickets/04-eval-corpus-v1-labeling-guideline) |
| Sign-off gate NFR M1, termasuk usulan RA-1 sampai RA-3 (availability, soak 24 jam, pengukuran ulang dengan mTLS) | CISO / platform | [21](../tickets/21-nfr-gate-m1-load-soak-chaos-dr) |
| Sign-off DPIA sebelum rollout pemantauan inline | DPO / Legal / HR | [35](../tickets/35-dpia-komunikasi-ke-karyawan-sebelum-rollout-inline) |
| Target throughput per pod: terima 125 RPS dengan lebih banyak replika, atau optimasi lanjut ke 300 RPS | Platform / arsitek | [47](../tickets/47-optimasi-pdp-throughput-per-pod) |
| Inventaris vendor SWG/CASB/DLP (ASM-5), untuk mengevaluasi ulang browser extension, adapter ICAP, dan endpoint agent | Infra / procurement | [01](../tickets/01-keputusan-hosting-data-residency-build-vs-buy), [22](../tickets/22-browser-extension-prompt-paste-upload-coaching), [23](../tickets/23-web-proxy-adapter-icap-reqmod-respmod), [36](../tickets/36-endpoint-agent-windows-macos) |

## Pekerjaan berikutnya

Temuan dari gate NFR M1 yang belum dikerjakan:

- **[Tiket 49](../tickets/49-detection-l2-di-jalur-pep):** menjadikan deteksi L2 ikut menentukan keputusan di jalur gateway, dengan timeout 150 ms dan fallback ke L1. Saat ini L2 berjalan dalam *shadow mode*.
- **[Tiket 50](../tickets/50-scan-file-hanya-2mib-teks-pertama):** scan file baru memeriksa 2 MiB teks pertama.
- **[Tiket 51](../tickets/51-fail-mode-bundle-kedaluwarsa-24-jam):** mode gagal saat bundle kebijakan kedaluwarsa lebih dari 24 jam.

## Rencana awal

Estimasi kasar dari spec, dalam *person-weeks* (pw), dengan asumsi tim 8–10 engineer:

| Milestone | Durasi rencana | Estimasi |
|---|---|---|
| M0 Discovery & baseline | ≈ 4 minggu | 12 pw |
| M1 MVP (P0) | ≈ 16 minggu | 110 pw |
| M2 P1-a | ≈ 12 minggu | 70 pw |
| M3 P1-b | ≈ 12 minggu | 85 pw |
| M4 P2 | ≈ 16 minggu | 90 pw |
| Berkelanjutan: red team, katalog AI, refresh model, pentest | – | ≈ 1 FTE |

M2 dan M3 bisa berjalan paralel bila tim minimal 10 orang. Perubahan detail per tanggal bisa dilihat di [Changelog](../changelog).
