---
layout: home
title: Welcome

hero:
  name: WANTIMPRES-26
  text: Guardian of company data & AI
  tagline: An Enterprise AI Data Security & AI Security Posture Management platform. Every AI interaction is inspected and weighed before sensitive data is allowed through.
  image:
    src: /logo.svg
    alt: "WANTIMPRES-26 logo: a security guard inside a shield"
  actions:
    - theme: brand
      text: Installation
      link: /en/guide/install
    - theme: alt
      text: Why WANTIMPRES-26?
      link: /en/guide/why
    - theme: alt
      text: How to Use
      link: /en/guide/how-to-use

features:
  - icon: 🔭
    title: AI visibility
    details: An AI app catalog, shadow AI discovery, and an agent inventory.
    link: /en/guide/how-to-use#shadow-ai-and-data-at-rest
    linkText: Shadow AI
  - icon: 🪪
    title: Sensitive data
    details: Indonesian national IDs (NIK), tax IDs (NPWP), bank accounts, card numbers, credentials, and source code are recognised before they leave.
    link: /en/guide/how-to-use#connect-an-app-to-the-ai-gateway
    linkText: AI gateway
  - icon: 🛡️
    title: Attacks on LLMs
    details: Direct and indirect prompt injection, jailbreaks, system prompt leakage, and excessive agency.
    link: /threat-model
    linkText: Threat model (ID)
  - icon: 🤖
    title: Autonomous agents
    details: Identity, least privilege, short-lived credentials, human approval, and a kill switch.
    link: /en/guide/how-to-use#connect-an-agent-through-the-mcp-gateway
    linkText: MCP gateway
  - icon: ⚖️
    title: One policy decision point
    details: Policy decisions are separated from enforcement. Every enforcement point asks the same decision point, so one policy applies across every channel.
    link: /en/guide/how-to-use#manage-policies
    linkText: Manage policies
  - icon: 📜
    title: Compliance evidence
    details: A hash-chained audit log, control mapping, and a 72-hour data breach notification workflow.
    link: /en/guide/how-to-use#soc-and-compliance-operations
    linkText: SOC & compliance
---

## How it works

WANTIMPRES-26 does not rely on a single filter. Every enforcement point runs a closed loop: capture the interaction, recognise its content, weigh its risk, carry out the decision, then record everything so the next decision is better.

```mermaid
flowchart TB
  A[AI interaction<br/>prompt, file, tool call] --> B[Enforcement point<br/>gateway, proxy, MCP]
  B --> C[Detection<br/>data & prompt]
  C --> D[Policy decision<br/>OPA + risk score]
  D --> E{Decision}
  E -->|allow / warn| F[Proceed]
  E -->|redact / tokenize| F
  E -->|block / approval| G[Held]
  F --> H[Events & incidents]
  G --> H
  H --> I[Posture · Investigation · Compliance]
  I -.->|tune policy & models| D
```

Inspected interactions cover prompts, file uploads, model responses, agent tool calls, and stored data that AI can reach. Full details are in the [Specification](./spec) and the [Interactive Architecture](https://sivi-shahab.github.io/WANTIMPRES-26/architecture/).

## Design basis

The design comes from research into current industry standards and practice. Its main references are:

- OWASP Top 10 for LLM Applications 2025 and OWASP Top 10 for Agentic Applications 2026
- NIST AI RMF 1.0 and its Generative AI Profile (NIST AI 600-1)
- The Model Context Protocol (MCP) authorization specification, version 2026-07-28
- Indonesia's Personal Data Protection Law (UU 27/2022), OJK Regulation POJK 11/POJK.03/2022, and OJK's 2025 AI governance guide for Indonesian banking
- Product patterns from Forcepoint AI Security, Microsoft Purview DSPM, and Netskope One AI Security

With one policy decision point, one detection layer, and many enforcement points, WANTIMPRES-26 helps the organisation adopt AI quickly without losing control of customer data, credentials, and intellectual property.

## Choose your path

| I want to… | Start with |
| --- | --- |
| Understand the problems it solves and how it differs from DLP & LLM gateways | [Why WANTIMPRES-26](./guide/why) |
| Build from source, run the local stack, or deploy to Kubernetes | [Installation](./guide/install) |
| Connect apps and agents, manage policies, run SOC operations | [How to Use](./guide/how-to-use) |
| Get short answers on privacy, data location, integration, and compliance | [FAQ](./guide/faq) |
| Understand where the platform is heading and what its name and logo mean | [Vision & Mission](./about/vision-mission) · [Name & Logo Philosophy](./about/philosophy) |
| Read the PRD, SRS, architecture, APIs, and compliance end to end | [Full Specification](./spec) |
| See what is in progress and what comes next (M0–M4) | [Ticket Overview](./tickets/) |
| Explore the searchable, traceable platform diagram | [Interactive Architecture](https://sivi-shahab.github.io/WANTIMPRES-26/architecture/) |
