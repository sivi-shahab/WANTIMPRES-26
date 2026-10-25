---
title: Ticket Overview
---

<script setup>
import { data as tickets } from '../../tickets/tickets.data'
const milestones = { M0: 'M0 · Discovery & baseline', M1: 'M1 · MVP (P0)', M2: 'M2 · P1-a', M3: 'M3 · P1-b', M4: 'M4 · P2' }
</script>

# Tickets & Roadmap

The specification is split into **{{ tickets.length }} tickets** across milestones. Tickets live in `.scratch/ai-data-security/issues/` and this page is rebuilt from those files on every site build. Ticket titles and bodies are in Bahasa Indonesia.

Tickets without blockers can start in parallel. Ticket **01** decides build-vs-buy and may change the scope of M2/M3.

<TicketBoard :tickets="tickets" :milestones="milestones" base="/en/tickets/" :labels="{ status: 'Status', ticket: 'Ticket', priority: 'Priority', type: 'Type', blocked: 'Blocked by' }" />
