---
title: Ringkasan Tiket
---

<script setup>
import { data as tickets } from './tickets.data'
const milestones = { M0: 'M0 · Discovery & baseline', M1: 'M1 · MVP (P0)', M2: 'M2 · P1-a', M3: 'M3 · P1-b', M4: 'M4 · P2' }
</script>

# Tiket & Roadmap

Spesifikasi dipecah menjadi **{{ tickets.length }} tiket** per milestone. Sumber tiket ada di `.scratch/ai-data-security/issues/`, dan halaman ini dibangun dari file tersebut setiap kali situs di-build.

Tiket tanpa blocker bisa dikerjakan paralel sejak awal. Tiket **01** menentukan arah build-vs-buy dan dapat mengubah cakupan M2/M3.

<TicketBoard :tickets="tickets" :milestones="milestones" base="/tickets/" :labels="{ status: 'Status', ticket: 'Tiket', priority: 'Prioritas', type: 'Tipe', blocked: 'Diblok oleh' }" />
