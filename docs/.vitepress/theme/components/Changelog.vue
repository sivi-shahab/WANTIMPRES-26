<script setup lang="ts">
import { withBase } from 'vitepress'

defineProps<{
  days: { date: string; entries: { hash: string; subject: string; tickets: { num: string; id: string }[] }[] }[]
  ticketBase: string
  locale: string
}>()

const REPO = 'https://github.com/sivi-shahab/WANTIMPRES-26/commit/'
const fmt = (d: string, locale: string) =>
  new Date(d + 'T00:00:00').toLocaleDateString(locale, { day: 'numeric', month: 'long', year: 'numeric' })
</script>

<template>
  <div class="changelog">
    <section v-for="d in days" :key="d.date">
      <h2 :id="d.date">{{ fmt(d.date, locale) }}</h2>
      <ul>
        <li v-for="e in d.entries" :key="e.hash">
          {{ e.subject }}
          <a v-for="t in e.tickets" :key="t.num" class="badge" :href="withBase(ticketBase + t.id)">#{{ t.num }}</a>
          <a class="hash" :href="REPO + e.hash" target="_blank" rel="noopener">{{ e.hash.slice(0, 7) }}</a>
        </li>
      </ul>
    </section>
  </div>
</template>
