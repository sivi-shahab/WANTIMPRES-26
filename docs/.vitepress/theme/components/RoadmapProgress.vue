<script setup lang="ts">
import { computed } from 'vue'
import { withBase } from 'vitepress'

type Ticket = { id: string; num: string; title: string; status: string; group: string }

const props = defineProps<{
  tickets: Ticket[]
  milestones: { id: string; title: string; scope: string; estimate: string }[]
  statusLabels: Record<string, string>
  ticketBase: string
  labels: { done: string; open: string; tickets: string; estimate: string }
}>()

// Urutan status dari yang paling maju; warna batang mengikuti urutan ini.
const ORDER = ['done', 'needs-gitlab-run', 'needs-signoff', 'needs-triage', 'deferred']
const IMPLEMENTED = new Set(['done', 'needs-gitlab-run', 'needs-signoff'])

const rows = computed(() =>
  props.milestones.map((m) => {
    const ts = props.tickets.filter((t) => t.group === m.id)
    const counts = ORDER.map((s) => ({ s, n: ts.filter((t) => t.status === s).length })).filter((c) => c.n)
    const implemented = ts.filter((t) => IMPLEMENTED.has(t.status)).length
    const open = ts.filter((t) => t.status !== 'done' && t.status !== 'needs-gitlab-run')
    return { ...m, total: ts.length, counts, implemented, open }
  }),
)
</script>

<template>
  <div class="roadmap">
    <section v-for="m in rows" :key="m.id" class="ms">
      <h3 :id="m.id.toLowerCase()">{{ m.title }}</h3>
      <p class="scope">{{ m.scope }}</p>
      <p class="meta">
        {{ m.total }} {{ labels.tickets }} · {{ labels.estimate }} {{ m.estimate }} ·
        <strong>{{ m.implemented }}/{{ m.total }}</strong> {{ labels.done }}
      </p>
      <div class="bar" role="img" :aria-label="m.counts.map((c) => `${c.n} ${statusLabels[c.s]}`).join(', ')">
        <span v-for="c in m.counts" :key="c.s" :class="['seg', c.s]" :style="{ flex: c.n }" :title="`${c.n} ${statusLabels[c.s]}`" />
      </div>
      <ul class="legend">
        <li v-for="c in m.counts" :key="c.s"><span :class="['dot', c.s]" />{{ c.n }} {{ statusLabels[c.s] }}</li>
      </ul>
      <details v-if="m.open.length">
        <summary>{{ labels.open }} ({{ m.open.length }})</summary>
        <ul>
          <li v-for="t in m.open" :key="t.id">
            <a :href="withBase(ticketBase + t.id)">{{ t.num }} · {{ t.title }}</a> — <code>{{ t.status }}</code>
          </li>
        </ul>
      </details>
    </section>
  </div>
</template>
