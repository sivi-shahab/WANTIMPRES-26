<script setup lang="ts">
import { computed } from 'vue'
import { withBase } from 'vitepress'

const props = defineProps<{
  tickets: { id: string; num: string; title: string; priority: string; type: string; milestone: string; group: string; status: string; blockedBy: string[] }[]
  milestones: Record<string, string>
  base: string
  labels: { ticket: string; status: string; priority: string; type: string; blocked: string }
}>()

const groups = computed(() =>
  Object.entries(props.milestones).map(([m, label]) => ({
    label,
    items: props.tickets.filter((t) => t.group === m),
  })),
)
</script>

<template>
  <div class="ticket-board">
    <section v-for="g in groups" :key="g.label">
      <h2 :id="g.label.split(' ')[0].toLowerCase()">{{ g.label }}</h2>
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>{{ labels.ticket }}</th>
            <th>{{ labels.status }}</th>
            <th>{{ labels.priority }}</th>
            <th>{{ labels.type }}</th>
            <th>{{ labels.blocked }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="t in g.items" :key="t.id">
            <td>{{ t.num }}</td>
            <td><a :href="withBase(base + t.id)">{{ t.title }}</a></td>
            <td><code>{{ t.status }}</code></td>
            <td><span class="badge" :class="t.priority">{{ t.priority }}</span></td>
            <td>{{ t.type }}</td>
            <td>
              <template v-if="t.blockedBy.length">
                <template v-for="(b, i) in t.blockedBy" :key="b">
                  <a :href="withBase(base + b)">{{ b.slice(0, 2) }}</a><span v-if="i < t.blockedBy.length - 1">, </span>
                </template>
              </template>
              <span v-else>–</span>
            </td>
          </tr>
        </tbody>
      </table>
    </section>
  </div>
</template>
