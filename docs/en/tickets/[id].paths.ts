import { loadTickets, ticketPage } from '../../.vitepress/tickets'

const labels = { status: 'Status', type: 'Type', priority: 'Priority', milestone: 'Milestone', blocked: 'Blocked by', spec: 'Spec reference' }

export default {
  paths: () => loadTickets().map((t) => ({ params: { id: t.id }, content: ticketPage(t, '/en/spec', labels) })),
}
