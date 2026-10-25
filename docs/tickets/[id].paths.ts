import { loadTickets, ticketPage } from '../.vitepress/tickets'

const labels = { status: 'Status', type: 'Tipe', priority: 'Prioritas', milestone: 'Milestone', blocked: 'Diblok oleh', spec: 'Rujukan spec' }

export default {
  paths: () => loadTickets().map((t) => ({ params: { id: t.id }, content: ticketPage(t, '/spec', labels) })),
}
