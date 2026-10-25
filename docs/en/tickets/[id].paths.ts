import { loadTickets, ticketPage } from '../../.vitepress/tickets'

const labels = { status: 'Status', type: 'Type', priority: 'Priority', milestone: 'Milestone', blocked: 'Blocked by', spec: 'Spec reference' }
const stale = 'This translation is missing or older than the Indonesian source. Switch to Bahasa Indonesia for the current version.'

export default {
  paths: () => loadTickets('en').map((t) => ({ params: { id: t.id }, content: ticketPage(t, '/en/spec', labels, stale) })),
}
