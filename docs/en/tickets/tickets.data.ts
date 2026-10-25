import { loadTickets } from '../../.vitepress/tickets'

export default {
  load: () => loadTickets('en').map(({ body, ...meta }) => meta),
}
