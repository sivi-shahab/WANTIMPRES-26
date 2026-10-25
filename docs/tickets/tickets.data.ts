import { loadTickets } from '../.vitepress/tickets'

export default {
  load: () => loadTickets().map(({ body, ...meta }) => meta),
}
