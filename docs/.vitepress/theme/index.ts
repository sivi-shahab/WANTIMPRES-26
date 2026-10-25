import DefaultTheme from 'vitepress/theme'
import TicketBoard from './components/TicketBoard.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('TicketBoard', TicketBoard)
  },
}
