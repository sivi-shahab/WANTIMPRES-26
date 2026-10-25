import DefaultTheme from 'vitepress/theme'
import Changelog from './components/Changelog.vue'
import TicketBoard from './components/TicketBoard.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('TicketBoard', TicketBoard)
    app.component('Changelog', Changelog)
  },
}
