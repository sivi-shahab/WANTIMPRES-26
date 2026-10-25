import { execFileSync } from 'node:child_process'
import { loadTickets } from './.vitepress/tickets'

export interface Entry {
  hash: string
  subject: string
  tickets: { num: string; id: string }[]
}

// Changelog dibangun dari riwayat git saat build (Pages checkout memakai fetch-depth 0).
export default {
  load() {
    const ids = new Map(loadTickets().map((t) => [t.num, t.id]))
    const log = execFileSync('git', ['log', '--date=short', '--format=%H%x1f%ad%x1f%s'], { encoding: 'utf8' })
    const days: { date: string; entries: Entry[] }[] = []
    for (const line of log.trim().split('\n')) {
      const [hash, date, subject] = line.split('\x1f')
      // "ticket 47", "tickets 09 and 40", "tickets 09, 10"
      const refs = [...subject.matchAll(/tickets? ((?:\d{2}(?:, | and )?)+)/gi)].flatMap((m) => m[1].match(/\d{2}/g) ?? [])
      const tickets = refs.filter((n) => ids.has(n)).map((n) => ({ num: n, id: ids.get(n)! }))
      if (days.at(-1)?.date !== date) days.push({ date, entries: [] })
      days.at(-1)!.entries.push({ hash, subject, tickets })
    }
    return days
  },
}
