import fs from 'node:fs'
import path from 'node:path'

// Tiket tetap disimpan di .scratch/ (konvensi repo); situs hanya membacanya.
const DIR = path.resolve(process.cwd(), '.scratch/ai-data-security/issues')

export const MILESTONES: Record<string, { id: string; en: string }> = {
  M0: { id: 'M0 · Discovery & baseline', en: 'M0 · Discovery & baseline' },
  M1: { id: 'M1 · MVP (P0)', en: 'M1 · MVP (P0)' },
  M2: { id: 'M2 · P1-a', en: 'M2 · P1-a' },
  M3: { id: 'M3 · P1-b', en: 'M3 · P1-b' },
  M4: { id: 'M4 · P2', en: 'M4 · P2' },
}

export interface Ticket {
  id: string
  num: string
  title: string
  status: string
  type: string
  priority: string
  milestone: string
  group: string
  blockedBy: string[]
  spec: string
  body: string
}

export function loadTickets(): Ticket[] {
  const files = fs.readdirSync(DIR).filter((f) => f.endsWith('.md')).sort()
  const ids = new Map(files.map((f) => [f.slice(0, 2), f.replace(/\.md$/, '')]))
  return files.map((f) => {
    const raw = fs.readFileSync(path.join(DIR, f), 'utf8')
    const field = (k: string) => raw.match(new RegExp(`^${k}: (.*)$`, 'm'))?.[1].trim() ?? ''
    return {
      id: f.replace(/\.md$/, ''),
      num: f.slice(0, 2),
      title: raw.match(/^# \d+: (.*)$/m)?.[1] ?? f,
      status: field('Status'),
      type: field('Type'),
      priority: field('Priority'),
      milestone: field('Milestone'),
      group: field('Milestone').match(/^M\d/)?.[0] ?? 'M4',
      blockedBy: field('Blocked by').split(',').map((s) => s.trim()).filter((n) => ids.has(n)).map((n) => ids.get(n)!),
      spec: field('Spec').replace(/`\.\.\/spec\.md`\s*/, ''),
      body: raw.includes('\n## ') ? raw.slice(raw.indexOf('\n## ') + 1) : raw.replace(/^# .*\n/, ''),
    }
  })
}

// Markdown halaman tiket: header field jadi tabel, "Blocked by" jadi link.
export function ticketPage(t: Ticket, specLink: string, labels: Record<string, string>): string {
  const blocked = t.blockedBy.length ? t.blockedBy.map((b) => `[${b.slice(0, 2)}](./${b})`).join(', ') : '–'
  return [
    `# ${t.num}: ${t.title}`,
    '',
    `| ${labels.status} | ${labels.type} | ${labels.priority} | ${labels.milestone} | ${labels.blocked} |`,
    '|---|---|---|---|---|',
    `| \`${t.status}\` | ${t.type} | ${t.priority} | ${t.milestone} | ${blocked} |`,
    '',
    `**${labels.spec}:** [${t.spec}](${specLink})`,
    '',
    t.body,
  ].join('\n')
}
