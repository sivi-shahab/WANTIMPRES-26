import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

// Spec & tiket tetap disimpan di .scratch/ (konvensi repo); situs hanya membacanya.
// Sumber kanonik berbahasa Indonesia; terjemahan English ada di en/ dengan nama file yang sama.
const ROOT = path.resolve(process.cwd(), '.scratch/ai-data-security')
const DIR = path.join(ROOT, 'issues')

// Terjemahan menyimpan hash sumbernya di baris pertama (lihat i18n-stamp.mjs).
const STAMP = /^<!-- source-sha256: ([0-9a-f]+) -->\n/
const hash = (file: string) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex').slice(0, 16)

// Path relatif ke ROOT, mis. 'spec.md' atau 'issues/01-x.md'. true = terjemahan tidak ada atau tertinggal dari sumber.
export function translationStale(rel: string): boolean {
  const en = path.join(ROOT, 'en', rel)
  if (!fs.existsSync(en)) return true
  return fs.readFileSync(en, 'utf8').match(STAMP)?.[1] !== hash(path.join(ROOT, rel))
}

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
  stale: boolean
}

// Metadata (status, prioritas, dst.) selalu dari sumber Indonesia; judul dan isi dari terjemahan bila lang = 'en'.
export function loadTickets(lang: 'id' | 'en' = 'id'): Ticket[] {
  const files = fs.readdirSync(DIR).filter((f) => f.endsWith('.md')).sort()
  const ids = new Map(files.map((f) => [f.slice(0, 2), f.replace(/\.md$/, '')]))
  return files.map((f) => {
    const raw = fs.readFileSync(path.join(DIR, f), 'utf8')
    const enFile = path.join(ROOT, 'en/issues', f)
    const text = lang === 'en' && fs.existsSync(enFile) ? fs.readFileSync(enFile, 'utf8').replace(STAMP, '') : raw
    const field = (k: string) => raw.match(new RegExp(`^${k}: (.*)$`, 'm'))?.[1].trim() ?? ''
    return {
      id: f.replace(/\.md$/, ''),
      num: f.slice(0, 2),
      title: text.match(/^# \d+: (.*)$/m)?.[1] ?? f,
      status: field('Status'),
      type: field('Type'),
      priority: field('Priority'),
      milestone: field('Milestone'),
      group: field('Milestone').match(/^M\d/)?.[0] ?? 'M4',
      blockedBy: field('Blocked by').split(',').map((s) => s.trim()).filter((n) => ids.has(n)).map((n) => ids.get(n)!),
      spec: field('Spec').replace(/`\.\.\/spec\.md`\s*/, ''),
      body: text.includes('\n## ') ? text.slice(text.indexOf('\n## ') + 1) : text.replace(/^# .*\n/, ''),
      stale: lang === 'en' && translationStale(`issues/${f}`),
    }
  })
}

// Markdown halaman tiket: header field jadi tabel, "Blocked by" jadi link.
export function ticketPage(t: Ticket, specLink: string, labels: Record<string, string>, staleNotice = ''): string {
  const blocked = t.blockedBy.length ? t.blockedBy.map((b) => `[${b.slice(0, 2)}](./${b})`).join(', ') : '–'
  return [
    `# ${t.num}: ${t.title}`,
    '',
    ...(t.stale && staleNotice ? [`::: warning\n${staleNotice}\n:::`, ''] : []),
    `| ${labels.status} | ${labels.type} | ${labels.priority} | ${labels.milestone} | ${labels.blocked} |`,
    '|---|---|---|---|---|',
    `| \`${t.status}\` | ${t.type} | ${t.priority} | ${t.milestone} | ${blocked} |`,
    '',
    `**${labels.spec}:** [${t.spec}](${specLink})`,
    '',
    t.body,
  ].join('\n')
}
