// Tandai terjemahan English sebagai sesuai dengan sumber Indonesia saat ini.
// Pakai setelah selesai memperbarui terjemahan:
//   npm run docs:stamp -- .scratch/ai-data-security/en/issues/01-x.md [file lain...]
import crypto from 'node:crypto'
import fs from 'node:fs'

const files = process.argv.slice(2)
if (!files.length) {
  console.error('usage: npm run docs:stamp -- <.scratch/ai-data-security/en/...md> ...')
  process.exit(1)
}
for (const en of files) {
  const src = en.replace('/en/', '/')
  if (src === en || !fs.existsSync(src)) {
    console.error(`no Indonesian source for ${en}`)
    process.exit(1)
  }
  const h = crypto.createHash('sha256').update(fs.readFileSync(src)).digest('hex').slice(0, 16)
  const body = fs.readFileSync(en, 'utf8').replace(/^<!-- source-sha256: [0-9a-f]+ -->\n/, '')
  fs.writeFileSync(en, `<!-- source-sha256: ${h} -->\n${body}`)
  console.log(`${en} ← ${h}`)
}
