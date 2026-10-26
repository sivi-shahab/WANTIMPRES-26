import { defineConfig, type DefaultTheme } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'
import { loadTickets, MILESTONES, translationStale } from './tickets'

const tickets = { id: loadTickets('id'), en: loadTickets('en') }

// Terjemahan yang tertinggal tetap dirender (tiket diberi banner), tapi diumumkan saat build.
const stale = ['spec.md', ...tickets.id.map((t) => `issues/${t.id}.md`)].filter(translationStale)
if (stale.length) console.warn(`[i18n] ${stale.length} English translation(s) missing or out of date:\n  ${stale.join('\n  ')}`)

function ticketSidebar(prefix: string, lang: 'id' | 'en'): DefaultTheme.SidebarItem[] {
  return Object.entries(MILESTONES).map(([m, label]) => ({
    text: label[lang],
    collapsed: true,
    items: tickets[lang]
      .filter((t) => t.group === m)
      .map((t) => ({ text: `${t.num} · ${t.title}`, link: `${prefix}tickets/${t.id}` })),
  }))
}

const base = process.env.DOCS_BASE ?? '/'
const ARCH_URL = 'https://sivi-shahab.github.io/WANTIMPRES-26/architecture/'

// Catatan engineering yang sudah ada di docs/ (berbahasa Indonesia, dipakai kedua locale).
const records = (label: string): DefaultTheme.SidebarItem => ({
  text: label,
  collapsed: true,
  items: [
    { text: 'Threat Model', link: '/threat-model' },
    { text: 'ADR-0001 · Hosting & cakupan build', link: '/adr/0001-hosting-residency-build-scope' },
    { text: 'ADR-0002 · Identitas via Keycloak', link: '/adr/0002-identity-keycloak-broker' },
    { text: 'ADR-0003 · RLS PostgreSQL per tenant', link: '/adr/0003-rls-postgresql-per-tenant' },
    { text: 'DPIA pemantauan AI karyawan', link: '/dpia-pemantauan-ai-karyawan' },
    { text: 'Guideline labeling', link: '/labeling-guideline' },
    { text: 'Laporan NFR M1', link: '/nfr/m1-report' },
    { text: 'Runbook · Egress AI gateway', link: '/runbooks/egress-ai-gateway' },
    { text: 'Runbook · Rotasi kunci bundle', link: '/runbooks/rotasi-kunci-bundle' },
  ],
})

const id: DefaultTheme.Config = {
  nav: [
    { text: 'Beranda', link: '/' },
    { text: 'Panduan', link: '/guide/how-to-use' },
    { text: 'Visi & Misi', link: '/about/vision-mission' },
    { text: 'Spesifikasi', link: '/spec' },
    { text: 'Tiket', link: '/tickets/' },
    { text: 'Arsitektur Interaktif', link: ARCH_URL },
  ],
  sidebar: [
    {
      text: 'Mulai',
      items: [
        { text: 'Selamat Datang', link: '/' },
        { text: 'Visi & Misi', link: '/about/vision-mission' },
        { text: 'Filosofi Nama & Logo', link: '/about/philosophy' },
      ],
    },
    {
      text: 'Panduan',
      items: [
        { text: 'Mengapa WANTIMPRES-26', link: '/guide/why' },
        { text: 'Cara Instalasi', link: '/guide/install' },
        { text: 'Cara Menggunakan', link: '/guide/how-to-use' },
        { text: 'FAQ', link: '/guide/faq' },
        { text: 'Glosarium', link: '/guide/glossary' },
        { text: 'Roadmap', link: '/guide/roadmap' },
        { text: 'Release Notes', link: '/guide/release-notes' },
        { text: 'Kontribusi', link: '/guide/contributing' },
        { text: 'Keamanan', link: '/guide/security' },
        { text: 'Kode Etik', link: '/guide/code-of-conduct' },
        { text: 'Lisensi', link: '/guide/license' },
        { text: 'Changelog', link: '/changelog' },
      ],
    },
    { text: 'Spesifikasi', items: [{ text: 'Spesifikasi Lengkap', link: '/spec' }, records('Catatan Engineering')] },
    { text: 'Tiket & Roadmap', items: [{ text: 'Ringkasan Tiket', link: '/tickets/' }, ...ticketSidebar('/', 'id')] },
  ],
  outline: { level: [2, 3], label: 'Di halaman ini' },
  docFooter: { prev: 'Sebelumnya', next: 'Berikutnya' },
  lastUpdated: { text: 'Terakhir diperbarui' },
  darkModeSwitchLabel: 'Tema',
  sidebarMenuLabel: 'Menu',
  returnToTopLabel: 'Kembali ke atas',
  langMenuLabel: 'Ganti bahasa',
  footer: { message: 'Dirilis di bawah Apache License 2.0', copyright: '© 2026 The WANTIMPRES-26 Authors' },
}

const en: DefaultTheme.Config = {
  nav: [
    { text: 'Home', link: '/en/' },
    { text: 'Guide', link: '/en/guide/how-to-use' },
    { text: 'Vision & Mission', link: '/en/about/vision-mission' },
    { text: 'Specification', link: '/en/spec' },
    { text: 'Tickets', link: '/en/tickets/' },
    { text: 'Interactive Architecture', link: ARCH_URL },
  ],
  sidebar: [
    {
      text: 'Get started',
      items: [
        { text: 'Welcome', link: '/en/' },
        { text: 'Vision & Mission', link: '/en/about/vision-mission' },
        { text: 'Name & Logo Philosophy', link: '/en/about/philosophy' },
      ],
    },
    {
      text: 'Guide',
      items: [
        { text: 'Why WANTIMPRES-26', link: '/en/guide/why' },
        { text: 'Installation', link: '/en/guide/install' },
        { text: 'How to Use', link: '/en/guide/how-to-use' },
        { text: 'FAQ', link: '/en/guide/faq' },
        { text: 'Glossary', link: '/en/guide/glossary' },
        { text: 'Roadmap', link: '/en/guide/roadmap' },
        { text: 'Release Notes', link: '/en/guide/release-notes' },
        { text: 'Contributing', link: '/en/guide/contributing' },
        { text: 'Security', link: '/en/guide/security' },
        { text: 'Code of Conduct', link: '/en/guide/code-of-conduct' },
        { text: 'License', link: '/en/guide/license' },
        { text: 'Changelog', link: '/en/changelog' },
      ],
    },
    { text: 'Specification', items: [{ text: 'Full Specification', link: '/en/spec' }, records('Engineering Records (ID)')] },
    { text: 'Tickets & Roadmap', items: [{ text: 'Ticket Overview', link: '/en/tickets/' }, ...ticketSidebar('/en/', 'en')] },
  ],
  outline: { level: [2, 3] },
  lastUpdated: { text: 'Last updated' },
  footer: { message: 'Released under the Apache License 2.0', copyright: '© 2026 The WANTIMPRES-26 Authors' },
}

export default withMermaid(
  defineConfig({
    title: 'WANTIMPRES-26',
    base,
    cleanUrls: true,
    lastUpdated: true,
    head: [['link', { rel: 'icon', type: 'image/svg+xml', href: `${base}logo.svg` }]],
    locales: {
      root: {
        label: 'Bahasa Indonesia',
        lang: 'id-ID',
        description: 'Penjaga data & AI perusahaan: Enterprise AI Data Security & AI-SPM',
        themeConfig: id,
      },
      en: {
        label: 'English',
        lang: 'en-US',
        link: '/en/',
        description: 'Enterprise AI data security & AI Security Posture Management',
        themeConfig: en,
      },
    },
    themeConfig: {
      logo: '/logo.svg',
      socialLinks: [{ icon: 'github', link: 'https://github.com/sivi-shahab/WANTIMPRES-26' }],
      search: {
        provider: 'local',
        options: {
          locales: {
            root: {
              translations: {
                button: { buttonText: 'Cari', buttonAriaLabel: 'Cari' },
                modal: {
                  noResultsText: 'Tidak ada hasil untuk',
                  resetButtonTitle: 'Hapus pencarian',
                  footer: { selectText: 'pilih', navigateText: 'navigasi', closeText: 'tutup' },
                },
              },
            },
          },
        },
      },
    },
  }),
)
