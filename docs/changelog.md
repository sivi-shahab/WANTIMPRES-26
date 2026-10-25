---
title: Changelog
outline: [2, 2]
---

<script setup>
import { data as days } from './changelog.data'
</script>

# Changelog

Semua perubahan pada WANTIMPRES-26, dari yang terbaru. Daftar ini dibuat otomatis dari riwayat git setiap kali situs di-build, jadi selalu sama dengan isi repository. Pesan commit ditulis dalam bahasa Inggris.

Label **#NN** menuju halaman tiket terkait, dan kode di ujung baris menuju commit-nya di [GitHub](https://github.com/sivi-shahab/WANTIMPRES-26/commits/main).

<Changelog :days="days" ticket-base="/tickets/" locale="id-ID" />
