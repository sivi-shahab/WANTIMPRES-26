---
title: Changelog
outline: [2, 2]
---

<script setup>
import { data as days } from '../changelog.data'
</script>

# Changelog

Every change to WANTIMPRES-26, newest first. This list is generated from the git history on every site build, so it always matches the repository.

A **#NN** label links to the related ticket, and the code at the end of each line links to the commit on [GitHub](https://github.com/sivi-shahab/WANTIMPRES-26/commits/main).

<Changelog :days="days" ticket-base="/en/tickets/" locale="en-GB" />
