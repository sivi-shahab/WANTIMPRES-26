---
title: Lisensi
outline: [2, 3]
---

# Lisensi

WANTIMPRES-26 dirilis di bawah **[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)**.

```text
Copyright 2026 The WANTIMPRES-26 Authors
```

Teks lisensi lengkap ada di file [`LICENSE`](https://github.com/sivi-shahab/WANTIMPRES-26/blob/main/LICENSE), dan pemberitahuan hak cipta di [`NOTICE`](https://github.com/sivi-shahab/WANTIMPRES-26/blob/main/NOTICE).

## Ringkasan

::: info Bukan nasihat hukum
Ringkasan ini hanya untuk memudahkan. Yang berlaku secara hukum adalah teks lengkap lisensi.
:::

**Anda boleh:**
- memakai kode untuk keperluan apa pun, termasuk komersial,
- mengubah kode dan membuat karya turunan,
- mendistribusikan kode asli maupun hasil ubahan,
- memakai paten kontributor yang melekat pada kontribusinya.

**Dengan syarat:**
- menyertakan salinan lisensi dan file `NOTICE` saat mendistribusikan,
- menandai file yang Anda ubah,
- mempertahankan pemberitahuan hak cipta, paten, dan atribusi yang sudah ada.

**Batasan:**
- lisensi ini tidak memberi hak memakai nama atau merek dagang proyek,
- kode diberikan apa adanya, tanpa jaminan,
- hak paten dari kontributor berakhir bila Anda menggugat paten terkait karya ini.

## Kontribusi

Sesuai Pasal 5 lisensi, setiap kontribusi yang Anda kirim ke proyek ini otomatis berada di bawah Apache License 2.0, kecuali Anda menyatakan lain secara eksplisit. Panduan berkontribusi ada di [Kontribusi](./contributing).

## Komponen pihak ketiga

Komponen pihak ketiga tetap memakai lisensinya masing-masing. Semuanya kompatibel dengan Apache-2.0. CI memeriksa lisensi dependensi Go dan Python dengan Trivy, dan build gagal bila menemukan lisensi yang dilarang.

### Dependensi Go langsung

| Modul | Lisensi |
|---|---|
| `github.com/capitalone/fpe` | Apache-2.0 |
| `github.com/coreos/go-oidc/v3` | Apache-2.0 |
| `github.com/go-jose/go-jose/v4` | Apache-2.0 |
| `github.com/google/uuid` | BSD-3-Clause |
| `github.com/jackc/pgx/v5` | MIT |
| `github.com/minio/minio-go/v7` | Apache-2.0 |
| `github.com/open-policy-agent/opa` | Apache-2.0 |
| `github.com/redis/go-redis/v9` | BSD-2-Clause |
| `github.com/santhosh-tekuri/jsonschema/v6` | Apache-2.0 |
| `github.com/twmb/franz-go` (termasuk `pkg/kadm`, `pkg/sr`) | BSD-3-Clause |
| `golang.org/x/oauth2`, `golang.org/x/text` | BSD-3-Clause |
| `sigs.k8s.io/yaml` | MIT dan BSD-3-Clause |

Dependensi tidak langsung tercantum di `go.mod` dan ikut diperiksa oleh Trivy.

### Layanan model (Python)

| Paket | Lisensi |
|---|---|
| `numpy` 1.26.4 | BSD-3-Clause |
| `onnxruntime` 1.19.2 | MIT |
| `tokenizers` 0.19.1 | Apache-2.0 |

### Model dan data pelatihan

Artefak model tidak disimpan di repository, tetapi asal-usul dan lisensinya dicatat di `services/model-inference/MODELS.json`.

| Komponen | Lisensi |
|---|---|
| Model dasar `distilbert/distilbert-base-multilingual-cased` | Apache-2.0 |
| Data sintetis internal (`evalcorpus`) | Internal, dibuat oleh proyek ini |
| Dataset `deepset/prompt-injections` | Apache-2.0 |
| Dataset `jackhhao/jailbreak-classification` | Apache-2.0 |
| Dataset `reshabhs/SPML_Chatbot_Prompt_Injection` | MIT |
| Dataset `cahya/alpaca-id-cleaned` | CC-BY-4.0 |

### Image container

| Image | Lisensi |
|---|---|
| `openpolicyagent/opa` | Apache-2.0 |
| `apache/tika` | Apache-2.0 |

### Dokumentasi

| Komponen | Lisensi |
|---|---|
| VitePress, `vitepress-plugin-mermaid`, Mermaid (hanya untuk membangun situs ini) | MIT |
| [Kode Etik](./code-of-conduct), diadaptasi dari Contributor Covenant 2.1 | CC-BY-4.0 |
