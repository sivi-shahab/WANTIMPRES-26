---
title: Cara Instalasi
outline: [2, 3]
---

# Cara Instalasi

Kode sumber ada di GitHub: **[github.com/sivi-shahab/WANTIMPRES-26](https://github.com/sivi-shahab/WANTIMPRES-26)**.

Halaman ini membahas dua jalur:

- **[Lingkungan pengembangan](#lingkungan-pengembangan):** build, uji, dan jalankan di laptop.
- **[Instalasi produksi](#instalasi-produksi):** deploy ke Kubernetes di data center sendiri, sesuai [ADR-0001](../adr/0001-hosting-residency-build-scope).

## Lingkungan pengembangan

### Kebutuhan

| Perangkat | Versi | Untuk |
|---|---|---|
| Go | 1.26 | Semua service kecuali model-inference |
| Docker (dengan Compose v2) | terbaru | Build image dan stack lokal |
| Python | 3 | `services/model-inference` (layanan model L2) |
| Node.js | 22 | Situs dokumentasi (opsional) |

### Ambil kode dan build

```sh
git clone https://github.com/sivi-shahab/WANTIMPRES-26.git
cd WANTIMPRES-26

go build ./...
go vet ./...
go test -race ./...    # unit test; test Rego juga dijalankan lewat Go
```

Layanan model L2 diuji terpisah:

```sh
cd services/model-inference
pip install -r requirements.txt
python -m unittest -v
```

Integration test (audit log, event pipeline, object storage) butuh backend sungguhan dan otomatis dilewati di lokal kecuali variabel lingkungannya diisi. Daftar variabelnya ada di `.gitlab-ci.yml` (`AUDIT_TEST_*`, `IT_KAFKA_*`, `IT_SCHEMA_REGISTRY_URL`, `IT_OPENSEARCH_URL`, `OBJSTORE_TEST_AZURITE`).

### Jalankan stack lokal

```sh
deploy/nfr/run.sh up      # gateway di localhost:18080
deploy/nfr/run.sh down
```

Skrip ini menjalankan Go di dalam image `golang:1.26`, jadi host cukup punya Docker. Langkah mencoba request pertama ada di [Cara Menggunakan](./how-to-use#coba-di-lokal).

### Jalankan situs dokumentasi

```sh
npm ci
npm run docs:dev          # http://localhost:5173
```

## Instalasi produksi

Arsitektur produksi berjalan di Kubernetes milik sendiri dan hanya memakai komponen open source standar, tanpa managed service yang mengunci ke satu cloud.

### 1. Siapkan dependensi

| Komponen | Versi yang diuji di CI | Fungsi |
|---|---|---|
| Kubernetes | – | Platform utama, namespace `wantimpres26` |
| PostgreSQL (HA, mis. Patroni) | 17 | Data control-plane, row-level security per tenant ([ADR-0003](../adr/0003-rls-postgresql-per-tenant)) |
| Kafka + schema registry (Karapace) | 3.9 | Event `decision_event.v1` (TLS + SASL) |
| OpenSearch | 2.19 | Pencarian event dan investigasi |
| Redis | – | Rate limit dan kuota gateway |
| Object storage S3-compatible dengan object lock | – | Anchor audit log (WORM) dan bukti |
| Keycloak | – | Broker identitas OIDC untuk admin ([ADR-0002](../adr/0002-identity-keycloak-broker)) |
| Vault (Transit) | – | Menandatangani bundle kebijakan; kunci privat tidak pernah masuk pod |
| cert-manager + csi-driver-spiffe | – | Identitas workload dan mTLS antar-service |
| Kyverno | – | Hanya menerima image yang ditandatangani |

### 2. Siapkan cluster (sekali per cluster)

1. **Identitas workload.** Pasang cert-manager dan csi-driver-spiffe dengan trust domain `wantimpres26.bank` dan CA intermediate khusus yang ditandatangani CA internal. Panduan lengkap, termasuk contoh Helm, ada di `deploy/cluster/workload-identity.md`.
2. **Kebijakan image bertanda tangan:**
   ```sh
   kubectl apply -f deploy/cluster/require-signed-images.yaml
   ```
3. **Alert** (opsional, untuk Prometheus Operator): `deploy/cluster/alerts.yaml`.

### 3. Build, tandatangani, dan publikasikan image

Semua service Go memakai satu Dockerfile bersama:

```sh
docker build --build-arg SERVICE=ai-gateway -f build/go.Dockerfile -t <registry>/wantimpres26/ai-gateway:<tag> .
```

Ulangi untuk `control-plane`, `mcp-gateway`, `detection-svc`, `token-vault`, `event-ingest`, `connector-worker`, dan `siem-export`. Image OPA dan Tika dibuat dari `build/opa.Dockerfile` dan `build/tika.Dockerfile`, sedangkan model-inference dari `services/model-inference/Dockerfile`.

Artefak model L2 tidak ikut di image maupun di repository. Artefak dibuat ulang dari `services/model-inference/train/`, di-pin dengan sha256 di `MODELS.json`, lalu di-mount dari model store ke `MODEL_DIR`.

Karena cluster hanya menerima image bertanda tangan, image harus ditandatangani (cosign) sebelum di-deploy. Pipeline rilis resminya ada di GitLab (`.gitlab-ci.yml`): lint → test → scan → build → SBOM → sign.

### 4. Siapkan Secret dan ConfigMap

Manifest di `deploy/base` tidak berisi rahasia. Semua Secret dibuat terpisah (*out of band*), sebaiknya lewat Vault atau secret manager yang dipakai tim platform.

**Secret konfigurasi per service.** Setiap Deployment membaca variabel lingkungannya dari Secret dengan nama yang sama: `ai-gateway`, `control-plane`, `mcp-gateway`, `token-vault`, `event-ingest`, `connector-worker`, `siem-export`, dan `audit-anchor`. Isinya misalnya `DATABASE_URL`, `KAFKA_BROKERS`, `SCHEMA_REGISTRY_URL`, `OPENSEARCH_URL`, `REDIS_URL`, `OIDC_ISSUER`, `TENANT_ID`, dan `TENANT_PEPPER`. Variabel yang dibaca tiap service tercatat di komentar manifest dan di `cmd/<service>/main.go`; ringkasannya ada di tabel konfigurasi `README.md`.

**Secret berisi file:**

| Secret | Isi |
|---|---|
| `<service>-bus` | Password SASL Kafka dan CA Kafka/OpenSearch per service |
| `ai-gateway-provider-keys` | Key API provider LLM (dibaca ulang otomatis saat berubah) |
| `bundle-signer-token` | Token Vault yang hanya boleh `transit/sign` untuk kunci bundle |
| `incident-kek`, `token-vault-kek` | Kunci pembungkus bukti insiden dan vault tokenisasi |
| `audit-anchor-key` | Kunci penandatangan anchor harian audit log |
| `connector-worker-files`, `siem-export-files` | Kredensial connector dan sertifikat SIEM |

**ConfigMap:**

| ConfigMap | Isi |
|---|---|
| `ai-gateway-config` | Konfigurasi aplikasi dan provider gateway (`AIGW_CONFIG_FILE`); lihat [Daftarkan aplikasi](./how-to-use#daftarkan-aplikasi-dan-provider) |
| `mcp-servers` | Daftar MCP server untuk MCP gateway |
| `policy-bundle-pubkey` | Kunci publik `wantimpres26-policy-a.pub` dan `wantimpres26-policy-b.pub` untuk verifikasi bundle |

`opa-config` dibuat otomatis oleh Kustomize dari `deploy/base/opa/opa.yaml`.

### 5. Deploy

Manifest bawaan menunjuk image `registry.local/wantimpres26/<service>:dev`. Ganti dengan registry dan tag Anda lewat overlay Kustomize, misalnya:

```yaml
# overlays/prod/kustomization.yaml (contoh)
resources:
  - ../../deploy/base
images:
  - name: registry.local/wantimpres26/ai-gateway
    newName: registry.example.internal/wantimpres26/ai-gateway
    newTag: "1.0.0"
  # ulangi untuk setiap service
```

Lalu terapkan:

```sh
kubectl apply -k overlays/prod     # atau: kubectl apply -k deploy/base
kubectl -n wantimpres26 get pods
```

Setiap service menyediakan `/healthz` untuk readiness dan liveness probe. Audit anchor berjalan sebagai CronJob setiap hari pukul 00:15 WIB (`Asia/Jakarta`).

### 6. Setelah instalasi

1. **Paksa trafik LLM lewat gateway.** Blokir egress langsung ke provider LLM; lihat [runbook egress AI gateway](../runbooks/egress-ai-gateway).
2. **Kebijakan awal.** Pada database kosong, template bawaan otomatis dimuat sebagai kebijakan `builtin`. Sesuaikan lewat [siklus rilis kebijakan](./how-to-use#kelola-kebijakan).
3. **Daftarkan aplikasi, provider, MCP server, dan agent** pertama ([Cara Menggunakan](./how-to-use)).
4. **Siapkan rotasi kunci bundle** sesuai [runbook rotasi kunci bundle](../runbooks/rotasi-kunci-bundle).
5. **Uji ulang target non-fungsional** di lingkungan produksi; angka di [laporan NFR M1](../nfr/m1-report) diukur di satu host.

::: tip Bantuan
Pertanyaan umum tentang instalasi dan operasional ada di [FAQ](./faq). Masalah dan usulan dicatat sebagai tiket di `.scratch/ai-data-security/issues/` pada [repository GitHub](https://github.com/sivi-shahab/WANTIMPRES-26).
:::
