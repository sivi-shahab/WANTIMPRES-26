# 40: Service-to-service authN, NetworkPolicy default-deny, kunci bundle di KMS/HSM

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M2
Spec: `../spec.md` §10.1 AuthN (SPIFFE/mTLS), Self-protection; `docs/threat-model.md` G1

## Konteks
Threat model (tiket 02) G1: detection-svc dan model-inference menerima request dari pod mana pun di cluster (oracle untuk mengakali detektor). `GET /bundles/wantimpres26.tar.gz` public, sehingga data katalog, registry agent, dan exception terbaca dari jaringan. Kunci tanda tangan bundle berupa file Secret, bukan KMS/HSM.

## Scope
- mTLS antar-service (SPIFFE/SVID via mesh atau cert-manager), atau minimal NetworkPolicy default-deny di namespace `wantimpres26` dengan allow eksplisit per alur §5.2.
- `/bundles` hanya untuk OPA sidecar (identitas workload).
- Tanda tangan bundle lewat KMS/HSM; kunci privat tidak pernah berupa file di pod.

## Acceptance criteria
- [x] Pod tanpa identitas yang berhak ditolak saat memanggil detection-svc, model-inference, dan `/bundles` (test). *(Bukti per service:)*
  - *detection-svc, `TestScanOnlyForPEPs`: ai-gateway boleh scan. siem-export, event-ingest, tika, dan `default` ditolak saat handshake.*
  - *model-inference, `test_mtls.py`: detection-svc dilayani. siem-export, klien tanpa sertifikat, dan sertifikat CA lain ditolak. Service menolak start tanpa `MTLS_DIR`/`MTLS_ALLOW`.*
  - *`/bundles`, `TestBundleOnlyForSidecarsAndKeyRotation`: OPA SDK dengan `deploy/base/opa/opa.yaml` apa adanya mendapat bundle sebagai ai-gateway, sedangkan sebagai siem-export tidak pernah siap. `/bundles` dihapus dari admin API (`TestRouteMatrix`).*
  - *Lapisan bersama, `TestWorkloadTLS`: menolak ID di luar daftar, tanpa sertifikat, dan CA asing. Klien juga memeriksa ID server. Sertifikat dirotasi di tempat tanpa restart.*
- [ ] NetworkPolicy default-deny aktif; alur §5.2 tetap lulus smoke test. *(Manifest sudah aktif: `deploy/base/networkpolicy.yaml`, default-deny Ingress+Egress plus allow per alur. Diverifikasi **statis** oleh `deploy/netpol_test.go`, yang mengevaluasi semantik NetworkPolicy atas manifest: semua alur §5.2 terbuka (BUN→OPA, PEP→DS, DS→MI, GW→TV, ingress admin, Alertmanager, Prometheus, DNS, data service eksternal), sedangkan jalur oracle/exfiltrasi tertutup (pod lain → detection/model/`/bundles`, model-inference/tika → luar). Test juga memastikan setiap workload punya ServiceAccount sendiri dan `MTLS_ALLOW` konsisten dengan jaringan. kubeconform: 46 resource valid; kustomize build OK. **Smoke test di cluster nyata belum dijalankan**, lihat Sisa.)*
- [x] Rotasi kunci bundle tanpa downtime terdokumentasi. *(`docs/runbooks/rotasi-kunci-bundle.md`. Diuji: `TestTransitSignerAndRotation` (slot a = file, slot b = Vault transit palsu; keduanya terverifikasi bila kedua slot dipercaya; slot b ditolak sebelum sidecar mengenalnya; kunci liar yang mengaku slot a ditolak) dan test OPA SDK end-to-end (release bertanda tangan a, lalu b, aktif tanpa sidecar di-restart; bundle kunci liar tidak menggantikan yang terakhir sah).)*

## Keputusan
- **Identitas workload:** SVID X.509 dari cert-manager csi-driver-spiffe (`spiffe://wantimpres26.bank/ns/wantimpres26/sa/<sa>`), dengan satu ServiceAccount per workload. Mesh tidak dipakai: jauh lebih sedikit komponen untuk 3 alur yang butuh authN. Kunci privat SVID dibuat di node dan diputar di tempat. Server Go (`internal/server`) dan Python (`mtls.py`) membaca ulang file saat berubah. Setup cluster: `deploy/cluster/workload-identity.md`.
- **Route khusus workload dipisah per port:** `server.RunMTLS` menyajikan route workload hanya di `:8443` (TLS 1.3, sertifikat klien wajib, SPIFFE ID ∈ `MTLS_ALLOW`, ditolak saat handshake). `:8080` hanya untuk probe kubelet; di control-plane juga admin API di belakang ingress. Tanpa `MTLS_DIR`, service menolak start kecuali `MTLS_INSECURE=true` (dev lokal).
- **Pemanggil yang diizinkan:** `/bundles` dan detection-svc untuk ai-gateway dan mcp-gateway; model-inference untuk detection-svc. `server.MTLSClient` disediakan untuk detection-svc → model-inference (tiket 09/10 memakainya saat memanggil model). OPA sidecar memakai `client_tls` bawaan OPA dengan `cert_reread_interval_seconds: 300`.
- **NetworkPolicy:** default-deny Ingress+Egress, DNS ke kube-dns, allow per alur §5.2, dan egress ke luar cluster hanya untuk pod berlabel `wantimpres26.bank/egress: external`. model-inference dan tika tidak berlabel, jadi tidak bisa mengirim data keluar. Egress eksternal `0.0.0.0/0` ditandai `ponytail:` untuk dipersempit ke CIDR data service per site. Namespace luar dicocokkan lewat `kubernetes.io/metadata.name` (`ingress-nginx`, `monitoring`, `kube-system`). control-plane → tika ditambahkan karena pendaftaran PDF (tiket 37) sebelumnya akan diblok `tika-isolated`.
- **Kunci bundle:** `policysvc.Signer` membungkus `crypto.Signer`. Implementasi produksi adalah Vault transit (`TransitSigner`, bisa HSM-backed via managed key), dan kunci file hanya untuk dev/test. Pilihan ini menghindari PKCS#11 (cgo) di image distroless. Bundle tetap JWS ES256 standar dengan `kid` = slot, diverifikasi verifier default OPA. Saat start, control-plane menandatangani probe dan memverifikasinya dengan kunci publik yang dikonfigurasi, sehingga konfigurasi Vault yang salah terdeteksi sebelum release pertama.
- **Rotasi:** dua slot tetap (`wantimpres26-policy-a`/`-b`) di semua sidecar, dan `signing.keyid` dihapus dari `opa.yaml` agar `kid` bundle yang memilih kunci. Rotasi cukup mengubah ConfigMap kunci publik dan env control-plane, tanpa mengubah args atau config sidecar.
- **Fixture PKI test Python** di `services/model-inference/testdata/pki` (berlaku 100 tahun, tidak dipercaya deployment mana pun) di-allowlist di `.gitleaks.toml`. Aturan default gitleaks tetap berlaku untuk path lain. Test Go membuat PKI-nya sendiri saat runtime.

## Hasil verifikasi lokal (2026-10-10)
- gofmt bersih, `go vet ./...` bersih, golangci-lint v2.5.0 0 issue. Python: `python -m unittest` (3 test) dan ruff check/format bersih.
- Test tiket ini hijau: `internal/server` (`TestWorkloadTLS`, `TestMTLSClientNeedsCertificates`), `cmd/detection-svc` (`TestScanOnlyForPEPs`), `cmd/control-plane` (`TestBundleOnlyForSidecarsAndKeyRotation`, `TestRouteMatrix`), `internal/policysvc` (`TestTransitSignerAndRotation`, dan test bundle lama dengan signer baru), `deploy` (`TestNetworkPolicy`), dan `test_mtls.py`.
- `go test -race ./...` dengan Postgres 17: 35 paket hijau di run penuh. Dua test berbasis waktu gagal saat load average host ~50 dari pekerjaan paralel: `mcpgw.TestKillSwitch` (4,9 detik) dan timeout `policysvc.TestRegoPolicies`. Keduanya hijau saat diulang sendiri dengan `-race` (bersama `lifecycle`, `server`, `cmd/...`, `deploy`).
- kubeconform v0.6.7 `-strict`: 46/46 valid. kustomize v5.4.3 build OK. gitleaks v8.28.0: 0 temuan dengan `.gitleaks.toml` (4 tanpa config, yaitu fixture test).

## Sisa
- **Smoke test cluster nyata** (kind/k3d dengan cert-manager + csi-driver-spiffe + CNI yang menegakkan NetworkPolicy, semua image dibangun) belum dijalankan. Perlu dijalankan di cluster staging sebelum AC ke-2 dicentang.
- Pasang cert-manager + csi-driver-spiffe dengan CA intermediate `wantimpres26` di HSM (tim platform, `deploy/cluster/workload-identity.md`). Buat kunci Vault transit, token sign-only, dan ConfigMap `policy-bundle-pubkey` dengan dua slot.
- Persempit egress `0.0.0.0/0` ke CIDR data service bank per site (overlay).
- PEP lain (web-proxy adapter, browser extension backend) yang memanggil detection-svc perlu ServiceAccount, volume SVID, dan entri `MTLS_ALLOW`/NetworkPolicy saat dibangun.
- token-vault masih memakai bearer token aplikasi (tiket 24) plus NetworkPolicy, belum mTLS.
