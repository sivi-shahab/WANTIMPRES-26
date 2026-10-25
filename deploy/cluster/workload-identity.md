# Identitas workload (SPIFFE/mTLS) untuk namespace `wantimpres26`

Tiket 40, threat model G1, spec §10.1. Dipasang sekali per cluster oleh tim platform, sebelum `deploy/base`.

## Komponen
- **cert-manager** dan **csi-driver-spiffe** (cert-manager.io). Setiap pod yang me-mount volume CSI `spiffe.csi.cert-manager.io` mendapat SVID X.509 berumur pendek di `/spiffe` (`tls.crt`, `tls.key`, `ca.crt`), dengan URI SAN `spiffe://wantimpres26.bank/ns/<namespace>/sa/<service account>`. Kunci privat dibuat di node dan tidak pernah menjadi Secret Kubernetes. Sertifikat diperbarui di tempat sebelum kedaluwarsa.
- **Trust domain:** `wantimpres26.bank`. Harus sama dengan nilai `MTLS_ALLOW` di `deploy/base`.
- **Issuer:** CA intermediate khusus `wantimpres26`, ditandatangani CA internal bank. Kunci CA disimpan di HSM (Vault PKI dengan managed key, atau issuer cert-manager yang memanggil HSM). Jangan pakai issuer self-signed di produksi.
- **Approver:** approver bawaan csi-driver-spiffe saja (menolak CSR yang tidak cocok dengan service account pod). Matikan auto-approve cert-manager untuk issuer ini.

Contoh Helm (nilai disesuaikan dengan issuer bank):

```sh
helm upgrade --install cert-manager-csi-driver-spiffe jetstack/cert-manager-csi-driver-spiffe -n cert-manager \
  --set app.trustDomain=wantimpres26.bank \
  --set app.issuer.name=wantimpres26-workload-ca --set app.issuer.kind=ClusterIssuer \
  --set app.certificateRequestDuration=1h \
  --set app.approver.signerName=clusterissuers.cert-manager.io/wantimpres26-workload-ca
```

## Siapa boleh memanggil siapa

| Server (port mTLS 8443) | `MTLS_ALLOW` | Alur §5.2 |
|---|---|---|
| control-plane `/bundles` | ai-gateway, mcp-gateway (sidecar OPA di pod-nya) | BUN → OPA |
| detection-svc `/scan/text` | ai-gateway, mcp-gateway | PEP → DS |
| model-inference | detection-svc | DS → MI |

Port 8080 tetap ada untuk probe kubelet (`/healthz`). Di control-plane, port ini juga melayani admin API di belakang ingress (OIDC). Route khusus workload tidak disajikan di port ini. Service tanpa `MTLS_DIR` menolak start, kecuali `MTLS_INSECURE=true` (hanya untuk pengembangan lokal).

NetworkPolicy default-deny (`deploy/base/networkpolicy.yaml`) membatasi jalur jaringan yang sama. Kalau salah satu lapisan salah konfigurasi, lapisan lainnya masih menahan. `deploy/netpol_test.go` memeriksa kedua lapisan saling cocok.

## Menambah pemanggil
1. Workload baru punya ServiceAccount sendiri (`deploy/base/serviceaccounts.yaml`) dan volume `spiffe`.
2. Tambahkan SPIFFE ID-nya ke `MTLS_ALLOW` server tujuan, dan alur jaringannya ke `networkpolicy.yaml`.
3. Tambahkan alurnya ke daftar `open` di `deploy/netpol_test.go`.
