# 05: Repo skeleton + pipeline CI/CD & supply chain

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 01
Spec: `../spec.md` §5.3 DEC-3; §12.2

## Konteks
Fondasi build untuk semua service. Control plane berupa modular monolith; PEP dan detection terpisah.

## Scope
- Struktur repo: control-plane (modular monolith), ai-gateway, detection-svc, model-inference, deploy/ (Helm/Kustomize).
- Pipeline: lint → unit → SAST → SCA → secret scan → build distroless → SBOM CycloneDX → cosign sign → IaC scan.
- Admission policy di cluster: hanya image bertanda tangan.
- Test privasi bersama: assert log/trace tidak mengandung field konten terlarang.

## Acceptance criteria
- [ ] Pipeline hijau untuk service hello-world di tiap komponen. *(Lokal: setiap job lint/test/scan lulus dengan image CI yang sama; build/sbom/sign diuji setara dengan docker + cosign. Belum dijalankan di GitLab.)*
- [x] SBOM dan signature terlampir di setiap image.
- [x] Deploy image tanpa tanda tangan ditolak cluster.

## Keputusan
- CI: **GitLab self-managed** (runner + registry on-prem).
- Bahasa: **Go** untuk control-plane, ai-gateway, detection-svc; **Python** untuk model-inference. Rust tidak dipakai sampai ada bukti kebutuhan latensi.
- Satu Go module (`wantimpres26`) dengan `cmd/<service>`; satu `build/go.Dockerfile` untuk semua service Go.
- Trivy menggantikan Checkov/tfsec (SCA + lisensi + IaC + image scan dalam satu tool).
- cosign key-based, `--tlog-upload=false`, format `.sig/.att` legacy (Kyverno 1.19 belum membaca bundle cosign v3).

## Hasil verifikasi lokal (2026-10-02)
- `go test -race`, unittest Python, golangci-lint v2.5.0, ruff, semgrep p/default, trivy fs/config, gitleaks (history + dir): lulus.
- Test privasi bersama: `internal/privacy` (Go) dan `services/model-inference/test_app.py` membaca daftar yang sama `internal/privacy/forbidden_fields.txt`.
- kind (k8s 1.33) + Kyverno 1.19.1: 4 deployment bertanda tangan jalan (tag di-mutate ke digest); pod unsigned ditolak; initContainer unsigned ditolak.

## Sisa / follow-up
- Jalankan pipeline di GitLab; isi `MIRROR`, `COSIGN_KEY` (protected, idealnya URI KMS/HSM), `COSIGN_PASSWORD`; ganti placeholder public key di policy.
- Provenance SLSA L3 belum ada.
- Admission belum memverifikasi attestation SBOM: Kyverno 1.19 ivpol menolak attestation tanpa tlog. Butuh Rekor on-prem atau fix upstream.
