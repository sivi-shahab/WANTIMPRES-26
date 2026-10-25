# Runbook: rotasi kunci tanda tangan policy bundle tanpa downtime

Tiket 40, threat model G1 dan §4.2. Untuk tim platform/keamanan.

## Model
- Kunci privat bundle ada di Vault transit dengan backing HSM (managed key). Control-plane menandatangani lewat `POST /v1/transit/sign/<kunci>/sha2-256` (`BUNDLE_TRANSIT_URL`) memakai token Vault yang hanya boleh `sign` pada kunci itu. Kunci privat tidak pernah berupa file di pod.
- Sidecar OPA selalu mempercayai **dua slot**, `wantimpres26-policy-a` dan `wantimpres26-policy-b`, dari ConfigMap `policy-bundle-pubkey` (`wantimpres26-policy-a.pub`, `wantimpres26-policy-b.pub`). Bundle membawa `kid` = slot penandatangannya, dan sidecar memilih kunci publik berdasarkan `kid` itu (tidak ada `signing.keyid` di `opa.yaml`).
- Control-plane menandatangani dengan satu slot (`BUNDLE_SIGNING_KEY_ID`) dan memeriksa saat start bahwa tanda tangan Vault cocok dengan kunci publik slot itu (`BUNDLE_SIGNING_PUBKEY_FILE`). Kalau tidak cocok, pod tidak start.

Contoh di bawah memakai slot aktif **a** dan rotasi ke **b**. Rotasi berikutnya kebalikannya.

## Langkah
1. **Buat kunci baru** di Vault (type `ecdsa-p256`, managed key HSM), mis. `wantimpres26-bundle-2027`. Ekspor kunci publiknya (`vault read transit/keys/wantimpres26-bundle-2027`, ubah ke PEM `PUBLIC KEY`). Buat policy Vault `transit/sign/wantimpres26-bundle-2027/*` untuk role control-plane.
2. **Isi slot yang menganggur:** perbarui ConfigMap `policy-bundle-pubkey` key `wantimpres26-policy-b.pub` dengan kunci publik baru. Biarkan `wantimpres26-policy-a.pub` tetap.
3. **Roll sidecar** (ai-gateway, mcp-gateway): `kubectl -n wantimpres26 rollout restart deploy/ai-gateway deploy/mcp-gateway`. `--set-file` membaca kunci saat start. Selama rolling, pod lama (hanya mengenal a) dan pod baru (a+b) sama-sama menerima bundle yang masih ditandatangani a. Tunggu sampai semua pod Ready.
4. **Pindahkan penanda tangan:** pada control-plane set `BUNDLE_SIGNING_KEY_ID=wantimpres26-policy-b`, `BUNDLE_SIGNING_PUBKEY_FILE=/keys/wantimpres26-policy-b.pub`, dan `BUNDLE_TRANSIT_URL=.../transit/sign/wantimpres26-bundle-2027/sha2-256`, lalu rollout. Replika baru langsung menandatangani bundle berikutnya dengan b, dan semua sidecar sudah mempercayai b. Replika lama yang masih menandatangani dengan a tetap diterima.
5. **Verifikasi:** metrik OPA `bundle_failed_load_counter` tetap 0 (alert `deploy/cluster/alerts.yaml`), dan `policy_release_current` sama di semua replika. Opsional: potong release kosong untuk memastikan bundle bertanda tangan b aktif.
6. **Pensiunkan kunci lama:** cabut izin `sign` pada kunci lama di Vault dan nonaktifkan kunci itu. Biarkan `wantimpres26-policy-a.pub` sampai rotasi berikutnya menimpanya. Tidak ada lagi yang menandatangani dengan a.

## Rotasi darurat (kunci lama bocor)
Langkah 1–4 sama. Lalu segera timpa `wantimpres26-policy-a.pub` dengan kunci publik **baru** (b) dan roll sidecar lagi, sehingga tanda tangan dengan kunci bocor tidak diterima di slot mana pun. Cache bundle di disk sidecar (`persist: true`) hanya dipakai saat start dan diverifikasi ulang dengan kunci yang berlaku. Bundle bertanda tangan kunci bocor tidak lagi dimuat setelah roll.

## Kalau gagal
- Control-plane tidak start dengan `bundle signing key: signature does not verify with the configured public key`: URL transit dan file kunci publik tidak sepasang. Kembalikan env ke slot sebelumnya.
- Sidecar `bundle_failed_load_counter` naik setelah langkah 4: masih ada sidecar yang belum di-roll di langkah 3. Kembalikan `BUNDLE_SIGNING_KEY_ID` ke slot lama, selesaikan langkah 3, lalu ulangi.
- Vault tidak bisa dihubungi: release baru gagal dibangun dan sidecar tetap memakai bundle terakhir yang sah (spec §13.1). Tidak ada fallback ke kunci file.

## Pengembangan lokal
`BUNDLE_SIGNING_KEY_FILE` (PEM EC P-256) menggantikan transit. Jangan dipakai di cluster bersama: kunci itu berupa file.
