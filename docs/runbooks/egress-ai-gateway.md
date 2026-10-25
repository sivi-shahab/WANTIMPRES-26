# Runbook: egress AI provider hanya lewat AI gateway

Tiket 43, threat model G4. Untuk tim jaringan (firewall/SWG) bank. Tujuannya membuat AI gateway wajib. Tanpa aturan ini, aplikasi atau developer bisa memanggil API provider LLM langsung dengan key pribadi, dan DLP, inspeksi injection, kuota, serta audit gateway tidak berlaku.

## 1. Daftar domain

Sumber kebenaran adalah katalog app AI di control-plane, berisi feed bertanda tangan ditambah app lokal bank. Yang masuk daftar adalah semua domain dari app yang punya API.

```sh
# satu domain per baris; setiap domain mencakup subdomainnya
curl -fsS -H "Authorization: Bearer $TOKEN" "https://wantimpres26-control-plane/catalog/egress?format=txt" > ai-provider-domains.txt
# versi JSON dengan app, vendor, dan hosting_region (untuk review)
curl -fsS -H "Authorization: Bearer $TOKEN" "https://wantimpres26-control-plane/catalog/egress"
```

- Butuh izin `config.read` (security admin).
- Domain web provider (mis. `chatgpt.com`) juga ikut. Server tidak punya alasan membukanya, dan domain yang tidak dimasukkan bisa jadi celah.
- Subdomain yang sudah tercakup domain induknya tidak dicantumkan ulang. Di firewall, pakai objek FQDN wildcard (`*.domain` + `domain`) atau kategori URL setara di SWG.
- Daftar berubah ketika feed katalog di-update atau ada app lokal ditambahkan. Sinkronkan minimal harian, atau buat otomatis dari endpoint di atas.

## 2. Aturan

| # | Sumber | Tujuan | Aksi |
|---|---|---|---|
| 1 | IP egress AI gateway (pod `ai-gateway`, lewat NAT/egress gateway cluster yang tetap) | domain di daftar, TCP 443 | izinkan |
| 2 | subnet server/DC (termasuk node Kubernetes selain egress gateway) | domain di daftar | **tolak dan log** |
| 3 | subnet workstation | domain di daftar | lewat SWG seperti biasa. Kebijakan pengguna diatur PEP browser/SWG, bukan aturan ini |

- Aturan 2 berada di atas aturan "server boleh ke internet" yang lebih umum.
- Resolusi DNS dari server ke domain ini tetap dicatat (DNS log). Itu sinyal untuk §4.
- Pengecualian (mis. server vendor dengan kontrak sendiri) butuh keputusan tertulis CISO dan masuk ke daftar `-gateways` di §4 supaya tidak dilaporkan.

## 3. Uji setelah perubahan

1. Dari pod AI gateway, `curl -sS -o /dev/null -w '%{http_code}' https://api.openai.com/v1/models` harus dapat respons dari provider (401 tanpa key itu normal).
2. Dari server lain di subnet DC, perintah yang sama harus gagal (timeout atau reset), dan firewall mencatat penolakannya.
3. Lewat aplikasi resmi, request ke gateway (`/v1/chat/completions`) tetap jalan.

## 4. Deteksi bypass dari log

Aturan bisa bocor (objek salah, domain baru, NAT tambahan). Log SWG/DNS dianalisis berkala:

```sh
TENANT_PEPPER=... shadow-baseline -format squid \
  -servers 10.20.0.0/16,10.21.0.0/16 -gateways 10.20.0.5,10.20.0.6 \
  -out report/ /var/log/squid/access.log*
# kirim temuan ke control-plane: jadi temuan posture dan event SIEM per pasangan server/domain baru
jq '{gateway_bypass}' report/shadow-baseline.json | curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' --data @- https://wantimpres26-control-plane/catalog/gateway-bypass
```

- Format `dns` (BIND query log) dan `jsonl` (dengan field `client_ip`, atau dipetakan lewat `-fields client=...`) juga bisa. Log tanpa alamat klien tidak bisa menunjukkan bypass.
- Alamat server di subnet `-servers` dilaporkan apa adanya karena itu infrastruktur, bukan orang. User dan alamat workstation tetap di-HMAC.
- Hasilnya muncul di `GET /posture` (`gateway_bypass`, metrik "Servers reaching AI providers without the AI gateway", target 0), dan audit `catalog.gateway_bypass` diteruskan ke SIEM.

## 5. Kalau ada temuan

1. Identifikasi pemilik server (CMDB) dan aplikasinya.
2. Tutup jalurnya di firewall (aturan 2), lalu arahkan aplikasi ke AI gateway (base URL gateway dan key app dari vault, tiket 13).
3. Kalau ada indikasi data nasabah terkirim, buka insiden dan nilai breach UU PDP (tiket 26).
