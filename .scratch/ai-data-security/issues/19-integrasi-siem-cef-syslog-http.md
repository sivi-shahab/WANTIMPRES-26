# 19: Integrasi SIEM (CEF/syslog, HTTP)

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 15
Spec: `../spec.md` §11; §12.3 Security telemetry

## Konteks
SOC bank bekerja dari SIEM yang sudah ada.

## Scope
- Export event dan incident ke CEF/syslog dan HTTP (HEC/Sentinel/Elastic).
- Security telemetry platform: perubahan policy, unmask, kill switch, dan kegagalan signature bundle.
- Retry + dead-letter queue.

## Acceptance criteria
- [ ] Test integrasi dengan minimal 1 SIEM target bank. *(Lokal: image `siem-export` → **syslog-ng 4.8 over TLS** (collector standar di depan QRadar/ArcSight), RFC 5424 + CEF terparse, 4/4 record diterima: event block, event allow risk 50, audit unmask, alert signature bundle; event allow risk 10 terfilter. SIEM target bank belum diketahui: jalankan ulang terhadap SIEM bank di staging.)*
- [x] Tidak ada raw content di payload export. *(Record dibangun dari allowlist field, snippet tidak diekspor, teks bebas (mis. justifikasi unmask) di-mask bila berisi deret digit NIK/PAN, key terlarang di target audit diganti `[REDACTED]`, dan `Record.Check` menolak (→ DLQ) apa pun yang masih tampak seperti konten. Dites unit untuk CEF, HEC, dan JSON; e2e: 0 kecocokan NIK/snippet di output syslog-ng.)*

## Keputusan
- Service baru `siem-export` dengan tiga sumber: event keputusan dari Kafka (hanya non-allow atau risk ≥ `SIEM_MIN_RISK`, default 40), **tail audit log** (cursor di Postgres, satu replica memegang cursor lewat `FOR UPDATE SKIP LOCKED`), dan webhook Alertmanager (bearer token). Audit log sudah memuat perubahan policy, unmask, perubahan role, break-glass, transisi incident; ticket ini menambah `incident.open` dan `incident.escalate`. Kill switch menyusul (ticket 30) lewat jalur audit yang sama.
- Kegagalan signature bundle berasal dari metrik OPA, jadi dikirim lewat Alertmanager → `siem-export` (`POST /alertmanager`).
- Sink: CEF over syslog RFC 5424, TLS, octet-counting RFC 6587/5425 (di syslog-ng: driver `syslog()`, bukan `network()`); HTTP Splunk HEC atau JSON array (Logstash/Elastic HTTP input, Sentinel DCR). 2xx terkirim, 4xx (kecuali 408/429) permanen.
- Retry eksponensial (6 percobaan, mulai 1 s), lalu DLQ topic `wantimpres26.siem.dlq.v1` (record yang sudah disanitasi + sink + alasan). Offset/cursor baru maju setelah terkirim atau masuk DLQ; jika DLQ gagal, tidak maju.
- Severity CEF: event = risk/10; audit: break-glass dan denial 9, unmask/role/publish/incident 7; alert dari label severity. `externalId` stabil agar SIEM bisa membuang duplikat setelah retry. Hash entri audit ikut, agar salinan di SIEM bisa dicocokkan dengan rantai.
- Metrik: `siem_records_sent_total`, `siem_send_retries_total`, `siem_records_dead_lettered_total`, `siem_audit_cursor`, `siem_audit_lag` + alert.

## Hasil verifikasi lokal (2026-10-03)
- Unit (escaping CEF, framing, no-raw-content, retry/DLQ, HTTP sink, webhook, syslog TLS + reconnect + CA tidak dipercaya ditolak), integrasi Postgres (audit tail sekali-per-entri dengan 2 replica), seluruh suite dengan `-race`; golangci-lint bersih.
- E2E di atas. Temuan: dengan driver syslog-ng yang salah (`network()`), 4 record "terkirim" tanpa error tetapi tidak diproses: syslog TCP tidak punya ack aplikasi.

## Sisa / follow-up
- Uji terhadap SIEM bank (QRadar/Splunk/Sentinel/Elastic) di staging; konfirmasi format (CEF vs JSON) dan field mapping dengan tim SOC.
- Syslog tanpa ack: pertimbangkan RELP atau sink HTTP bila SIEM harus mengonfirmasi penerimaan.
- Sentinel Logs Ingestion API butuh token AAD (belum); replay DLQ masih manual.
- TLS client certificate (mTLS) ke collector bila diwajibkan.
