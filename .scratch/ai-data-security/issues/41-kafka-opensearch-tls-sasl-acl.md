# 41: Kafka/OpenSearch: TLS, SASL/mTLS client, ACL topic per producer

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M2
Blocked by: 15
Spec: `../spec.md` §10.1 Encryption; `docs/threat-model.md` G2

## Konteks
Threat model (tiket 02) G2: client Kafka belum mengonfigurasi TLS/SASL (catatan tiket 15). Siapa pun di jaringan bisa memproduksi decision event palsu (insiden palsu, atau banjir untuk menyamarkan serangan) atau membaca event. OpenSearch belum diautentikasi dari client.

## Scope
- Konfigurasi TLS + SASL (SCRAM atau mTLS) di producer/consumer (`internal/events`, event-ingest, incident, siem-export).
- ACL topic: hanya PEP yang boleh produce ke `decision_event`, consumer per group.
- Client OpenSearch dengan TLS + auth.

## Acceptance criteria
- [x] Producer tanpa kredensial ditolak broker (test integrasi). *(`TestBrokerACLs` terhadap Kafka 3.9 asli (listener SASL + `StandardAuthorizer`): client tanpa SASL dan client dengan password salah gagal produce, dan topic hanya berisi record dari PEP.)*
- [x] Event dari principal yang bukan PEP ditolak atau ditandai. *(Ditolak broker. Di test yang sama, akun `siem-export` yang terautentikasi (SCRAM-SHA-512, hanya punya grant consume) ditolak dengan `CLUSTER_AUTHORIZATION_FAILED`: idempotent producer tanpa WRITE topic sudah gagal di InitProducerID, sebelum mencapai topic. Daftar grant produksi ada di `cmd/event-ingest` (`grants`): hanya `ai-gateway` dan `mcp-gateway` yang boleh produce ke `wantimpres26.decision_event.v1`.)*
- [x] Koneksi plaintext ke Kafka/OpenSearch gagal di konfigurasi produksi. *(Default-nya TLS. `events.KafkaOpts` menolak konfigurasi tanpa identitas client dan selalu memakai TLS kecuali `KAFKA_PLAINTEXT=true`. `ingest.OpenSearchFromEnv` menolak `http://` dan konfigurasi tanpa user/password kecuali `OPENSEARCH_PLAINTEXT=true`. `TestKafkaTLSVerifiesBroker` dan `TestOpenSearchFromEnv`: sertifikat server diverifikasi terhadap CA yang dikonfigurasi, dan CA lain ditolak.)*

## Keputusan
- **Satu fungsi koneksi per backend:** `events.KafkaOpts(os.Getenv)` dipakai semua service Kafka (ai-gateway, mcp-gateway, control-plane, event-ingest, siem-export). Fungsi ini mengatur TLS 1.2+ (`KAFKA_CA_FILE`), SASL `SCRAM-SHA-512` (default) atau `PLAIN` (`KAFKA_SASL_USER` + `KAFKA_SASL_PASSWORD_FILE`), dan/atau sertifikat client mTLS (`KAFKA_CERT_FILE`/`KAFKA_KEY_FILE`). `ingest.OpenSearchFromEnv` dipakai event-ingest dan control-plane (https, basic auth, `OPENSEARCH_CA_FILE`). Opt-out plaintext hanya boleh untuk local/CI dan harus eksplisit (`*_PLAINTEXT=true`).
- **ACL sebagai data:** `events.Grant` + `events.ApplyACLs` (kadm, idempoten). `event-ingest kafka-acls` dijalankan sekali sebagai Job dengan kredensial admin broker. Broker wajib memakai authorizer tanpa `allow.everyone.if.no.acl.found`, jadi yang tidak di-grant ditolak. Principal = user SASL per service (nama service).
- **Deploy:** setiap service Kafka memakai `KAFKA_SASL_USER` = nama service, dan file CA/password dari Secret `<service>-bus` yang di-mount di `/bus`.
- `events.NewProducer` kini menerima opsi koneksi (termasuk broker) dari pemanggil. `DLQTopic` pindah ke `siem.DLQTopic` agar bisa direferensikan oleh grant.
- **CI:** broker Kafka mendapat listener `SASL` (:9094, PLAIN untuk admin + SCRAM-SHA-512) dan `StandardAuthorizer`. Listener PLAINTEXT tetap ada untuk test pipeline lama (ANONYMOUS = super user, hanya di CI). Variabel baru: `IT_KAFKA_SASL_BROKERS`, `IT_KAFKA_ADMIN_PASSWORD`.

## Hasil verifikasi lokal (2026-10-10)
- Broker Kafka 3.9.0 dengan konfigurasi persis seperti `.gitlab-ci.yml` (+ karapace, OpenSearch 2.19.3): `go vet ./...` bersih, dan `go test -race ./...` dengan semua env IT_* hijau, termasuk `TestPipelineIntegration` (ingest) terhadap broker yang authorizer-nya aktif. golangci-lint v2.5.0: 0 issue.
- Saat suite penuh berjalan bersamaan dengan pekerjaan lain (load average ~35 di 16 core), `mcpgw TestKillSwitch` (anggaran 2 detik) dan dua test Rego (deadline evaluasi) gagal karena waktu habis. Paket itu tidak disentuh. Saat dijalankan ulang: `policysvc` hijau, dan `TestKillSwitch` sendirian lulus (1,95 detik).

## Sisa
- TLS ke broker dan OpenSearch *asli* hanya diuji lewat stand-in TLS lokal (verifikasi CA di sisi client). Listener SSL/HTTPS sungguhan di CI butuh sertifikat yang tidak bisa disuntikkan ke service GitLab. Perlu diuji di staging dengan CA bank.
- Schema registry (karapace) masih tanpa TLS/auth dari client (`sr.NewClient` hanya URL). Ini di luar scope tiket, tapi registry palsu bisa mengacaukan decode. Perlu tiket lanjutan.
- Kafka dan OpenSearch sendiri (listener TLS, user SCRAM, role security plugin, Job `kafka-acls`) dikelola tim platform. Repo hanya menyediakan sisi client, daftar grant, dan Secret yang diharapkan.
