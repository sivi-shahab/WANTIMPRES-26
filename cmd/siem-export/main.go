package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sr"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/events"
	"wantimpres26/internal/privacy"
	"wantimpres26/internal/server"
	"wantimpres26/internal/siem"
)

// Env: KAFKA_* (events.KafkaOpts), SCHEMA_REGISTRY_URL, DATABASE_URL (audit log + cursor), SIEM_MIN_RISK (default 40),
// syslog sink: SIEM_SYSLOG_ADDR, SIEM_SYSLOG_CA_FILE (TLS; SIEM_SYSLOG_PLAINTEXT=true only for a local collector),
// HTTP sink: SIEM_HTTP_URL, SIEM_HTTP_FORMAT (hec|json), SIEM_HTTP_AUTH_FILE (Authorization header value),
// ALERTMANAGER_TOKEN_SHA256 (hex), SOAR webhook: SOAR_WEBHOOK_URL + SOAR_WEBHOOK_SECRET_FILE (HMAC key). At least one sink.
func main() {
	log := privacy.NewLogger("siem-export")
	fail := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithCancel(context.Background())

	var sinks []siem.Sink
	if addr := os.Getenv("SIEM_SYSLOG_ADDR"); addr != "" {
		host, _ := os.Hostname()
		s := &siem.Syslog{Addr: addr, Hostname: host}
		if os.Getenv("SIEM_SYSLOG_PLAINTEXT") != "true" {
			pool, err := caPool(os.Getenv("SIEM_SYSLOG_CA_FILE"))
			if err != nil {
				fail("syslog CA", err)
			}
			s.TLS = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		}
		sinks = append(sinks, s)
	}
	if url := os.Getenv("SIEM_HTTP_URL"); url != "" {
		h := http.Header{}
		if f := os.Getenv("SIEM_HTTP_AUTH_FILE"); f != "" {
			auth, err := os.ReadFile(f)
			if err != nil {
				fail("SIEM HTTP auth", err)
			}
			h.Set("Authorization", strings.TrimSpace(string(auth)))
		}
		sinks = append(sinks, &siem.HTTP{URL: url, Format: os.Getenv("SIEM_HTTP_FORMAT"), Header: h, Client: &http.Client{Timeout: 30 * time.Second}})
	}
	// SOAR webhook (ticket 26): the incident records of the audit stream, signed.
	if url := os.Getenv("SOAR_WEBHOOK_URL"); url != "" {
		secret, err := os.ReadFile(os.Getenv("SOAR_WEBHOOK_SECRET_FILE"))
		if err != nil || len(bytes.TrimSpace(secret)) < 32 {
			fail("SOAR_WEBHOOK_SECRET_FILE (at least 32 bytes)", err)
		}
		sinks = append(sinks, &siem.Filtered{Label: "soar", Keep: siem.SOARRecord,
			Sink: &siem.HTTP{URL: url, Format: "json", Header: http.Header{}, Secret: bytes.TrimSpace(secret), Client: &http.Client{Timeout: 30 * time.Second}}})
	}
	if len(sinks) == 0 {
		fail("no SIEM sink", errors.New("set SIEM_SYSLOG_ADDR and/or SIEM_HTTP_URL"))
	}

	kafka, err := events.KafkaOpts(os.Getenv)
	if err != nil {
		fail("kafka config", err)
	}
	producer, err := kgo.NewClient(append(kafka, kgo.DefaultProduceTopic(siem.DLQTopic))...)
	if err != nil {
		fail("kafka producer", err)
	}
	metrics := siem.NewMetrics()
	deliverer := &siem.Deliverer{Sinks: sinks, MaxAttempts: 6, Backoff: time.Second, Log: log, Metrics: metrics,
		DLQ: func(ctx context.Context, sink string, r siem.Record, reason string) error {
			return producer.ProduceSync(ctx, &kgo.Record{Key: []byte(r.ID), Value: siem.DLQMessage(sink, r, reason)}).FirstErr()
		}}

	db, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		fail("database", err)
	}
	auditLog, err := audit.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		fail("audit log", err)
	}
	tail := &siem.AuditTail{DB: db, Audit: auditLog, Deliver: deliverer, Every: 2 * time.Second, Log: log}
	metrics.AuditCursor, metrics.AuditLag = tail.Cursor, tail.Lag
	go func() {
		if err := tail.Run(ctx); err != nil {
			fail("audit export", err)
		}
	}()

	consumer, err := kgo.NewClient(append(kafka, kgo.ConsumerGroup(siem.Group), kgo.ConsumeTopics(events.Topic), kgo.DisableAutoCommit())...)
	if err != nil {
		fail("kafka consumer", err)
	}
	rc, err := sr.NewClient(sr.URLs(os.Getenv("SCHEMA_REGISTRY_URL")))
	if err != nil {
		fail("schema registry", err)
	}
	minRisk := 40
	if v := os.Getenv("SIEM_MIN_RISK"); v != "" {
		if minRisk, err = strconv.Atoi(v); err != nil {
			fail("SIEM_MIN_RISK", err)
		}
	}
	go func() {
		if err := siem.RunEvents(ctx, consumer, &events.Decoder{SR: rc}, deliverer, minRisk, log); err != nil {
			fail("event export", err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		metrics.Write(w)
	})
	if h := os.Getenv("ALERTMANAGER_TOKEN_SHA256"); h != "" {
		sum, err := hex.DecodeString(h)
		if err != nil || len(sum) != sha256.Size {
			fail("ALERTMANAGER_TOKEN_SHA256 must be a hex SHA-256", err)
		}
		mux.Handle("POST /alertmanager", siem.AlertmanagerHandler(sum, deliverer))
	}
	server.Run("siem-export", mux)
	cancel()
	consumer.Close()
	producer.Close()
}

func caPool(file string) (*x509.CertPool, error) {
	if file == "" {
		return x509.SystemCertPool()
	}
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no certificates in " + file)
	}
	return pool, nil
}
