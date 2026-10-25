package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"wantimpres26/internal/aigw"
	"wantimpres26/internal/events"
	"wantimpres26/internal/mcpgw"
	"wantimpres26/internal/privacy"
	"wantimpres26/internal/server"
	"wantimpres26/internal/tokvault"
)

// Env: AIGW_CONFIG_FILE (aigw.Config: apps with gateway key hashes and limits, providers with vault key files),
// OPA_URL (default http://127.0.0.1:8181, the sidecar), KAFKA_* (events.KafkaOpts), SCHEMA_REGISTRY_URL, TENANT_ID,
// TENANT_PEPPER, REDIS_URL (rate limits and token quotas shared across replicas; without it, per replica),
// VAULT_URLS (comma-separated token-vault URLs, tried in order; without it, tokenize redacts) and VAULT_TOKEN,
// DETECTION_URL (detection-svc over mTLS from MTLS_DIR: the L2 shadow report in decision events, ticket 49; without
// it, none) and DETECTION_TIMEOUT (Go duration, default 150ms, spec §13.3).
func main() {
	log := privacy.NewLogger("ai-gateway")
	fail := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(1)
	}
	ctx := context.Background()
	for _, k := range []string{"AIGW_CONFIG_FILE", "TENANT_ID", "TENANT_PEPPER"} {
		if os.Getenv(k) == "" {
			fail("config", errors.New(k+" is required"))
		}
	}
	raw, err := os.ReadFile(os.Getenv("AIGW_CONFIG_FILE"))
	if err != nil {
		fail("AIGW_CONFIG_FILE", err)
	}
	cfg, err := aigw.ParseConfig(raw)
	if err != nil {
		fail("AIGW_CONFIG_FILE", err)
	}
	providers := map[string]aigw.Provider{}
	for _, p := range cfg.Providers {
		providers[p.Name] = p
	}
	kafka, err := events.KafkaOpts(os.Getenv)
	if err != nil {
		fail("kafka config", err)
	}
	producer, err := events.NewProducer(ctx, os.Getenv("SCHEMA_REGISTRY_URL"), kafka...)
	if err != nil {
		fail("event producer", err)
	}
	defer producer.Close()
	count := aigw.MemoryCounter(time.Now)
	metrics := producer.WriteMetrics
	if u := os.Getenv("REDIS_URL"); u != "" {
		opt, err := redis.ParseURL(u)
		if err != nil {
			fail("REDIS_URL", err)
		}
		// Redis answers in about a millisecond; a counter must never cost the request more than this (ticket 48).
		// The URL's own dial_timeout/read_timeout/max_retries win.
		for _, t := range []*time.Duration{&opt.DialTimeout, &opt.ReadTimeout, &opt.WriteTimeout, &opt.PoolTimeout} {
			if *t == 0 {
				*t = 50 * time.Millisecond
			}
		}
		if opt.MaxRetries == 0 {
			opt.MaxRetries = -1
		}
		d := &aigw.Degraded{Primary: aigw.RedisCounter(redis.NewClient(opt)), Local: count, Cooldown: 5 * time.Second, Now: time.Now, Log: log}
		count = d.Count
		metrics = func(w io.Writer) { producer.WriteMetrics(w); d.WriteMetrics(w) }
	}
	var vault *tokvault.Client
	if u := os.Getenv("VAULT_URLS"); u != "" {
		vault = &tokvault.Client{URLs: strings.Split(u, ","), Token: os.Getenv("VAULT_TOKEN"), HTTP: &http.Client{Timeout: 2 * time.Second}}
	}
	opaURL := os.Getenv("OPA_URL")
	if opaURL == "" {
		opaURL = "http://127.0.0.1:8181"
	}
	opa := &mcpgw.OPA{URL: opaURL, HTTP: &http.Client{Timeout: 2 * time.Second}}
	var detection *aigw.Detection
	if u := os.Getenv("DETECTION_URL"); u != "" {
		hc, err := server.MTLSClient(0, "spiffe://wantimpres26.bank/ns/wantimpres26/sa/detection-svc")
		if err != nil {
			fail("detection-svc client", err)
		}
		detection = &aigw.Detection{URL: u, HTTP: hc, Timeout: 150 * time.Millisecond}
		if d, err := time.ParseDuration(os.Getenv("DETECTION_TIMEOUT")); err == nil && d > 0 {
			detection.Timeout = d
		}
	}
	gw := &aigw.Gateway{
		Apps: cfg.Apps, Providers: providers, Decide: opa.Decide, Key: (&aigw.KeyFiles{}).Key, Count: count, Vault: vault,
		Emit: func(_ context.Context, e events.Event) error { return producer.Publish(e) }, Metrics: metrics,
		// Models take their time: bound the wait for response headers, generously.
		Upstream: &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, ResponseHeaderTimeout: 120 * time.Second}},
		Pepper:   []byte(os.Getenv("TENANT_PEPPER")), TenantID: os.Getenv("TENANT_ID"), Now: time.Now, Log: log,
		Detection: detection,
	}
	mux := http.NewServeMux()
	gw.Routes(mux)
	server.Run("ai-gateway", mux)
}
