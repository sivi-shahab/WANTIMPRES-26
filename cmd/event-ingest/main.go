package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sr"

	"wantimpres26/internal/events"
	"wantimpres26/internal/ingest"
	"wantimpres26/internal/privacy"
	"wantimpres26/internal/server"
	"wantimpres26/internal/siem"
)

// Env: KAFKA_* (events.KafkaOpts), SCHEMA_REGISTRY_URL, OPENSEARCH_* (ingest.OpenSearchFromEnv).
func main() {
	// `event-ingest kafka-acls`: run once (Job) with the broker admin's KAFKA_* credentials.
	if len(os.Args) > 1 && os.Args[1] == "kafka-acls" {
		kafka, err := events.KafkaOpts(os.Getenv)
		if err == nil {
			var admin *kgo.Client
			if admin, err = kgo.NewClient(kafka...); err == nil {
				err = events.ApplyACLs(context.Background(), admin, grants)
				admin.Close()
			}
		}
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "kafka-acls:", err)
			os.Exit(1)
		}
		return
	}
	log := privacy.NewLogger("event-ingest")
	fail := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithCancel(context.Background())

	kafka, err := events.KafkaOpts(os.Getenv)
	if err != nil {
		fail("kafka config", err)
	}
	kc, err := kgo.NewClient(append(kafka,
		kgo.ConsumerGroup(ingest.Group),
		kgo.ConsumeTopics(events.Topic),
		kgo.DisableAutoCommit(),
	)...)
	if err != nil {
		fail("kafka client", err)
	}
	rc, err := sr.NewClient(sr.URLs(os.Getenv("SCHEMA_REGISTRY_URL")))
	if err != nil {
		fail("schema registry client", err)
	}
	search, err := ingest.OpenSearchFromEnv(os.Getenv, 30*time.Second)
	if err != nil {
		fail("opensearch config", err)
	}
	if err := search.Setup(ctx); err != nil {
		fail("opensearch setup", err)
	}

	metrics := ingest.NewMetrics()
	in := &ingest.Ingester{KC: kc, SR: rc, OS: search, Metrics: metrics, Log: log}
	go func() {
		// Any error here is one retrying cannot fix in-process: restart and redeliver from the last commit.
		if err := in.Run(ctx); err != nil {
			fail("ingest stopped", err)
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", metrics)
	server.Run("event-ingest", mux)
	cancel()
	kc.Close()
}

// grants is who may do what on the event bus (ticket 41): only the PEPs produce decision events. Principals are the
// services' SASL users (or mTLS certificate CNs); the broker refuses everything not listed (no
// allow.everyone.if.no.acl.found).
var grants = []events.Grant{
	{Principal: "User:ai-gateway", Produce: []string{events.Topic}},
	{Principal: "User:mcp-gateway", Produce: []string{events.Topic}},
	{Principal: "User:event-ingest", Consume: []string{events.Topic}, Groups: []string{ingest.Group}},
	{Principal: "User:control-plane", Consume: []string{events.Topic}, Groups: []string{"control-plane"}}, // cmd/control-plane consumerGroup
	{Principal: "User:siem-export", Consume: []string{events.Topic}, Groups: []string{siem.Group}, Produce: []string{siem.DLQTopic}},
}
