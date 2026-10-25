package ingest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sr"

	"wantimpres26/internal/events"
)

// Retention (spec §10.2): 90 days hot, deleted at 400 days, attached to every daily index.
func TestRetentionPolicy(t *testing.T) {
	var p struct {
		Policy struct {
			States []struct {
				Name        string
				Actions     []map[string]any
				Transitions []struct {
					StateName  string `json:"state_name"`
					Conditions struct {
						MinIndexAge string `json:"min_index_age"`
					}
				}
			}
			ISMTemplate []struct {
				IndexPatterns []string `json:"index_patterns"`
			} `json:"ism_template"`
		}
	}
	if err := json.Unmarshal(ismPolicy, &p); err != nil {
		t.Fatal(err)
	}
	ages := map[string]string{}
	for _, s := range p.Policy.States {
		for _, tr := range s.Transitions {
			ages[tr.StateName] = tr.Conditions.MinIndexAge
		}
	}
	if ages["warm"] != "90d" || ages["delete"] != "400d" {
		t.Errorf("transitions %v, want warm at 90d and delete at 400d", ages)
	}
	if len(p.Policy.ISMTemplate) != 1 || !slices.Contains(p.Policy.ISMTemplate[0].IndexPatterns, IndexPrefix+"*") {
		t.Errorf("policy not attached to %s*", IndexPrefix)
	}
	if got := IndexFor(time.Date(2026, 10, 3, 23, 30, 0, 0, time.FixedZone("WIB", 7*3600))); got != IndexPrefix+"2026.10.03" {
		t.Errorf("IndexFor = %s", got)
	}
}

func TestMetricsExposition(t *testing.T) {
	m := NewMetrics()
	m.Consumed.Add(3)
	m.Rejected(events.RejectRawContent)
	m.SetLag(events.Topic, 1, 7)
	m.ObserveDelay(3 * time.Second)
	var b bytes.Buffer
	m.write(&b)
	for _, want := range []string{
		"events_consumed_total 3",
		`events_rejected_total{reason="raw_content"} 1`,
		`kafka_consumer_lag{group="event-ingest",topic="wantimpres26.decision_event.v1",partition="1"} 7`,
		`event_index_delay_seconds_bucket{le="2"} 0`,
		`event_index_delay_seconds_bucket{le="5"} 1`,
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in\n%s", want, b.String())
		}
	}
}

func uuid() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func hex(n int) string {
	b := make([]byte, n/2)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Needs Kafka + a Confluent-compatible schema registry + OpenSearch (CI job test:integration). Skipped only outside CI.
func TestPipelineIntegration(t *testing.T) {
	brokers, registry, search := os.Getenv("IT_KAFKA_BROKERS"), os.Getenv("IT_SCHEMA_REGISTRY_URL"), os.Getenv("IT_OPENSEARCH_URL")
	if brokers == "" || registry == "" || search == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("IT_KAFKA_BROKERS / IT_SCHEMA_REGISTRY_URL / IT_OPENSEARCH_URL must be set in CI")
		}
		t.Skip("no Kafka/registry/OpenSearch")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	admin, err := kgo.NewClient(kgo.SeedBrokers(brokers))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := kadm.NewClient(admin).CreateTopic(ctx, 3, 1, nil, events.Topic); err != nil && !strings.Contains(err.Error(), "TOPIC_ALREADY_EXISTS") {
		t.Fatal(err)
	}

	os := &OpenSearch{URL: search, HTTP: &http.Client{Timeout: 30 * time.Second}}
	if err := os.Setup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.Setup(ctx); err != nil { // second run updates the existing policy
		t.Fatalf("setup is not idempotent: %v", err)
	}
	kc, err := kgo.NewClient(kgo.SeedBrokers(brokers), kgo.ConsumerGroup(Group), kgo.ConsumeTopics(events.Topic),
		kgo.DisableAutoCommit(), kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	if err != nil {
		t.Fatal(err)
	}
	defer kc.Close()
	rc, _ := sr.NewClient(sr.URLs(registry))
	metrics := NewMetrics()
	in := &Ingester{KC: kc, SR: rc, OS: os, Metrics: metrics, Log: slog.New(slog.DiscardHandler)}
	runCtx, stop := context.WithCancel(ctx)
	runErr := make(chan error, 1)
	go func() { runErr <- in.Run(runCtx) }()

	prod, err := events.NewProducer(ctx, registry, kgo.SeedBrokers(brokers))
	if err != nil {
		t.Fatal(err)
	}
	defer prod.Close()

	// Bad records, each a different rejection reason.
	raw, _ := kgo.NewClient(kgo.SeedBrokers(brokers), kgo.DefaultProduceTopic(events.Topic))
	defer raw.Close()
	ours, err := rc.CreateSchema(ctx, events.Subject, sr.Schema{Schema: events.SchemaV1, Type: sr.TypeJSON})
	if err != nil {
		t.Fatal(err)
	}
	loose, err := rc.CreateSchema(ctx, "someone-else-value", sr.Schema{Schema: `{"type": "object"}`, Type: sr.TypeJSON})
	if err != nil {
		t.Fatal(err)
	}
	wire := func(id int, v any) []byte {
		b, _ := json.Marshal(v)
		var h sr.ConfluentHeader
		out, _ := h.AppendEncode(nil, id, nil)
		return append(out, b...)
	}
	goodEvent := func() events.Event {
		return events.Event{EventID: uuid(), TenantID: "00000000-0000-0000-0000-000000000001", TS: time.Now().UTC().Format(time.RFC3339Nano),
			TraceID: hex(32), Channel: "ai_gateway", Direction: "request", PrincipalID: hex(64), AppID: "chatgpt", Action: "redact",
			ReasonCodes: []string{"PCI_PAN"}, PolicyVersion: "builtin-1", RiskScore: 64, RiskVersion: "risk-1",
			Classes: []events.Class{{Type: "PCI.PAN", Count: 1, Confidence: 0.99}}, ContentHash: hex(64), Snippet: "kartu [REDACTED:PCI.PAN]"}
	}
	withPrompt := map[string]any{"event_id": uuid(), "prompt": "NIK saya 3171234567890001"}
	unredacted := goodEvent()
	unredacted.Snippet = "NIK 3171234567890001"
	for _, v := range [][]byte{
		wire(ours.ID, withPrompt),       // raw_content
		wire(ours.ID, unredacted),       // unredacted_snippet
		[]byte(`{"event_id": "x"}`),     // wire_format: no registry header
		wire(loose.ID, goodEvent()),     // unknown_schema: a looser schema from another subject
		wire(ours.ID, map[string]any{}), // schema
	} {
		if err := raw.ProduceSync(ctx, &kgo.Record{Value: v}).FirstErr(); err != nil {
			t.Fatal(err)
		}
	}

	// Good events, published over ~20 s like a steady PEP, while a poller records when each first shows in search.
	const n = 200
	var mu sync.Mutex
	published := map[string]time.Time{}
	seen := map[string]time.Duration{}
	pollCtx, stopPoll := context.WithCancel(ctx)
	polled := make(chan struct{})
	go func() {
		defer close(polled)
		for pollCtx.Err() == nil {
			code, body, err := os.do(pollCtx, http.MethodGet, "/"+IndexPrefix+"*/_search?size=10000&_source=false", nil, "application/json")
			if err == nil && code == 200 {
				var res struct {
					Hits struct {
						Hits []struct {
							ID string `json:"_id"`
						}
					}
				}
				_ = json.Unmarshal(body, &res)
				now := time.Now()
				mu.Lock()
				for _, h := range res.Hits.Hits {
					if at, ok := published[h.ID]; ok && seen[h.ID] == 0 {
						seen[h.ID] = now.Sub(at)
					}
				}
				done := len(seen) == n
				mu.Unlock()
				if done {
					return
				}
			}
			time.Sleep(250 * time.Millisecond)
		}
	}()
	var index string
	for i := range n {
		e := goodEvent()
		mu.Lock()
		published[e.EventID] = time.Now()
		mu.Unlock()
		if err := prod.Publish(e); err != nil {
			t.Fatal(err)
		}
		index = IndexFor(time.Now())
		if i%10 == 9 {
			time.Sleep(time.Second)
		}
	}
	select {
	case <-polled:
	case <-time.After(2 * time.Minute):
	}
	stopPoll()
	<-polled
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != n {
		t.Fatalf("%d of %d events searchable", len(seen), n)
	}
	delays := make([]time.Duration, 0, n)
	for _, d := range seen {
		delays = append(delays, d)
	}
	slices.Sort(delays)
	p95 := delays[n*95/100-1]
	t.Logf("publish-to-searchable: p50 %v, p95 %v, max %v", delays[n/2], p95, delays[n-1])
	if p95 > 60*time.Second {
		t.Errorf("p95 %v > 60s", p95)
	}

	// Lag is refreshed every 10 s.
	var text bytes.Buffer
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		text.Reset()
		metrics.write(&text)
		if strings.Contains(text.String(), "kafka_consumer_lag{") {
			break
		}
	}
	// The topic may hold records from earlier runs: counters are lower bounds, the exact check is the _count below.
	if got := metrics.Indexed.Load(); got < n {
		t.Errorf("events_indexed_total %d < %d", got, n)
	}
	for _, want := range []string{
		"kafka_consumer_lag{",
		`events_rejected_total{reason="raw_content"}`,
		`events_rejected_total{reason="unredacted_snippet"}`,
		`events_rejected_total{reason="wire_format"}`,
		`events_rejected_total{reason="unknown_schema"}`,
		`events_rejected_total{reason="schema"}`,
	} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("metrics missing %q:\n%s", want, text.String())
		}
	}

	// Exactly our events reached the index: none of the rejected ones (they share none of these ids).
	ids, _ := json.Marshal(slices.Collect(maps.Keys(published)))
	q := fmt.Sprintf(`{"query": {"bool": {"should": [{"ids": {"values": %s}}, {"term": {"event_id": %q}}]}}}`, ids, withPrompt["event_id"])
	code, body, _ := os.do(ctx, http.MethodPost, "/"+IndexPrefix+"*/_count", []byte(q), "application/json")
	if code != 200 || !strings.Contains(string(body), fmt.Sprintf(`"count":%d`, n)) {
		t.Errorf("index count: %d %s, want exactly %d", code, body, n)
	}
	// The retention policy is attached to the daily index.
	_, body, _ = os.do(ctx, http.MethodGet, "/_plugins/_ism/explain/"+index, nil, "application/json")
	if !strings.Contains(string(body), `"policy_id":"wantimpres26-events"`) {
		t.Errorf("ISM policy not attached to %s: %s", index, body)
	}

	stop()
	if err := <-runErr; err != nil {
		t.Errorf("ingest returned %v", err)
	}
}
