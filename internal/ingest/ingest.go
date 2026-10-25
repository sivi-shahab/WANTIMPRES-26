// Package ingest is the event-ingest consumer: decision events from Kafka, validated against their registered
// schema and the raw-content check, indexed into daily OpenSearch indices (spec §5.1, §10.2).
package ingest

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sr"

	"wantimpres26/internal/events"
)

const Group = "event-ingest"

// Ingester consumes events.Topic. At-least-once: offsets are committed only after OpenSearch accepted the batch,
// and documents are indexed by event_id so redelivery overwrites instead of duplicating.
type Ingester struct {
	KC      *kgo.Client // consumer group Group on events.Topic, autocommit disabled
	SR      *sr.Client
	OS      *OpenSearch
	Metrics *Metrics
	Log     *slog.Logger

	dec events.Decoder
}

// Run consumes until ctx is cancelled.
func (in *Ingester) Run(ctx context.Context) error {
	in.dec = events.Decoder{SR: in.SR}
	go in.trackLag(ctx)
	for {
		fetches := in.KC.PollRecords(ctx, 1000)
		if ctx.Err() != nil {
			return nil
		}
		fetches.EachError(func(t string, p int32, err error) { in.Log.Error("fetch", "topic", t, "partition", p, "err", err) })
		var docs []Doc
		var err error
		fetches.EachRecord(func(r *kgo.Record) {
			if err != nil {
				return
			}
			in.Metrics.Consumed.Add(1)
			var d Doc
			if d, err = in.accept(ctx, r); err == nil && d.ID != "" {
				docs = append(docs, d)
			}
		})
		if err != nil {
			return err // registry unreachable: crash and redeliver rather than reject good events
		}
		if err := in.index(ctx, docs); err != nil {
			return err
		}
		if err := in.KC.CommitUncommittedOffsets(ctx); err != nil {
			in.Log.Error("commit", "err", err)
		}
	}
}

// accept returns the document to index, or a zero Doc when the record is rejected (and counted).
func (in *Ingester) accept(ctx context.Context, r *kgo.Record) (Doc, error) {
	payload, reason, err := in.dec.Decode(ctx, r.Value)
	if err != nil {
		return Doc{}, err
	}
	var meta struct {
		EventID string    `json:"event_id"`
		TS      time.Time `json:"ts"`
	}
	if reason == "" && json.Unmarshal(payload, &meta) != nil {
		reason = events.RejectSchema
	}
	if reason != "" {
		// Count and log where the record was; never its content.
		in.Metrics.Rejected(reason)
		in.Log.Warn("event rejected", "reason", reason, "partition", r.Partition, "offset", r.Offset)
		return Doc{}, nil
	}
	return Doc{Index: IndexFor(meta.TS), ID: meta.EventID, Body: payload, Received: r.Timestamp}, nil
}

// index retries until OpenSearch takes the batch or ctx ends: nothing is committed before that.
func (in *Ingester) index(ctx context.Context, docs []Doc) error {
	for backoff := time.Second; len(docs) > 0; backoff = min(2*backoff, 30*time.Second) {
		failed, err := in.OS.Bulk(ctx, docs)
		if err == nil {
			in.Metrics.Indexed.Add(int64(len(docs) - failed))
			in.Metrics.IndexFailed.Add(int64(failed))
			now := time.Now()
			for _, d := range docs {
				in.Metrics.ObserveDelay(now.Sub(d.Received))
			}
			return nil
		}
		in.Log.Error("bulk index, retrying", "err", err, "docs", len(docs), "backoff", backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
	return nil
}

func (in *Ingester) trackLag(ctx context.Context) {
	adm := kadm.NewClient(in.KC)
	for t := time.NewTicker(10 * time.Second); ; {
		lags, err := adm.Lag(ctx, Group)
		if err == nil {
			for _, gl := range lags {
				for topic, parts := range gl.Lag {
					for p, l := range parts {
						in.Metrics.SetLag(topic, p, l.Lag)
					}
				}
			}
		} else if ctx.Err() == nil {
			in.Log.Error("consumer lag", "err", err)
		}
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}
