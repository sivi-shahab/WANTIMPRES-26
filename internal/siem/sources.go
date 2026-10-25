package siem

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/events"
)

// Group is siem-export's consumer group on the decision event topic.
const Group = "siem-export"

// DLQTopic holds records no SIEM sink accepted, sanitized, for replay.
const DLQTopic = "wantimpres26.siem.dlq.v1"

// Exportable keeps the SIEM to what a SOC acts on: every non-allow decision and anything risky enough to matter.
func Exportable(e events.Event, minRisk int) bool {
	return e.Action != "allow" || e.RiskScore >= minRisk
}

// RunEvents exports decision events from Kafka. Offsets are committed after delivery (or dead-lettering).
func RunEvents(ctx context.Context, kc *kgo.Client, dec *events.Decoder, d *Deliverer, minRisk int, log *slog.Logger) error {
	for {
		fetches := kc.PollRecords(ctx, 500)
		if ctx.Err() != nil {
			return nil
		}
		fetches.EachError(func(t string, p int32, err error) { log.Error("fetch", "topic", t, "partition", p, "err", err) })
		var recs []Record
		var err error
		fetches.EachRecord(func(r *kgo.Record) {
			if err != nil {
				return
			}
			var payload []byte
			var reason string
			if payload, reason, err = dec.Decode(ctx, r.Value); err != nil || reason != "" {
				return // rejected records are counted by event-ingest; never exported
			}
			var e events.Event
			if json.Unmarshal(payload, &e) == nil && Exportable(e, minRisk) {
				recs = append(recs, FromEvent(e))
			}
		})
		if err != nil {
			return err
		}
		if err := d.Deliver(ctx, recs); err != nil {
			return err
		}
		if err := kc.CommitUncommittedOffsets(ctx); err != nil {
			log.Error("commit", "err", err)
		}
	}
}

// AuditTail exports the audit log in seq order from a cursor kept in Postgres (schema siem). Only one replica
// holds the cursor row at a time (FOR UPDATE SKIP LOCKED), so entries go out once.
type AuditTail struct {
	DB      *pgxpool.Pool
	Audit   *audit.Store
	Deliver *Deliverer
	Every   time.Duration
	Log     *slog.Logger
	cursor  atomic.Int64
	lag     atomic.Int64
}

func (a *AuditTail) Cursor() int64 { return a.cursor.Load() }

// Lag is how many audit entries exist beyond the cursor (as of the last batch).
func (a *AuditTail) Lag() int64 { return a.lag.Load() }

func (a *AuditTail) Run(ctx context.Context) error {
	if _, err := a.DB.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS siem;
		CREATE TABLE IF NOT EXISTS siem.cursor (name text PRIMARY KEY, seq bigint NOT NULL);
		INSERT INTO siem.cursor VALUES ('audit', 0) ON CONFLICT DO NOTHING`); err != nil {
		return err
	}
	for ctx.Err() == nil {
		n, err := a.batch(ctx)
		if err != nil && ctx.Err() == nil {
			a.Log.Error("audit export", "err", err)
		}
		if n == 0 || err != nil {
			select {
			case <-ctx.Done():
			case <-time.After(a.Every):
			}
		}
	}
	return nil
}

// batch exports up to 500 entries after the cursor and advances it in the same transaction.
func (a *AuditTail) batch(ctx context.Context) (int, error) {
	var n int
	err := pgx.BeginFunc(ctx, a.DB, func(tx pgx.Tx) error {
		var seq int64
		err := tx.QueryRow(ctx, "SELECT seq FROM siem.cursor WHERE name = 'audit' FOR UPDATE SKIP LOCKED").Scan(&seq)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // another replica is exporting
		} else if err != nil {
			return err
		}
		a.cursor.Store(seq)
		var head int64
		if err := tx.QueryRow(ctx, "SELECT coalesce(max(seq), 0) FROM audit.audit_log").Scan(&head); err != nil {
			return err
		}
		a.lag.Store(head - seq)
		entries, err := a.Audit.After(ctx, seq, 500)
		if err != nil || len(entries) == 0 {
			return err
		}
		recs := make([]Record, len(entries))
		for i, e := range entries {
			recs[i] = FromAudit(e)
		}
		if err := a.Deliver.Deliver(ctx, recs); err != nil {
			return err
		}
		last := entries[len(entries)-1].Seq
		if _, err := tx.Exec(ctx, "UPDATE siem.cursor SET seq = $1 WHERE name = 'audit'", last); err != nil {
			return err
		}
		a.cursor.Store(last)
		a.lag.Store(head - last)
		n = len(entries)
		return nil
	})
	return n, err
}

// AlertmanagerHandler receives Alertmanager webhooks (bearer token, compared by SHA-256) and exports the alerts:
// bundle signature failures, break-glass use, ack SLA misses (deploy/cluster/alerts.yaml). 5xx makes
// Alertmanager retry when even the DLQ failed.
func AlertmanagerHandler(tokenSHA256 []byte, d *Deliverer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
		if subtle.ConstantTimeCompare(got[:], tokenSHA256) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct {
			Alerts []Alert `json:"alerts"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		recs := make([]Record, len(body.Alerts))
		for i, al := range body.Alerts {
			recs[i] = FromAlert(al)
		}
		if err := d.Deliver(r.Context(), recs); err != nil {
			http.Error(w, "delivery failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
