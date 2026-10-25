// Package objstore is the connector for object storage — S3-compatible (MinIO on-prem, AWS S3, GCS through its
// S3-interoperable XML API) and Azure Blob — behind one Backend interface (spec §4.3 FR-DATA-2: incremental from
// event notifications). A bucket is a container. The first pass lists the bucket; after that the feed is the
// bucket's event notifications, which Receiver writes into Postgres (data.object_events) as they arrive.
package objstore

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/connector"
)

//go:embed schema.sql
var schemaSQL string

// Open applies the event queue schema.
func Open(ctx context.Context, db *pgxpool.Pool) error {
	if _, err := db.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("apply object event schema: %w", err)
	}
	return nil
}

// Object is one listed object.
type Object struct {
	Key      string
	ETag     string // normalized: lower-case hex or opaque tag, no quotes; the same form the events carry
	Size     int64
	Modified time.Time
}

// Backend is one object-storage API.
type Backend interface {
	Kind() string // s3 | gcs | azure
	Buckets(ctx context.Context) ([]string, error)
	// List returns up to a page of objects after marker, and the marker for the next page ("" = last page).
	List(ctx context.Context, bucket, marker string) ([]Object, string, error)
	Get(ctx context.Context, bucket, key string, maxBytes int64) ([]byte, error)
	// Public: anyone (no credentials) can read objects of the bucket.
	Public(ctx context.Context, bucket string) (bool, error)
}

// Store is the connector for one source (one account / endpoint).
type Store struct {
	Source  string // data source id; events are stored under it
	DB      *pgxpool.Pool
	Backend Backend
	Buckets []string // only these buckets; empty = every bucket the credentials can list
	// PolicyCache: how long a bucket's public/not-public answer is reused (0 = read it for every item).
	PolicyCache time.Duration
	// QuarantineBucket receives quarantined objects (ticket 33); "" = no quarantine. Keep it out of Buckets.
	QuarantineBucket string

	mu     sync.Mutex
	public map[string]publicity
}

type publicity struct {
	public bool
	at     time.Time
}

const eventPage = 500

func (s *Store) Containers(ctx context.Context) ([]connector.Container, error) {
	bs, err := s.Backend.Buckets(ctx)
	if err != nil {
		return nil, err
	}
	var out []connector.Container
	for _, b := range bs {
		if len(s.Buckets) == 0 || containsString(s.Buckets, b) {
			out = append(out, connector.Container{ID: b, Name: b, Kind: s.Backend.Kind()})
		}
	}
	return out, nil
}

// Items: cursor "" starts a listing pass (remembering the newest event id first, so nothing that changes during
// the listing is lost); "list:<mark>:<marker>" continues it; "events:<id>" reads the event queue after id.
func (s *Store) Items(ctx context.Context, c connector.Container, cursor string) (connector.Page, error) {
	switch {
	case cursor == "":
		var mark int64
		if err := s.DB.QueryRow(ctx, "SELECT coalesce(max(id), 0) FROM data.object_events WHERE source = $1 AND bucket = $2", s.Source, c.ID).Scan(&mark); err != nil {
			return connector.Page{}, err
		}
		return s.list(ctx, c, mark, "")
	case strings.HasPrefix(cursor, "list:"):
		mark, marker, ok := strings.Cut(strings.TrimPrefix(cursor, "list:"), ":")
		n, err := strconv.ParseInt(mark, 10, 64)
		if !ok || err != nil {
			return connector.Page{}, fmt.Errorf("bad cursor %q", cursor)
		}
		return s.list(ctx, c, n, marker)
	case strings.HasPrefix(cursor, "events:"):
		after, err := strconv.ParseInt(strings.TrimPrefix(cursor, "events:"), 10, 64)
		if err != nil {
			return connector.Page{}, fmt.Errorf("bad cursor %q", cursor)
		}
		return s.events(ctx, c, after)
	}
	return connector.Page{}, fmt.Errorf("bad cursor %q", cursor)
}

func (s *Store) list(ctx context.Context, c connector.Container, mark int64, marker string) (connector.Page, error) {
	objs, next, err := s.Backend.List(ctx, c.ID, marker)
	if err != nil {
		return connector.Page{}, err
	}
	p := connector.Page{Next: fmt.Sprintf("list:%d:%s", mark, next)}
	if next == "" {
		p.Next, p.Done = fmt.Sprintf("events:%d", mark), true
	}
	for _, o := range objs {
		p.Items = append(p.Items, item(c.ID, o.Key, o.ETag, o.Size, o.Modified, false))
	}
	return p, nil
}

func (s *Store) events(ctx context.Context, c connector.Container, after int64) (connector.Page, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, key, etag, size, deleted, at FROM data.object_events
		WHERE source = $1 AND bucket = $2 AND id > $3 ORDER BY id LIMIT $4`, s.Source, c.ID, after, eventPage)
	if err != nil {
		return connector.Page{}, err
	}
	type ev struct {
		ID      int64
		Key     string
		ETag    string
		Size    int64
		Deleted bool
		At      time.Time
	}
	evs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ev])
	if err != nil {
		return connector.Page{}, err
	}
	p := connector.Page{Next: fmt.Sprintf("events:%d", after), Done: len(evs) < eventPage}
	for _, e := range evs {
		p.Items = append(p.Items, item(c.ID, e.Key, e.ETag, e.Size, e.At, e.Deleted))
		p.Next = fmt.Sprintf("events:%d", e.ID)
	}
	return p, nil
}

func item(bucket, key, etag string, size int64, mod time.Time, deleted bool) connector.Item {
	name := key[strings.LastIndexByte(key, '/')+1:]
	return connector.Item{ID: key, ContainerID: bucket, Name: name, Path: bucket + "/" + key, ContentTag: etag, Size: size, Modified: mod, Deleted: deleted}
}

func (s *Store) Get(ctx context.Context, it connector.Item, maxBytes int64) ([]byte, error) {
	if it.Size > maxBytes {
		return nil, fmt.Errorf("object is %d bytes, limit %d", it.Size, maxBytes)
	}
	return s.Backend.Get(ctx, it.ContainerID, it.ID, maxBytes)
}

// ACL: object stores grant per bucket, not per file. A bucket anyone may read makes every object an anonymous
// share. ponytail: per-object ACLs (AWS legacy ACLs, GCS fine-grained) are not read.
func (s *Store) ACL(ctx context.Context, it connector.Item) ([]connector.Grant, error) {
	s.mu.Lock()
	p, ok := s.public[it.ContainerID]
	s.mu.Unlock()
	if !ok || time.Since(p.at) >= s.PolicyCache {
		pub, err := s.Backend.Public(ctx, it.ContainerID)
		if err != nil {
			return nil, err
		}
		p = publicity{pub, time.Now()}
		s.mu.Lock()
		if s.public == nil {
			s.public = map[string]publicity{}
		}
		s.public[it.ContainerID] = p
		s.mu.Unlock()
	}
	if p.public {
		return []connector.Grant{{Kind: "anyone_link", Role: "read", External: true}}, nil
	}
	return nil, nil
}

func (s *Store) Labels(context.Context, connector.Item) ([]string, error) { return nil, nil }

func containsString(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// EventRetention: queued notifications older than this are dropped. Scans run hourly, so a week covers a long
// outage; a scanner further behind than that should rescan (cursor "").
const EventRetention = 7 * 24 * time.Hour

// PurgeEvents drops old notifications.
func PurgeEvents(ctx context.Context, db *pgxpool.Pool, now time.Time) (int64, error) {
	tag, err := db.Exec(ctx, "DELETE FROM data.object_events WHERE at < $1", now.Add(-EventRetention))
	return tag.RowsAffected(), err
}

// Mover is a backend that can move objects (remediation credentials).
type Mover interface {
	Move(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) error
}

type quarantined struct {
	Bucket string `json:"bucket"`
	Key    string `json:"key"`
}

// Remediate: quarantine moves the object into QuarantineBucket (key "<bucket>/<key>"). Public access is a
// bucket setting here, not a per-object link, so revoke/remove are not per-item actions; labels do not exist.
func (s *Store) Remediate(ctx context.Context, it connector.Item, a connector.Action, dryRun bool) (connector.Change, error) {
	m, ok := s.Backend.(Mover)
	if a.Kind != connector.Quarantine || !ok || s.QuarantineBucket == "" {
		return connector.Change{}, fmt.Errorf("%w: %s on %s object storage", connector.ErrNotSupported, a.Kind, s.Backend.Kind())
	}
	if it.ContainerID == s.QuarantineBucket {
		return connector.Change{}, connector.ErrNothingToDo
	}
	dst := it.ContainerID + "/" + it.ID
	ch := connector.Change{Steps: []string{fmt.Sprintf("move %s/%s to %s/%s", it.ContainerID, it.ID, s.QuarantineBucket, dst)}}
	ch.Undo, _ = json.Marshal(quarantined{it.ContainerID, it.ID})
	if dryRun {
		return ch, nil
	}
	return ch, m.Move(ctx, it.ContainerID, it.ID, s.QuarantineBucket, dst)
}

// Undo moves a quarantined object back.
func (s *Store) Undo(ctx context.Context, _ connector.Item, raw json.RawMessage, dryRun bool) (connector.Change, error) {
	m, ok := s.Backend.(Mover)
	var q quarantined
	if !ok || s.QuarantineBucket == "" || json.Unmarshal(raw, &q) != nil || q.Bucket == "" {
		return connector.Change{}, fmt.Errorf("%w: undo on %s object storage", connector.ErrNotSupported, s.Backend.Kind())
	}
	src := q.Bucket + "/" + q.Key
	ch := connector.Change{Steps: []string{fmt.Sprintf("move %s/%s back to %s/%s", s.QuarantineBucket, src, q.Bucket, q.Key)}}
	if dryRun {
		return ch, nil
	}
	return ch, m.Move(ctx, s.QuarantineBucket, src, q.Bucket, q.Key)
}
