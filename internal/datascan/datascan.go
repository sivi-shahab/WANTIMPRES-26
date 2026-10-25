// Package datascan discovers and classifies data at rest through a connector (spec §4.3 FR-DATA-1..5): it walks
// each container's change feed with a checkpointed cursor, reads content only for new or changed items it
// samples, classifies with the L1 detectors and external labels, analyses sharing for oversharing, and stores
// assets with an exposure score. Raw content is never stored.
package datascan

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/connector"
	"wantimpres26/internal/detect"
	"wantimpres26/internal/extract"
	"wantimpres26/internal/similarity"
)

//go:embed schema.sql
var schemaSQL string

// ModelVersion names the classifier behind stored classifications.
const ModelVersion = "detect-l1"

// Open applies the schema.
func Open(ctx context.Context, db *pgxpool.Pool) error {
	if _, err := db.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("apply data schema: %w", err)
	}
	return nil
}

// Scanner scans one source.
type Scanner struct {
	DB     *pgxpool.Pool
	Source string // data source id, e.g. "m365"
	Conn   connector.Connector
	Limits extract.Limits
	Tika   *extract.Tika
	Pepper []byte
	// Similar: registered confidential documents (ticket 37); nil = none.
	Similar *similarity.Live
	Labels  map[string]string // external label id → sensitivity (tenant label taxonomy)
	// BroadGroups: groups that mean "everyone" (lower-case names).
	BroadGroups []string
	// Sampling (FR-DATA-3): in sample mode a stable SamplePercent of files (at most SampleMax) is read. After a
	// pass, a container goes full when it is small (< SmallContainer files) or dense (≥ DenseRatio sensitive
	// among ≥ MinSample sampled); going full re-walks it once to read what was skipped.
	SamplePercent  int
	SampleMax      int64
	SmallContainer int64
	MinSample      int64
	DenseRatio     float64
	Now            func() time.Time
	Log            *slog.Logger
}

// Defaults fills unset tuning values with the spec's examples.
func (s *Scanner) Defaults() {
	if s.Limits == (extract.Limits{}) {
		s.Limits = extract.Default
	}
	if s.SamplePercent == 0 {
		s.SamplePercent, s.SampleMax, s.SmallContainer, s.MinSample, s.DenseRatio = 5, 10000, 1000, 20, 0.05
	}
	if s.BroadGroups == nil {
		s.BroadGroups = []string{"everyone", "everyone except external users", "all company", "all users", "semua karyawan", "seluruh karyawan"}
	}
	if s.Now == nil {
		s.Now = time.Now
	}
}

// Stats counts what one run did.
type Stats struct {
	Containers, Items, ContentRead, ACLRead, Unchanged, Deleted, Errors int
}

// Run scans every container of the source once. One failing container does not stop the others.
func (s *Scanner) Run(ctx context.Context) (Stats, error) {
	var st Stats
	cs, err := s.Conn.Containers(ctx)
	if err != nil {
		return st, fmt.Errorf("list containers: %w", err)
	}
	for _, c := range cs {
		if err := ctx.Err(); err != nil {
			return st, err
		}
		if err := s.container(ctx, c, &st); err != nil {
			st.Errors++
			s.Log.Error("container scan", "source", s.Source, "container", c.ID, "err", err)
		}
		st.Containers++
	}
	return st, nil
}

func (s *Scanner) container(ctx context.Context, c connector.Container, st *Stats) error {
	conn, err := s.DB.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	// One worker per container at a time: replicas scan in parallel without stepping on each other's cursor.
	var locked bool
	key := s.Source + "/" + c.ID
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtext($1))", key).Scan(&locked); err != nil || !locked {
		return err
	}
	defer func() { _, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock(hashtext($1))", key) }()

	if _, err := s.DB.Exec(ctx, `INSERT INTO data.containers (source_id, container_id, name, kind) VALUES ($1, $2, $3, $4)
		ON CONFLICT (source_id, container_id) DO UPDATE SET name = $3, kind = $4`, s.Source, c.ID, c.Name, c.Kind); err != nil {
		return err
	}
	for pass := 0; pass < 2; pass++ {
		var cursor, mode string
		var sampled int64
		if err := s.DB.QueryRow(ctx, "SELECT cursor, mode, sampled FROM data.containers WHERE source_id = $1 AND container_id = $2",
			s.Source, c.ID).Scan(&cursor, &mode, &sampled); err != nil {
			return err
		}
		bootstrap := cursor == ""
		for {
			page, err := s.Conn.Items(ctx, c, cursor)
			if err != nil {
				return err
			}
			for _, it := range page.Items {
				read, err := s.item(ctx, c, it, mode == "full" || (sampled < s.SampleMax && s.sampled(it)), bootstrap, st)
				if err != nil {
					return fmt.Errorf("item %s: %w", it.ID, err)
				}
				if read {
					sampled++
				}
			}
			cursor = page.Next
			// Checkpoint every page: a crash resumes here, not from the start.
			if _, err := s.DB.Exec(ctx, "UPDATE data.containers SET cursor = $3 WHERE source_id = $1 AND container_id = $2", s.Source, c.ID, cursor); err != nil {
				return err
			}
			if page.Done {
				break
			}
		}
		full, err := s.settle(ctx, c, mode, bootstrap)
		if err != nil || !full {
			return err
		}
		// Gone full: one more pass from the start reads the files the sample skipped (and only those).
	}
	return nil
}

// sampled: a stable pseudo-random SamplePercent of items, so reruns pick the same ones.
func (s *Scanner) sampled(it connector.Item) bool {
	h := sha256.Sum256([]byte(it.ContainerID + "/" + it.ID))
	return binary.BigEndian.Uint32(h[:4])%100 < uint32(s.SamplePercent)
}

// settle records the container's counts after a pass and decides whether it must be read in full.
func (s *Scanner) settle(ctx context.Context, c connector.Container, mode string, bootstrap bool) (bool, error) {
	var items, sampled, sensitive int64
	err := s.DB.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE content_scanned),
		count(*) FILTER (WHERE content_scanned AND sensitivity IN ('confidential', 'restricted'))
		FROM data.assets WHERE source_id = $1 AND container_id = $2 AND deleted_at IS NULL`, s.Source, c.ID).Scan(&items, &sampled, &sensitive)
	if err != nil {
		return false, err
	}
	goFull := mode == "sample" && bootstrap && (items < s.SmallContainer ||
		sampled >= s.MinSample && float64(sensitive) >= s.DenseRatio*float64(sampled))
	sql := "UPDATE data.containers SET items = $3, sampled = $4, sensitive = $5, last_scan = $6 WHERE source_id = $1 AND container_id = $2"
	if goFull {
		sql = "UPDATE data.containers SET items = $3, sampled = $4, sensitive = $5, last_scan = $6, mode = 'full', cursor = '' WHERE source_id = $1 AND container_id = $2"
	}
	_, err = s.DB.Exec(ctx, sql, s.Source, c.ID, items, sampled, sensitive, s.Now())
	return goFull, err
}

type stored struct {
	id          string
	tag         string
	scanned     bool
	label       *string
	sensitivity string
}

// item processes one change. It reports whether content was read.
// walk: the feed is enumerating everything (bootstrap or re-walk), not reporting changes.
func (s *Scanner) item(ctx context.Context, c connector.Container, it connector.Item, wantContent, walk bool, st *Stats) (bool, error) {
	if it.Folder {
		return false, nil
	}
	st.Items++
	if it.Deleted {
		st.Deleted++
		_, err := s.DB.Exec(ctx, "UPDATE data.assets SET deleted_at = $3 WHERE source_id = $1 AND external_id = $2 AND deleted_at IS NULL", s.Source, it.ID, s.Now())
		return false, err
	}
	var old *stored
	var o stored
	err := s.DB.QueryRow(ctx, "SELECT id::text, content_tag, content_scanned, label, sensitivity FROM data.assets WHERE source_id = $1 AND external_id = $2",
		s.Source, it.ID).Scan(&o.id, &o.tag, &o.scanned, &o.label, &o.sensitivity)
	switch {
	case err == nil:
		old = &o
	case !errors.Is(err, pgx.ErrNoRows):
		return false, err
	}
	contentChanged := old == nil || old.tag != it.ContentTag
	readContent := wantContent && (contentChanged || !old.scanned)
	if old != nil && !contentChanged && (old.scanned || !wantContent) {
		st.Unchanged++
		if walk {
			return false, nil // enumerated again, nothing new to read
		}
		// otherwise back in the change feed for its sharing or name: grants only
	}

	var acl []connector.Grant
	if walk && old != nil && !contentChanged {
		// Re-walk to read skipped content: the grants were read moments ago in this run's first pass.
		if acl, err = storedACL(ctx, s.DB, old.id); err != nil {
			return false, err
		}
	} else {
		if acl, err = s.Conn.ACL(ctx, it); err != nil {
			return false, fmt.Errorf("acl: %w", err)
		}
		st.ACLRead++
	}
	var label *string
	if contentChanged {
		ls, err := s.Conn.Labels(ctx, it)
		if err != nil {
			return false, fmt.Errorf("labels: %w", err)
		}
		if len(ls) > 0 {
			label = &ls[0]
		}
	} else {
		label = old.label
	}

	sens := "internal"
	var classes []detect.Class
	scanned, note := false, ""
	switch {
	case readContent:
		st.ContentRead++
		sens, classes, note = s.classify(ctx, it)
		scanned = true
	case old != nil && !contentChanged:
		sens, scanned = old.sensitivity, old.scanned
	}
	if !scanned && note == "" {
		note = "not sampled"
	}
	if l := s.Labels[deref(label)]; rank(l) > rank(sens) {
		sens = l // the label is a floor (FR-CLS-6): a "Confidential" document is at least confidential
	}
	flags, err := s.flags(ctx, acl, sens)
	if err != nil {
		return false, err
	}

	err = pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO data.assets (source_id, container_id, external_id, path_hash, content_tag, size, label, sensitivity,
			exposure_score, flags, content_scanned, scan_note, modified_at, scanned_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			ON CONFLICT (source_id, external_id) DO UPDATE SET container_id = $2, path_hash = $4, content_tag = $5, size = $6, label = $7,
			sensitivity = $8, exposure_score = $9, flags = $10, content_scanned = $11, scan_note = $12, modified_at = $13, scanned_at = $14, deleted_at = NULL
			RETURNING id::text`, s.Source, c.ID, it.ID, s.hash(it.Path), it.ContentTag, it.Size, label, sens, Exposure(sens, flags), flags,
			scanned, nullable(note), it.Modified, s.Now()).Scan(&id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM data.acl_entries WHERE asset_id = $1", id); err != nil {
			return err
		}
		for _, g := range acl {
			if _, err := tx.Exec(ctx, "INSERT INTO data.acl_entries (asset_id, grantee_kind, grantee_ref, permission, external) VALUES ($1, $2, $3, $4, $5)",
				id, g.Kind, g.Ref, g.Role, g.External); err != nil {
				return err
			}
		}
		if !readContent {
			return nil
		}
		if _, err := tx.Exec(ctx, "DELETE FROM data.classifications WHERE asset_id = $1", id); err != nil {
			return err
		}
		for _, cl := range classes {
			if _, err := tx.Exec(ctx, "INSERT INTO data.classifications (asset_id, class, count, confidence, model_version) VALUES ($1, $2, $3, $4, $5)",
				id, cl.Type, cl.Count, cl.Confidence, ModelVersion); err != nil {
				return err
			}
		}
		return nil
	})
	return readContent, err
}

func storedACL(ctx context.Context, db *pgxpool.Pool, assetID string) ([]connector.Grant, error) {
	rows, err := db.Query(ctx, "SELECT grantee_kind, grantee_ref, permission, external FROM data.acl_entries WHERE asset_id = $1", assetID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[connector.Grant])
}

// classify reads and classifies content. Content that cannot be read is still "scanned" (with a note) so a
// broken or hostile file is not fetched on every run; a new version (new tag) is tried again.
func (s *Scanner) classify(ctx context.Context, it connector.Item) (string, []detect.Class, string) {
	data, err := s.Conn.Get(ctx, it, s.Limits.MaxBytes)
	if err != nil {
		return "internal", nil, "not read: " + err.Error()
	}
	res, err := extract.Extract(ctx, data, it.Name, s.Limits, s.Tika)
	note := ""
	switch {
	case errors.Is(err, extract.ErrLimit):
		note = "extraction limit: " + err.Error() // zip bombs and the like: worth a look, not a crash
	case err != nil:
		note = "not extracted: " + err.Error()
	case res.Truncated:
		note = fmt.Sprintf("classified first %d bytes", s.Limits.MaxText)
	}
	r := detect.Scan(res.Text)
	similarity.Apply(&r, s.Similar.Index().Match(res.Text))
	return r.Sensitivity, r.Classes, note
}

// --- oversharing (FR-DATA-4) ---

// Flags.
const (
	FlagAnyoneLink    = "anyone_link"       // anonymous sharing link
	FlagExternalShare = "external_share"    // shared with a guest or outside the tenant's domains
	FlagBroadGroup    = "broad_group"       // "Everyone"-style group on confidential or restricted content
	FlagOrphan        = "orphan_permission" // granted to a user who is no longer active
)

func (s *Scanner) flags(ctx context.Context, acl []connector.Grant, sens string) ([]string, error) {
	set := map[string]bool{}
	var users []string
	for _, g := range acl {
		switch {
		case g.Kind == "anyone_link":
			set[FlagAnyoneLink] = true
		case g.External:
			set[FlagExternalShare] = true
		case g.Kind == "group" && slices.Contains(s.BroadGroups, strings.ToLower(g.Ref)) && rank(sens) >= rank("confidential"):
			set[FlagBroadGroup] = true
		case g.Kind == "user":
			users = append(users, strings.ToLower(g.Ref))
		}
	}
	if len(users) > 0 {
		// Inactive in the bank's directory (SCIM, ticket 06). Users the directory never knew are not orphans.
		var n int
		if err := s.DB.QueryRow(ctx, "SELECT count(*) FROM identity.users WHERE lower(user_name) = ANY($1) AND NOT active", users).Scan(&n); err != nil {
			return nil, fmt.Errorf("orphan check: %w", err)
		}
		set[FlagOrphan] = n > 0
	}
	out := []string{}
	for f, on := range set {
		if on {
			out = append(out, f)
		}
	}
	slices.Sort(out)
	return out, nil
}

var levels = []string{"public", "internal", "confidential", "restricted"}

func rank(sens string) int { return slices.Index(levels, sens) }

// Exposure is the 0–100 exposure score: how sensitive (public 0, internal .3, confidential .6, restricted 1)
// times how far it is shared (anyone link 1, external .8, broad group .6, orphan permission .3, otherwise .1).
func Exposure(sens string, flags []string) int {
	f := map[string]float64{"public": 0, "internal": 0.3, "confidential": 0.6, "restricted": 1}[sens]
	reach := 0.1
	for _, fl := range flags {
		reach = max(reach, map[string]float64{FlagAnyoneLink: 1, FlagExternalShare: 0.8, FlagBroadGroup: 0.6, FlagOrphan: 0.3}[fl])
	}
	return int(math.Round(100 * f * reach))
}

func (s *Scanner) hash(p string) string {
	m := hmac.New(sha256.New, s.Pepper)
	m.Write([]byte(s.Source + ":" + p))
	return hex.EncodeToString(m.Sum(nil))
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Refresh re-reads an asset's grants and label after a remediation and recomputes its flags and exposure. Path
// and content tag stay as scanned (a moved item is reported by the feed); a new label can only raise sensitivity.
func (s *Scanner) Refresh(ctx context.Context, assetID string) error {
	var it connector.Item
	var sens string
	if err := s.DB.QueryRow(ctx, "SELECT external_id, container_id, content_tag, sensitivity FROM data.assets WHERE id = $1 AND source_id = $2",
		assetID, s.Source).Scan(&it.ID, &it.ContainerID, &it.ContentTag, &sens); err != nil {
		return err
	}
	acl, err := s.Conn.ACL(ctx, it)
	if err != nil {
		return fmt.Errorf("acl: %w", err)
	}
	ls, err := s.Conn.Labels(ctx, it)
	if err != nil {
		return fmt.Errorf("labels: %w", err)
	}
	var label *string
	if len(ls) > 0 {
		label = &ls[0]
		if l := s.Labels[ls[0]]; rank(l) > rank(sens) {
			sens = l
		}
	}
	flags, err := s.flags(ctx, acl, sens)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "UPDATE data.assets SET label = $2, sensitivity = $3, flags = $4, exposure_score = $5, scanned_at = $6 WHERE id = $1",
			assetID, label, sens, flags, Exposure(sens, flags), s.Now()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM data.acl_entries WHERE asset_id = $1", assetID); err != nil {
			return err
		}
		for _, g := range acl {
			if _, err := tx.Exec(ctx, "INSERT INTO data.acl_entries (asset_id, grantee_kind, grantee_ref, permission, external) VALUES ($1, $2, $3, $4, $5)",
				assetID, g.Kind, g.Ref, g.Role, g.External); err != nil {
				return err
			}
		}
		return nil
	})
}
