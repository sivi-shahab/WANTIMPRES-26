package catalog

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/events"
	"wantimpres26/internal/lifecycle"
	"wantimpres26/internal/policysvc"
)

//go:embed schema.sql
var schemaSQL string

var (
	ErrNotFound = errors.New("not found")
	ErrStale    = errors.New("catalog feed version is not newer than the current one")
)

// Store is the catalog module. Every change that alters what the PDP sees cuts a policy release in the same
// transaction as its audit entry, so sidecars get it with the next bundle (≤ 60 s, ticket 12).
type Store struct {
	db       *pgxpool.Pool
	tenant   string
	policies *lifecycle.Store
}

// Open applies the schema, registers the catalog as a release document, and imports the embedded seed when the
// database has no feed yet (or an older one than the seed).
func Open(ctx context.Context, db *pgxpool.Pool, tenant string, policies *lifecycle.Store) (*Store, error) {
	if _, err := db.Exec(ctx, schemaSQL); err != nil {
		return nil, fmt.Errorf("apply catalog schema: %w", err)
	}
	s := &Store{db: db, tenant: tenant, policies: policies}
	policies.AddExtra(s.releaseDoc)
	seed, err := ParseFeed(seedFeed)
	if err != nil {
		return nil, fmt.Errorf("seed catalog: %w", err)
	}
	err = s.change(ctx, "system", "catalog.feed.import", func(tx pgx.Tx) (map[string]any, error) {
		if _, err := tx.Exec(ctx, "LOCK TABLE catalog.feeds IN EXCLUSIVE MODE"); err != nil { // replicas start together
			return nil, err
		}
		cur, err := currentVersion(ctx, tx)
		if err != nil || cur >= seed.Version {
			return nil, err
		}
		return s.importFeed(ctx, tx, "system", seed, seedFeed, "seed")
	})
	return s, err
}

func (s *Store) change(ctx context.Context, actor, action string, f func(pgx.Tx) (map[string]any, error)) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		target, err := f(tx)
		if err != nil || target == nil {
			return err
		}
		_, err = audit.AppendTx(ctx, tx, s.tenant, actor, action, target)
		return err
	})
}

func currentVersion(ctx context.Context, q pgx.Tx) (int64, error) {
	var v int64
	err := q.QueryRow(ctx, "SELECT coalesce(max(version), 0) FROM catalog.feeds").Scan(&v)
	return v, err
}

func (s *Store) importFeed(ctx context.Context, tx pgx.Tx, actor string, f Feed, raw []byte, source string) (map[string]any, error) {
	sum := sha256.Sum256(raw)
	if _, err := tx.Exec(ctx, "INSERT INTO catalog.feeds (version, sha256, apps, source, imported_by) VALUES ($1, $2, $3, $4, $5)",
		f.Version, hex.EncodeToString(sum[:]), f.Apps, source, actor); err != nil {
		return nil, err
	}
	n, err := s.policies.CutRelease(ctx, tx, actor, fmt.Sprintf("catalog feed v%d (%s)", f.Version, source))
	return map[string]any{"version": f.Version, "apps": len(f.Apps), "sha256": hex.EncodeToString(sum[:]), "source": source, "release": n}, err
}

// ImportSigned imports a feed whose detached signature verifies against pubPEM and whose version is newer.
func (s *Store) ImportSigned(ctx context.Context, actor string, raw []byte, sigB64 string, pubPEM []byte) (int64, error) {
	f, err := VerifyFeed(raw, sigB64, pubPEM)
	if err != nil {
		// Refused feeds are telemetry too: someone served a feed we would not trust.
		_ = s.change(ctx, actor, "catalog.feed.rejected", func(pgx.Tx) (map[string]any, error) {
			sum := sha256.Sum256(raw)
			return map[string]any{"sha256": hex.EncodeToString(sum[:]), "error": err.Error()}, nil
		})
		return 0, err
	}
	err = s.change(ctx, actor, "catalog.feed.import", func(tx pgx.Tx) (map[string]any, error) {
		if _, err := tx.Exec(ctx, "LOCK TABLE catalog.feeds IN EXCLUSIVE MODE"); err != nil {
			return nil, err
		}
		cur, err := currentVersion(ctx, tx)
		if err != nil {
			return nil, err
		}
		if f.Version <= cur {
			return nil, fmt.Errorf("%w: got %d, have %d", ErrStale, f.Version, cur)
		}
		return s.importFeed(ctx, tx, actor, f, raw, "signed")
	})
	return f.Version, err
}

// --- effective catalog ---------------------------------------------------------------------------------

// View is an app as the bank sees it: feed or local definition, with overrides applied.
type View struct {
	App
	Source    string     `json:"source"` // feed | local | observed (seen in traffic, not in the catalog)
	Sanction  string     `json:"sanction"`
	Decided   bool       `json:"decided"` // the bank set a status (vs. the feed default)
	Owner     *string    `json:"owner,omitempty"`
	Reason    *string    `json:"reason,omitempty"`
	ReviewAt  *time.Time `json:"review_at,omitempty"`
	Flags     []string   `json:"flags"`
	Usage     *Usage     `json:"usage,omitempty"`
	UpdatedBy *string    `json:"updated_by,omitempty"`
}

// Usage is the last 30 days of APP_USAGE_DAILY.
type Usage struct {
	Events          int64 `json:"events"`
	SensitiveEvents int64 `json:"sensitive_events"`
	Blocked         int64 `json:"blocked"`
	Users           int64 `json:"users"`
}

// DefaultSanction is a feed app's status until the bank decides: known to exist, not approved.
const DefaultSanction = "unsanctioned"

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// effective merges the current feed with overrides and local apps.
func effective(ctx context.Context, q querier, today time.Time) (map[string]*View, int64, error) {
	var version int64
	var apps []App
	err := q.QueryRow(ctx, "SELECT version, apps FROM catalog.feeds ORDER BY version DESC LIMIT 1").Scan(&version, &apps)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, err
	}
	out := map[string]*View{}
	for _, a := range apps {
		out[a.ID] = &View{App: a, Source: "feed", Sanction: DefaultSanction}
	}
	rows, err := q.Query(ctx, `SELECT app_id, sanction, owner, reason, review_at, hosting_region, ojk_approval_ref, trains_on_data, local, updated_by
		FROM catalog.overrides`)
	if err != nil {
		return nil, 0, err
	}
	for rows.Next() {
		var id string
		var sanction, region, ojk *string
		var train *bool
		var local *App
		var v View
		if err := rows.Scan(&id, &sanction, &v.Owner, &v.Reason, &v.ReviewAt, &region, &ojk, &train, &local, &v.UpdatedBy); err != nil {
			return nil, 0, err
		}
		cur, ok := out[id]
		switch {
		case ok:
		case local != nil:
			cur = &View{App: *local, Source: "local", Sanction: DefaultSanction}
			out[id] = cur
		default:
			continue // override for an app the current feed dropped: kept, not shown
		}
		cur.Owner, cur.Reason, cur.ReviewAt, cur.UpdatedBy = v.Owner, v.Reason, v.ReviewAt, v.UpdatedBy
		if sanction != nil {
			cur.Sanction, cur.Decided = *sanction, true
		}
		if region != nil {
			cur.HostingRegion = *region
		}
		if ojk != nil {
			cur.OJKApprovalRef = ojk
		}
		if train != nil {
			cur.TrainsOnCustomerData = train
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	for _, v := range out {
		v.Flags = flags(v.App, v.ReviewAt, today)
	}
	return out, version, nil
}

// Flags for the reports (ticket 16 AC, ADR-0001): offshore processing without an OJK approval reference;
// unknown region counts as offshore.
const (
	FlagOffshoreNoOJK = "offshore_without_ojk_approval"
	FlagReviewOverdue = "review_overdue"
)

func flags(a App, reviewAt *time.Time, today time.Time) []string {
	f := []string{}
	if a.HostingRegion != "ID" && (a.OJKApprovalRef == nil || strings.TrimSpace(*a.OJKApprovalRef) == "") {
		f = append(f, FlagOffshoreNoOJK)
	}
	if reviewAt != nil && reviewAt.Before(today) {
		f = append(f, FlagReviewOverdue)
	}
	return f
}

// releaseDoc is data.wantimpres26.catalog for policy releases: what the PDP needs per app (wantimpres26/dest/dest.rego).
func (s *Store) releaseDoc(ctx context.Context, tx pgx.Tx) (policysvc.Overrides, error) {
	views, version, err := effective(ctx, tx, time.Now())
	if err != nil {
		return nil, err
	}
	apps := map[string]any{}
	for id, v := range views {
		a := map[string]any{"sanction": v.Sanction, "region": v.HostingRegion}
		if v.TrainsOnCustomerData != nil {
			a["trains_on_data"] = *v.TrainsOnCustomerData
		}
		if v.OJKApprovalRef != nil {
			a["ojk_approval_ref"] = *v.OJKApprovalRef // offshore processing approved by OJK (POJK 11/2022, ADR-0001)
		}
		apps[id] = a
	}
	return policysvc.Overrides{"wantimpres26.catalog": map[string]any{"version": version, "apps": apps}}, nil
}

// --- changes -----------------------------------------------------------------------------------------------

// Patch is a PATCH /apps/{id} body (§8.4). Nil fields are left as they are.
type Patch struct {
	Sanction       *string `json:"sanction"`
	Owner          *string `json:"owner"`
	Reason         *string `json:"reason"`
	ReviewAt       *string `json:"review_at"` // YYYY-MM-DD
	HostingRegion  *string `json:"hosting_region"`
	OJKApprovalRef *string `json:"ojk_approval_ref"`
	TrainsOnData   *bool   `json:"trains_on_data"`
}

// Update applies a patch to an app in the catalog. A sanction change needs a reason. Audited (before/after) and
// published as a release in one transaction.
func (s *Store) Update(ctx context.Context, actor, id string, p Patch) (View, error) {
	if p.Sanction != nil && !slices.Contains(Sanctions, *p.Sanction) {
		return View{}, fmt.Errorf("%w: sanction %q", ErrInvalid, *p.Sanction)
	}
	if p.Sanction != nil && (p.Reason == nil || strings.TrimSpace(*p.Reason) == "") {
		return View{}, fmt.Errorf("%w: a sanction change needs a reason", ErrInvalid)
	}
	if p.HostingRegion != nil && !regionRe.MatchString(*p.HostingRegion) {
		return View{}, fmt.Errorf("%w: hosting_region %q", ErrInvalid, *p.HostingRegion)
	}
	var review *time.Time
	if p.ReviewAt != nil {
		t, err := time.Parse(time.DateOnly, *p.ReviewAt)
		if err != nil {
			return View{}, fmt.Errorf("%w: review_at %q", ErrInvalid, *p.ReviewAt)
		}
		review = &t
	}
	var after View
	err := s.change(ctx, actor, "catalog.app.update", func(tx pgx.Tx) (map[string]any, error) {
		before, _, err := effective(ctx, tx, time.Now())
		if err != nil {
			return nil, err
		}
		b, ok := before[id]
		if !ok {
			return nil, ErrNotFound
		}
		_, err = tx.Exec(ctx, `INSERT INTO catalog.overrides (app_id, sanction, owner, reason, review_at, hosting_region, ojk_approval_ref, trains_on_data, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (app_id) DO UPDATE SET
			  sanction = coalesce($2, catalog.overrides.sanction), owner = coalesce($3, catalog.overrides.owner),
			  reason = coalesce($4, catalog.overrides.reason), review_at = coalesce($5, catalog.overrides.review_at),
			  hosting_region = coalesce($6, catalog.overrides.hosting_region),
			  ojk_approval_ref = coalesce($7, catalog.overrides.ojk_approval_ref),
			  trains_on_data = coalesce($8, catalog.overrides.trains_on_data), updated_by = $9, updated_at = now()`,
			id, p.Sanction, p.Owner, p.Reason, review, p.HostingRegion, p.OJKApprovalRef, p.TrainsOnData, actor)
		if err != nil {
			return nil, err
		}
		views, _, err := effective(ctx, tx, time.Now())
		if err != nil {
			return nil, err
		}
		after = *views[id]
		n, err := s.policies.CutRelease(ctx, tx, actor, fmt.Sprintf("catalog: %s %s -> %s", id, b.Sanction, after.Sanction))
		return map[string]any{"app": id, "release": n, "patch": p,
			"before": map[string]any{"sanction": b.Sanction, "hosting_region": b.HostingRegion, "ojk_approval_ref": b.OJKApprovalRef, "owner": b.Owner},
			"after":  map[string]any{"sanction": after.Sanction, "hosting_region": after.HostingRegion, "ojk_approval_ref": after.OJKApprovalRef, "owner": after.Owner},
		}, err
	})
	return after, err
}

// AddLocal adds an app the feed does not have (FR-DISC-5: no redeploy). Status starts unsanctioned.
func (s *Store) AddLocal(ctx context.Context, actor string, a App) error {
	if err := a.Validate(); err != nil {
		return err
	}
	return s.change(ctx, actor, "catalog.app.add", func(tx pgx.Tx) (map[string]any, error) {
		views, _, err := effective(ctx, tx, time.Now())
		if err != nil {
			return nil, err
		}
		if _, exists := views[a.ID]; exists {
			return nil, fmt.Errorf("%w: app %s exists", ErrInvalid, a.ID)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO catalog.overrides (app_id, local, updated_by) VALUES ($1, $2, $3)", a.ID, a, actor); err != nil {
			return nil, err
		}
		n, err := s.policies.CutRelease(ctx, tx, actor, "catalog: add local app "+a.ID)
		return map[string]any{"app": a.ID, "name": a.Name, "hosting_region": a.HostingRegion, "release": n}, err
	})
}

// --- usage ---------------------------------------------------------------------------------------------------

// Record counts one decision event into APP_USAGE_DAILY (once per event id).
func (s *Store) Record(ctx context.Context, e events.Event) error {
	ts, err := time.Parse(time.RFC3339Nano, e.TS)
	if err != nil {
		return err
	}
	day := ts.UTC().Format(time.DateOnly)
	sensitive := len(e.Classes) > 0 || e.Sensitivity == "confidential" || e.Sensitivity == "restricted"
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "INSERT INTO catalog.usage_seen (event_id, day) VALUES ($1, $2) ON CONFLICT DO NOTHING", e.EventID, day)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO catalog.usage_daily (app_id, day, events, sensitive_events, blocked) VALUES ($1, $2, 1, $3, $4)
			ON CONFLICT (app_id, day) DO UPDATE SET events = catalog.usage_daily.events + 1,
			  sensitive_events = catalog.usage_daily.sensitive_events + $3, blocked = catalog.usage_daily.blocked + $4`,
			e.AppID, day, b2i(sensitive), b2i(e.Action == "block"))
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "INSERT INTO catalog.usage_users (app_id, day, principal) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING", e.AppID, day, e.PrincipalID)
		return err
	})
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// PurgeUsage drops dedup keys older than 3 days and per-user rows older than 400 days (§10.2 event metadata).
func (s *Store) PurgeUsage(ctx context.Context, now time.Time) error {
	_, err := s.db.Exec(ctx, `DELETE FROM catalog.usage_seen WHERE day < $1;
		DELETE FROM catalog.usage_users WHERE day < $2; DELETE FROM catalog.usage_daily WHERE day < $2`,
		now.AddDate(0, 0, -3), now.AddDate(0, 0, -400))
	return err
}

// --- reads ---------------------------------------------------------------------------------------------------

// ListOptions is GET /apps.
type ListOptions struct {
	Sanction string
	Flag     string
	Sort     string // events | sensitive_events | blocked | users | name; "-" prefix = descending
	Limit    int
	Offset   int
}

// List returns apps with 30-day usage, including apps seen in traffic that are not in the catalog.
func (s *Store) List(ctx context.Context, o ListOptions, now time.Time) ([]View, int, error) {
	views, _, err := effective(ctx, s.db, now)
	if err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `SELECT d.app_id, sum(d.events), sum(d.sensitive_events), sum(d.blocked),
		  (SELECT count(DISTINCT principal) FROM catalog.usage_users u WHERE u.app_id = d.app_id AND u.day >= $1)
		FROM catalog.usage_daily d WHERE d.day >= $1 GROUP BY d.app_id`, now.AddDate(0, 0, -30))
	if err != nil {
		return nil, 0, err
	}
	for rows.Next() {
		var id string
		var u Usage
		if err := rows.Scan(&id, &u.Events, &u.SensitiveEvents, &u.Blocked, &u.Users); err != nil {
			return nil, 0, err
		}
		v, ok := views[id]
		if !ok { // shadow AI: in traffic, not in the catalog
			v = &View{App: App{ID: id, Name: id, HostingRegion: "unknown"}, Source: "observed", Sanction: DefaultSanction}
			v.Flags = flags(v.App, nil, now)
			views[id] = v
		}
		v.Usage = &u
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var out []View
	for _, v := range views {
		if v.Usage == nil {
			v.Usage = &Usage{}
		}
		if (o.Sanction == "" || v.Sanction == o.Sanction) && (o.Flag == "" || slices.Contains(v.Flags, o.Flag)) {
			out = append(out, *v)
		}
	}
	key, desc := strings.TrimPrefix(o.Sort, "-"), strings.HasPrefix(o.Sort, "-")
	metric := func(v View) int64 {
		switch key {
		case "sensitive_events":
			return v.Usage.SensitiveEvents
		case "blocked":
			return v.Usage.Blocked
		case "users":
			return v.Usage.Users
		}
		return v.Usage.Events
	}
	sort.SliceStable(out, func(i, j int) bool {
		if key == "" || key == "name" {
			return (out[i].ID < out[j].ID) != desc
		}
		if metric(out[i]) != metric(out[j]) {
			return (metric(out[i]) < metric(out[j])) != desc
		}
		return out[i].ID < out[j].ID
	})
	total := len(out)
	if o.Offset > len(out) {
		o.Offset = len(out)
	}
	out = out[o.Offset:]
	if o.Limit > 0 && len(out) > o.Limit {
		out = out[:o.Limit]
	}
	return out, total, nil
}

// Apps returns the current effective catalog (for the matcher and reports).
func (s *Store) Apps(ctx context.Context) ([]App, error) {
	views, _, err := effective(ctx, s.db, time.Now())
	if err != nil {
		return nil, err
	}
	out := make([]App, 0, len(views))
	for _, v := range views {
		out = append(out, v.App)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
