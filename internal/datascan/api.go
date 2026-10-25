package datascan

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/authz"
)

// Asset is a data_asset with its findings. No content, no path: external_id is what remediation needs.
type Asset struct {
	ID             string    `json:"id"`
	SourceID       string    `json:"source_id"`
	ContainerID    string    `json:"container_id"`
	ExternalID     string    `json:"external_id"`
	PathHash       string    `json:"path_hash"`
	Size           int64     `json:"size"`
	Label          *string   `json:"label,omitempty"`
	Sensitivity    string    `json:"sensitivity"`
	ExposureScore  int       `json:"exposure_score"`
	Flags          []string  `json:"flags"`
	ContentScanned bool      `json:"content_scanned"`
	ScanNote       *string   `json:"scan_note,omitempty"`
	ScannedAt      time.Time `json:"scanned_at"`
	Classes        []Class   `json:"classes"`
	ACL            []Grant   `json:"acl,omitempty"`
}

type Class struct {
	Class        string  `json:"class"`
	Count        int     `json:"count"`
	Confidence   float32 `json:"confidence"`
	ModelVersion string  `json:"model_version"`
}

type Grant struct {
	Kind       string `json:"grantee_kind"`
	Ref        string `json:"grantee_ref"`
	Permission string `json:"permission"`
	External   bool   `json:"external"`
}

// Routes mounts the read API: the riskiest assets first, and a per-source summary (dashboard readers).
func Routes(rt *authz.Router, db *pgxpool.Pool) {
	reply := func(w http.ResponseWriter, v any, err error) {
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	rt.Handle("GET /data/assets", authz.DashboardRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		q := r.URL.Query()
		minExp, _ := strconv.Atoi(q.Get("min_exposure"))
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit <= 0 || limit > 500 {
			limit = 100
		}
		rows, err := db.Query(r.Context(), `SELECT a.id::text, a.source_id, a.container_id, a.external_id, a.path_hash, a.size, a.label, a.sensitivity,
			a.exposure_score, a.flags, a.content_scanned, a.scan_note, a.scanned_at,
			coalesce((SELECT json_agg(json_build_object('class', c.class, 'count', c.count, 'confidence', c.confidence, 'model_version', c.model_version)
				ORDER BY c.class) FROM data.classifications c WHERE c.asset_id = a.id), '[]'),
			coalesce((SELECT json_agg(json_build_object('grantee_kind', g.grantee_kind, 'grantee_ref', g.grantee_ref, 'permission', g.permission,
				'external', g.external)) FROM data.acl_entries g WHERE g.asset_id = a.id), '[]')
			FROM data.assets a WHERE a.deleted_at IS NULL AND a.exposure_score >= $1 AND ($2 = '' OR $2 = ANY(a.flags))
			AND ($3 = '' OR a.sensitivity = $3) AND ($4 = '' OR a.source_id = $4)
			ORDER BY a.exposure_score DESC, a.scanned_at DESC LIMIT $5`, minExp, q.Get("flag"), q.Get("sensitivity"), q.Get("source"), limit)
		if err != nil {
			reply(w, nil, err)
			return
		}
		as, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Asset, error) {
			var a Asset
			err := row.Scan(&a.ID, &a.SourceID, &a.ContainerID, &a.ExternalID, &a.PathHash, &a.Size, &a.Label, &a.Sensitivity, &a.ExposureScore,
				&a.Flags, &a.ContentScanned, &a.ScanNote, &a.ScannedAt, &a.Classes, &a.ACL)
			return a, err
		})
		reply(w, as, err)
	})
	rt.Handle("GET /data/summary", authz.DashboardRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		type summary struct {
			SourceID      string           `json:"source_id"`
			Assets        int64            `json:"assets"`
			Scanned       int64            `json:"content_scanned"`
			BySensitivity map[string]int64 `json:"by_sensitivity"`
			ByFlag        map[string]int64 `json:"by_flag"`
			HighExposure  int64            `json:"exposure_ge_60"`
		}
		rows, err := db.Query(r.Context(), `SELECT source_id, count(*), count(*) FILTER (WHERE content_scanned),
			(SELECT json_object_agg(s, n) FROM (SELECT sensitivity s, count(*) n FROM data.assets b WHERE b.source_id = a.source_id AND b.deleted_at IS NULL GROUP BY 1) x),
			coalesce((SELECT json_object_agg(f, n) FROM (SELECT unnest(flags) f, count(*) n FROM data.assets b WHERE b.source_id = a.source_id AND b.deleted_at IS NULL GROUP BY 1) y), '{}'),
			count(*) FILTER (WHERE exposure_score >= 60)
			FROM data.assets a WHERE deleted_at IS NULL GROUP BY source_id ORDER BY source_id`)
		if err != nil {
			reply(w, nil, err)
			return
		}
		out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (summary, error) {
			var s summary
			err := row.Scan(&s.SourceID, &s.Assets, &s.Scanned, &s.BySensitivity, &s.ByFlag, &s.HighExposure)
			return s, err
		})
		if out == nil {
			out = []summary{}
		}
		reply(w, out, err)
	})
}
