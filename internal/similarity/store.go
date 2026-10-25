package similarity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/authz"
	"wantimpres26/internal/extract"
	"wantimpres26/internal/tenantdb"
)

//go:embed schema.sql
var schemaSQL string

var (
	ErrInvalid  = errors.New("invalid request")
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("document already registered")
)

// Store is the registered corpus (control-plane).
type Store struct {
	DB     *pgxpool.Pool
	Tenant string
	Pepper []byte
	Tika   *extract.Tika // nil: no PDF or legacy Office formats
}

// Open applies the schema.
func Open(ctx context.Context, db *pgxpool.Pool) error {
	if _, err := db.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("apply similarity schema: %w", err)
	}
	return tenantdb.Isolate(ctx, db, "similarity.docs")
}

// Register extracts the text of a file, fingerprints it and stores the fingerprints. The text is dropped.
func (s *Store) Register(ctx context.Context, actor, name, sensitivity string, data []byte, now time.Time) (Doc, error) {
	if name == "" || len(name) > 200 || (sensitivity != "confidential" && sensitivity != "restricted") {
		return Doc{}, fmt.Errorf("%w: name (1-200 chars) and sensitivity (confidential|restricted) required", ErrInvalid)
	}
	res, err := extract.Extract(ctx, data, name, extract.Default, s.Tika)
	if err != nil {
		return Doc{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if res.Truncated {
		return Doc{}, fmt.Errorf("%w: text longer than %d bytes; split the document", ErrInvalid, extract.Default.MaxText)
	}
	fps := Fingerprints(s.Pepper, res.Text)
	if len(fps) < MinShared {
		return Doc{}, fmt.Errorf("%w: too little text to fingerprint (%d fingerprints, need %d)", ErrInvalid, len(fps), MinShared)
	}
	m := hmac.New(sha256.New, s.Pepper)
	m.Write([]byte(res.Text))
	d := Doc{Name: name, Sensitivity: sensitivity, Size: len(fps)}
	err = pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `INSERT INTO similarity.docs (tenant_id, name, sensitivity, content_hmac, fingerprints, registered_by, registered_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING RETURNING id`,
			s.Tenant, name, sensitivity, hex.EncodeToString(m.Sum(nil)), fps, actor, now).Scan(&d.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrExists
		}
		if err != nil {
			return err
		}
		_, err = audit.AppendTx(ctx, tx, s.Tenant, actor, "similarity.register",
			map[string]any{"doc_id": d.ID, "name": name, "sensitivity": sensitivity, "fingerprints": len(fps)})
		return err
	})
	return d, err
}

// Unregister removes a document (declassified, superseded). Audited.
func (s *Store) Unregister(ctx context.Context, actor string, id int64) error {
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		var name string
		err := tx.QueryRow(ctx, "DELETE FROM similarity.docs WHERE tenant_id = $1 AND id = $2 RETURNING name", s.Tenant, id).Scan(&name)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		_, err = audit.AppendTx(ctx, tx, s.Tenant, actor, "similarity.unregister", map[string]any{"doc_id": id, "name": name})
		return err
	})
}

// Listed is a registered document as the API shows it.
type Listed struct {
	Doc
	RegisteredBy string    `json:"registered_by"`
	RegisteredAt time.Time `json:"registered_at"`
}

func (s *Store) List(ctx context.Context) ([]Listed, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, name, sensitivity, cardinality(fingerprints), registered_by, registered_at
		FROM similarity.docs WHERE tenant_id = $1 ORDER BY id`, s.Tenant)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Listed, error) {
		var l Listed
		err := r.Scan(&l.ID, &l.Name, &l.Sensitivity, &l.Size, &l.RegisteredBy, &l.RegisteredAt)
		return l, err
	})
}

// Load builds an index of the tenant's registered documents.
func Load(ctx context.Context, db *pgxpool.Pool, tenant string, pepper []byte) (*Index, error) {
	rows, err := db.Query(ctx, "SELECT id, name, sensitivity, fingerprints FROM similarity.docs WHERE tenant_id = $1 ORDER BY id", tenant)
	if err != nil {
		return nil, err
	}
	var docs []Doc
	var fps [][]int64
	var d Doc
	var f []int64
	_, err = pgx.ForEachRow(rows, []any{&d.ID, &d.Name, &d.Sensitivity, &f}, func() error {
		d.Size = len(f)
		docs, fps = append(docs, d), append(fps, f)
		f = nil
		return nil
	})
	if err != nil {
		return nil, err
	}
	return Build(pepper, docs, fps), nil
}

// Live is the current index, refreshed in the background. A nil *Live or an empty one matches nothing.
type Live struct{ p atomic.Pointer[Index] }

func (l *Live) Index() *Index {
	if l == nil {
		return nil
	}
	return l.p.Load()
}

// Watch loads the index now and reloads it every interval when the corpus changed (spec §13.1: policy changes reach
// every PEP within 60 s; a registered document is treated the same). A failed reload keeps the previous index.
func Watch(ctx context.Context, db *pgxpool.Pool, tenant string, pepper []byte, every time.Duration, log *slog.Logger) (*Live, error) {
	l := &Live{}
	version := func() (v [2]int64, err error) {
		err = db.QueryRow(ctx, "SELECT count(*), coalesce(max(id), 0) FROM similarity.docs WHERE tenant_id = $1", tenant).Scan(&v[0], &v[1])
		return v, err
	}
	load := func() ([2]int64, error) {
		v, err := version()
		if err != nil {
			return v, err
		}
		ix, err := Load(ctx, db, tenant, pepper)
		if err != nil {
			return v, err
		}
		l.p.Store(ix)
		return v, nil
	}
	cur, err := load()
	if err != nil {
		return nil, fmt.Errorf("load similarity index: %w", err)
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if v, err := version(); err != nil || v == cur {
				if err != nil {
					log.Warn("similarity index version check failed", "err", err)
				}
				continue
			}
			v, err := load()
			if err != nil {
				log.Warn("similarity index reload failed; keeping the previous one", "err", err)
				continue
			}
			cur = v
			log.Info("similarity index reloaded", "documents", v[0])
		}
	}()
	return l, nil
}

// Routes mounts the corpus API (control-plane). Registering and removing documents is DLP policy authoring.
func Routes(rt *authz.Router, s *Store, now func() time.Time) {
	reply := func(w http.ResponseWriter, status int, v any, err error) {
		switch {
		case errors.Is(err, ErrInvalid):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, ErrNotFound):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, ErrExists):
			http.Error(w, err.Error(), http.StatusConflict)
		case err != nil:
			http.Error(w, "internal error", http.StatusInternalServerError)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	// Body: the file itself (any format extract supports). Query: name (file name, also picks the format), sensitivity.
	rt.Handle("POST /similarity/docs", authz.PolicyWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, extract.Default.MaxBytes))
		var d Doc
		if err != nil {
			err = fmt.Errorf("%w: body: %v", ErrInvalid, err)
		} else {
			q := r.URL.Query()
			d, err = s.Register(r.Context(), c.Username, q.Get("name"), q.Get("sensitivity"), data, now())
		}
		reply(w, http.StatusCreated, d, err)
	})
	rt.Handle("GET /similarity/docs", authz.PolicyRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		ds, err := s.List(r.Context())
		reply(w, http.StatusOK, ds, err)
	})
	rt.Handle("DELETE /similarity/docs/{id}", authz.PolicyWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			err = ErrNotFound
		} else {
			err = s.Unregister(r.Context(), c.Username, id)
		}
		reply(w, http.StatusOK, map[string]int64{"deleted": id}, err)
	})
}
