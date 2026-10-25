package similarity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	neturl "net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/audit"
)

const tenant = "00000000-0000-0000-0000-000000000037"

func testDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("AUDIT_TEST_DATABASE_URL")
	if dbURL == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("AUDIT_TEST_DATABASE_URL must be set in CI")
		}
		t.Skip("no test Postgres")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("similarity_test_%d", time.Now().UnixNano()%1e9)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)"); admin.Close() })
	u, _ := neturl.Parse(dbURL)
	u.Path = "/" + name
	al, err := audit.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(al.Close)
	db, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if err := Open(ctx, db); err != nil {
		t.Fatal(err)
	}
	return db
}

// TestStore: register a document, find it through a live index, refuse duplicates and junk, unregister it; every
// change audited; no text stored.
func TestStore(t *testing.T) {
	db := testDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Store{DB: db, Tenant: tenant, Pepper: key}
	now := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	c := newCorpus(5)
	text := c.doc(1500)

	live, err := Watch(ctx, db, tenant, key, 50*time.Millisecond, slog.New(slog.DiscardHandler))
	if err != nil || live.Index().Len() != 0 {
		t.Fatalf("watch: %v %d", err, live.Index().Len())
	}
	d, err := s.Register(ctx, "dlp1", "rencana-akuisisi.txt", "restricted", []byte(text), now)
	if err != nil || d.ID == 0 || d.Size < 100 {
		t.Fatalf("register: %+v %v", d, err)
	}
	if _, err := s.Register(ctx, "dlp1", "copy.txt", "restricted", []byte(text), now); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	for _, bad := range []struct{ name, sens, body string }{
		{"x.txt", "internal", text},  // only confidential/restricted are worth registering
		{"", "restricted", text},     // name required
		{"x.txt", "restricted", "a"}, // too short to fingerprint
	} {
		if _, err := s.Register(ctx, "dlp1", bad.name, bad.sens, []byte(bad.body), now); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v: %v", bad, err)
		}
	}
	// The live index picks the document up within a refresh.
	prompt := c.prompt(c.excerpt(text, 50))
	deadline := time.Now().Add(5 * time.Second)
	for len(live.Index().Match(prompt)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("registered document not found by the live index")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if h := live.Index().Match(prompt)[0]; h.Doc.ID != d.ID || h.Doc.Sensitivity != "restricted" || h.Doc.Name != "rencana-akuisisi.txt" {
		t.Fatalf("hit: %+v", h)
	}
	ls, err := s.List(ctx)
	if err != nil || len(ls) != 1 || ls[0].RegisteredBy != "dlp1" || ls[0].Size != d.Size {
		t.Fatalf("list: %+v %v", ls, err)
	}
	// Only fingerprints are stored: no column holds a word of the text.
	var row string
	if err := db.QueryRow(ctx, "SELECT row_to_json(d)::text FROM similarity.docs d").Scan(&row); err != nil {
		t.Fatal(err)
	}
	for _, w := range strings.Fields(c.excerpt(text, 20)) {
		if len(w) > 5 && strings.Contains(row, strings.ToLower(strings.Trim(w, ".,"))) {
			t.Fatalf("stored row contains document word %q", w)
		}
	}
	if err := s.Unregister(ctx, "dlp2", d.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Unregister(ctx, "dlp2", d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second unregister: %v", err)
	}
	for deadline = time.Now().Add(5 * time.Second); len(live.Index().Match(prompt)) > 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("unregistered document still matched")
		}
	}
	var actions []string
	rows, _ := db.Query(ctx, "SELECT actor || ':' || action FROM audit.audit_log ORDER BY seq")
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	if got := strings.Join(actions, ","); got != "dlp1:similarity.register,dlp2:similarity.unregister" {
		t.Fatalf("audit: %s", got)
	}
}
