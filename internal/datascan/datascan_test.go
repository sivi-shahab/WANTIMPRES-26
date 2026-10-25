package datascan

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	neturl "net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/agents"
	"wantimpres26/internal/audit"
	"wantimpres26/internal/catalog"
	"wantimpres26/internal/connector"
	"wantimpres26/internal/connector/m365"
	"wantimpres26/internal/connector/m365/m365test"
	"wantimpres26/internal/identity"
	"wantimpres26/internal/lifecycle"
	"wantimpres26/policy"
)

const nik = "3201011505900001"

func setup(t *testing.T) (*pgxpool.Pool, *m365test.Graph, *Scanner) {
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
	name := fmt.Sprintf("datascan_test_%d", time.Now().UnixNano()%1e9)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)"); admin.Close() })
	u, _ := neturl.Parse(dbURL)
	u.Path = "/" + name
	db, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if _, err := identity.Open(ctx, db, "00000000-0000-0000-0000-000000000001"); err != nil {
		t.Fatal(err)
	}
	for _, u := range []struct {
		name   string
		active bool
	}{{"budi@bankmega.com", true}, {"eko@bankmega.com", false}} {
		if _, err := db.Exec(ctx, "INSERT INTO identity.users (user_name, active, doc) VALUES ($1, $2, '{}')", u.name, u.active); err != nil {
			t.Fatal(err)
		}
	}
	if err := Open(ctx, db); err != nil {
		t.Fatal(err)
	}
	fake := m365test.New()
	t.Cleanup(fake.Close)
	fake.Drives = []*m365test.Drive{{ID: "lib-1", Name: "Kredit", Type: "documentLibrary", Items: map[string]*m365test.Item{}}}
	g := &m365.Graph{BaseURL: fake.URL(), HTTP: fake.Client(), Domains: []string{"bankmega.com"}, Backoff: connector.Backoff{Retries: 5,
		Base: time.Second, Max: time.Minute, Sleep: func(context.Context, time.Duration) error { return nil }}}
	s := &Scanner{DB: db, Source: "m365", Conn: g, Pepper: []byte("pepper"), Labels: map[string]string{"lbl-restricted": "restricted"},
		Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC) }}
	s.Defaults()
	return db, fake, s
}

func docx(t *testing.T, text string) []byte {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, _ := w.Create("word/document.xml")
	_, _ = f.Write([]byte(`<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>` + text + `</w:t></w:r></w:p></w:body></w:document>`))
	_ = w.Close()
	return b.Bytes()
}

func bomb(t *testing.T) []byte {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, _ := w.Create("zeros.txt")
	_, _ = f.Write(make([]byte, 10<<20))
	_ = w.Close()
	return b.Bytes()
}

type row struct {
	sens     string
	exposure int
	flags    []string
	scanned  bool
	note     *string
	deleted  bool
}

func asset(t *testing.T, db *pgxpool.Pool, id string) row {
	t.Helper()
	var r row
	var del *time.Time
	if err := db.QueryRow(context.Background(), "SELECT sensitivity, exposure_score, flags, content_scanned, scan_note, deleted_at FROM data.assets WHERE external_id = $1", id).
		Scan(&r.sens, &r.exposure, &r.flags, &r.scanned, &r.note, &del); err != nil {
		t.Fatalf("asset %s: %v", id, err)
	}
	r.deleted = del != nil
	return r
}

func TestScan(t *testing.T) {
	db, fake, s := setup(t)
	ctx := context.Background()
	fake.Put("lib-1", "a", m365test.Item{Name: "nasabah.txt", Path: "/drive/root:/kredit", Content: []byte("Data NIK " + nik),
		Perms: []map[string]any{m365test.GroupPerm("Everyone except external users")}})
	fake.Put("lib-1", "b", m365test.Item{Name: "kartu.docx", Path: "/drive/root:/kredit", Content: docx(t, "kartu 4111 1111 1111 1111"),
		Perms: []map[string]any{m365test.LinkPerm("anonymous")}})
	fake.Put("lib-1", "c", m365test.Item{Name: "strategi.txt", Path: "/drive/root:/direksi", Content: []byte("Rencana ekspansi 2027"),
		Labels: []string{"lbl-restricted"}, Perms: []map[string]any{m365test.UserPerm("partner@konsultan.co.id", "read")}})
	fake.Put("lib-1", "d", m365test.Item{Name: "notulen.txt", Path: "/drive/root:/umum", Content: []byte("Rapat mingguan"),
		Perms: []map[string]any{m365test.UserPerm("budi@bankmega.com", "owner"), m365test.UserPerm("eko@bankmega.com", "write")}})
	fake.Put("lib-1", "e", m365test.Item{Name: "arsip.zip", Path: "/drive/root:/umum", Content: bomb(t)})
	fake.Put("lib-1", "f", m365test.Item{Name: "kredit", Path: "/drive/root:", Folder: true})
	fake.Throttle["/permissions"] = &m365test.Throttle{Times: 2, Status: 429, RetryAfter: "1"} // the scan rides it out

	st, err := s.Run(ctx)
	if err != nil || st.Errors != 0 {
		t.Fatalf("bootstrap: %+v %v", st, err)
	}
	// A small library goes full after the sampled first pass: every file classified, each read exactly once.
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		if n := fake.Count("content:" + id); n != 1 {
			t.Errorf("content of %s read %d times", id, n)
		}
	}
	var mode string
	_ = db.QueryRow(ctx, "SELECT mode FROM data.containers WHERE container_id = 'lib-1'").Scan(&mode)
	if mode != "full" {
		t.Errorf("small container mode %s", mode)
	}
	for id, want := range map[string]row{
		"a": {sens: "confidential", exposure: 36, flags: []string{FlagBroadGroup}, scanned: true},
		"b": {sens: "confidential", exposure: 60, flags: []string{FlagAnyoneLink}, scanned: true},
		"c": {sens: "restricted", exposure: 80, flags: []string{FlagExternalShare}, scanned: true}, // by label: the text alone is internal
		"d": {sens: "internal", exposure: 9, flags: []string{FlagOrphan}, scanned: true},
	} {
		got := asset(t, db, id)
		if got.sens != want.sens || got.exposure != want.exposure || !slices.Equal(got.flags, want.flags) || !got.scanned {
			t.Errorf("asset %s: %+v, want %+v", id, got, want)
		}
	}
	if e := asset(t, db, "e"); e.note == nil || !strings.HasPrefix(*e.note, "extraction limit") {
		t.Errorf("zip bomb: %+v", e)
	}
	var classes []string
	rows, _ := db.Query(ctx, "SELECT c.class FROM data.classifications c JOIN data.assets a ON a.id = c.asset_id WHERE a.external_id IN ('a', 'b') ORDER BY 1")
	for rows.Next() {
		var c string
		_ = rows.Scan(&c)
		classes = append(classes, c)
	}
	if !slices.Equal(classes, []string{"PCI.PAN", "PII_ID.NIK"}) {
		t.Errorf("classes %v", classes)
	}
	// FR-DATA-5: no raw content anywhere, not even the path.
	var leak int
	_ = db.QueryRow(ctx, `SELECT count(*) FROM (SELECT row_to_json(a)::text j FROM data.assets a UNION ALL SELECT row_to_json(c)::text FROM data.classifications c
		UNION ALL SELECT row_to_json(g)::text FROM data.acl_entries g UNION ALL SELECT row_to_json(k)::text FROM data.containers k) x
		WHERE j LIKE '%' || $1 || '%' OR j LIKE '%4111 1111%' OR j LIKE '%4111111111111111%' OR j LIKE '%ekspansi%' OR j LIKE '%/kredit%'`, nik).Scan(&leak)
	if leak != 0 {
		t.Errorf("%d rows hold raw content or paths", leak)
	}

	// AC: an incremental scan does not repeat unchanged items.
	st, _ = s.Run(ctx)
	if st.Items != 0 || st.ContentRead != 0 || st.ACLRead != 0 {
		t.Errorf("nothing changed, yet: %+v", st)
	}
	// One content change, one sharing change, one deletion: exactly those are touched.
	fake.Put("lib-1", "b", m365test.Item{Name: "kartu.docx", Path: "/drive/root:/kredit", Content: docx(t, "kartu sudah ditutup"),
		Perms: []map[string]any{m365test.LinkPerm("anonymous")}})
	fake.Share("lib-1", "d", []map[string]any{m365test.LinkPerm("anonymous")})
	fake.Delete("lib-1", "a")
	st, _ = s.Run(ctx)
	if st.Items != 3 || st.ContentRead != 1 || st.ACLRead != 2 || st.Deleted != 1 || st.Unchanged != 1 {
		t.Errorf("incremental: %+v", st)
	}
	if fake.Count("content:b") != 2 || fake.Count("content:d") != 1 || fake.Count("content:c") != 1 || fake.Count("perms:c") != 1 {
		t.Errorf("fetches: content b=%d d=%d c=%d, perms c=%d", fake.Count("content:b"), fake.Count("content:d"), fake.Count("content:c"), fake.Count("perms:c"))
	}
	if b := asset(t, db, "b"); b.sens != "internal" || b.exposure != 30 {
		t.Errorf("b after the card number left: %+v", b)
	}
	if d := asset(t, db, "d"); !slices.Equal(d.flags, []string{FlagAnyoneLink}) || d.exposure != 30 {
		t.Errorf("d after an anyone link: %+v", d)
	}
	if a := asset(t, db, "a"); !a.deleted {
		t.Error("deleted item still live")
	}
}

// FR-DATA-3: a large container is sampled; a dense one goes full.
func TestAdaptiveSampling(t *testing.T) {
	_, fake, s := setup(t)
	s.SamplePercent, s.SmallContainer, s.MinSample = 10, 10, 3
	fake.PageSize = 25
	fake.Drives = append(fake.Drives, &m365test.Drive{ID: "lib-2", Name: "Arsip KTP", Type: "documentLibrary", Items: map[string]*m365test.Item{}})
	for i := range 200 {
		fake.Put("lib-1", fmt.Sprintf("plain-%03d", i), m365test.Item{Name: "memo.txt", Content: []byte("Rapat mingguan unit operasional")})
		fake.Put("lib-2", fmt.Sprintf("ktp-%03d", i), m365test.Item{Name: "ktp.txt", Content: []byte("NIK " + nik)})
	}
	if _, err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	read := func(prefix string) int {
		n := 0
		for i := range 200 {
			n += fake.Count(fmt.Sprintf("content:%s-%03d", prefix, i))
		}
		return n
	}
	if n := read("plain"); n < 5 || n > 40 {
		t.Errorf("benign 200-file library: %d read, want ~10%%", n)
	}
	if n := read("ktp"); n != 200 {
		t.Errorf("dense library: %d of 200 read, want all", n)
	}
}

// Google token audit → OAuth grants; AI apps among them (by keyword or the AI app catalog) join the shadow-agent
// review queue.
func TestOAuthAudit(t *testing.T) {
	db, _, _ := setup(t)
	ctx := context.Background()
	u := db.Config().ConnString()
	al, err := audit.Open(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(al.Close)
	ls, err := lifecycle.Open(ctx, db, "00000000-0000-0000-0000-000000000001", policy.Files)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Open(ctx, db, "00000000-0000-0000-0000-000000000001", ls); err != nil {
		t.Fatal(err)
	}
	if _, err := agents.Open(ctx, db, "00000000-0000-0000-0000-000000000001", ls); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	var asked []time.Time
	grants := []connector.OAuthGrant{
		{ClientID: "c-chatgpt", AppName: "ChatGPT", Scopes: []string{"drive.readonly"}, User: "ani@bankmega.com", At: now.Add(-2 * time.Hour)},
		{ClientID: "c-chatgpt", AppName: "ChatGPT", Scopes: []string{"gmail.readonly"}, User: "Budi@bankmega.com", At: now.Add(-time.Hour)},
		{ClientID: "c-gram", AppName: "Grammarly for Chrome", User: "ani@bankmega.com", At: now.Add(-time.Hour)}, // in the AI catalog
		{ClientID: "c-zoom", AppName: "Zoom for Google Workspace", User: "ani@bankmega.com", At: now.Add(-time.Hour)},
		{ClientID: "c-drive", AppName: "Google Drive for desktop", User: "ani@bankmega.com", At: now.Add(-time.Hour)}, // vendor Google: not AI
	}
	a := &OAuthAudit{DB: db, Source: "gworkspace", Pepper: []byte("p"), Now: func() time.Time { return now },
		Fetch: func(_ context.Context, since time.Time) ([]connector.OAuthGrant, error) {
			asked = append(asked, since)
			return grants, nil
		}}
	for range 2 { // the second pass re-reads the overlap: nothing doubles
		if n, err := a.Run(ctx); err != nil || n != 2 {
			t.Fatalf("AI apps: %d %v", n, err)
		}
	}
	if !asked[0].Equal(now.Add(-30*24*time.Hour)) || !asked[1].Equal(now.Add(-Lag)) {
		t.Errorf("since %v", asked)
	}
	rows, _ := db.Query(ctx, `SELECT g.client_id, g.ai, g.scopes, (SELECT count(*) FROM data.oauth_grant_users u WHERE u.client_id = g.client_id)
		FROM data.oauth_grants g ORDER BY 1`)
	var got []string
	for rows.Next() {
		var id string
		var ai bool
		var scopes []string
		var users int
		_ = rows.Scan(&id, &ai, &scopes, &users)
		slices.Sort(scopes)
		got = append(got, fmt.Sprintf("%s ai=%v users=%d %v", id, ai, users, scopes))
	}
	want := []string{"c-chatgpt ai=true users=2 [drive.readonly gmail.readonly]", "c-drive ai=false users=1 []", "c-gram ai=true users=1 []", "c-zoom ai=false users=1 []"}
	if !slices.Equal(got, want) {
		t.Errorf("grants:\n got %v\nwant %v", got, want)
	}
	var queued []string
	rows, _ = db.Query(ctx, "SELECT agent_id || ':' || source || ':' || state FROM agents.discovered ORDER BY 1")
	for rows.Next() {
		var q string
		_ = rows.Scan(&q)
		queued = append(queued, q)
	}
	if !slices.Equal(queued, []string{"oauth:c-chatgpt:oauth_grant:pending", "oauth:c-gram:oauth_grant:pending"}) {
		t.Errorf("review queue %v", queued)
	}
	var leak int
	_ = db.QueryRow(ctx, "SELECT count(*) FROM data.oauth_grant_users WHERE user_hash LIKE '%@%'").Scan(&leak)
	if leak != 0 {
		t.Error("e-mail stored in clear")
	}
}
