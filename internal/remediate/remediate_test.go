package remediate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	neturl "net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/connector"
	"wantimpres26/internal/connector/m365"
	"wantimpres26/internal/connector/m365/m365test"
	"wantimpres26/internal/datascan"
	"wantimpres26/internal/identity"
)

const tenant = "00000000-0000-0000-0000-000000000001"

type env struct {
	db    *pgxpool.Pool
	fake  *m365test.Graph
	sc    *datascan.Scanner
	store *Store
	ex    *Executor
	now   time.Time
}

func setup(t *testing.T) *env {
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
	name := fmt.Sprintf("remediate_test_%d", time.Now().UnixNano()%1e9)
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
	al, err := audit.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(al.Close)
	if _, err := identity.Open(ctx, db, tenant); err != nil {
		t.Fatal(err)
	}
	if err := Open(ctx, db); err != nil {
		t.Fatal(err)
	}
	fake := m365test.New()
	t.Cleanup(fake.Close)
	fake.Drives = []*m365test.Drive{{ID: "lib-1", Name: "Kredit", Type: "documentLibrary", Items: map[string]*m365test.Item{}}}
	g := &m365.Graph{BaseURL: fake.URL(), HTTP: fake.Client(), WriteHTTP: fake.Client(), Domains: []string{"bankmega.com"},
		Backoff: connector.Backoff{Retries: 1, Sleep: func(context.Context, time.Duration) error { return nil }}}
	e := &env{db: db, fake: fake, now: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)}
	clock := func() time.Time { return e.now }
	e.sc = &datascan.Scanner{DB: db, Source: "m365", Conn: g, Pepper: []byte("p"), Log: slog.New(slog.DiscardHandler), Now: clock}
	e.sc.Defaults()
	e.store = &Store{DB: db, Tenant: tenant}
	e.ex = &Executor{DB: db, Tenant: tenant, Scanners: map[string]*datascan.Scanner{"m365": e.sc}, Now: clock, Log: slog.New(slog.DiscardHandler)}
	return e
}

// asset scans one item into an asset and returns its id.
func (e *env) asset(t *testing.T, id string, perms ...map[string]any) string {
	t.Helper()
	e.fake.Put("lib-1", id, m365test.Item{Name: id + ".txt", Content: []byte("NIK 3201011505900001"), Parent: "folder-kredit", Perms: perms})
	if _, err := e.sc.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	var aid string
	if err := e.db.QueryRow(context.Background(), "SELECT id::text FROM data.assets WHERE external_id = $1", id).Scan(&aid); err != nil {
		t.Fatal(err)
	}
	e.fake.Writes = nil
	return aid
}

func (e *env) run(t *testing.T) {
	t.Helper()
	if _, err := e.ex.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (e *env) get(t *testing.T, id string) Remediation {
	t.Helper()
	r, err := e.store.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func flags(t *testing.T, db *pgxpool.Pool, assetID string) ([]string, int) {
	var f []string
	var exp int
	_ = db.QueryRow(context.Background(), "SELECT flags, exposure_score FROM data.assets WHERE id::text = $1", assetID).Scan(&f, &exp)
	return f, exp
}

// AC (ticket 33): dry run vs execution, and no action without approval.
func TestDryRunApproveExecute(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	aid := e.asset(t, "x", m365test.UserPerm("budi@bankmega.com", "owner"), m365test.LinkPerm("anonymous"))
	if f, exp := flags(t, e.db, aid); !slices.Equal(f, []string{"anyone_link"}) || exp != 60 {
		t.Fatalf("scanned: %v %d", f, exp)
	}
	revoke := connector.Action{Kind: connector.RevokeAnyoneLinks}
	r, err := e.store.Request(ctx, "ani@bankmega.com", aid, revoke, "anonymous link on customer data", e.now)
	if err != nil || r.State != "requested" {
		t.Fatalf("request: %+v %v", r, err)
	}
	if _, err := e.store.Request(ctx, "ani@bankmega.com", aid, revoke, "", e.now); !errors.Is(err, ErrState) {
		t.Errorf("duplicate request: %v", err)
	}

	// Dry run: a plan, and nothing written at the source.
	e.run(t)
	r = e.get(t, r.ID)
	if r.State != "planned" || len(r.Plan) != 1 || !strings.HasPrefix(r.Plan[0], "delete permission") || len(e.fake.Writes) != 0 {
		t.Fatalf("planned: %+v; writes %v", r, e.fake.Writes)
	}
	// Not approved: running again executes nothing.
	e.run(t)
	if e.get(t, r.ID).State != "planned" || len(e.fake.Writes) != 0 {
		t.Fatal("executed without approval")
	}
	// The requester cannot approve their own request.
	if _, err := e.store.Decide(ctx, "ANI@bankmega.com", r.ID, true, "", e.now); !errors.Is(err, ErrSelf) {
		t.Errorf("self-approval: %v", err)
	}
	// And the executor refuses anything not properly approved, whatever the row says.
	for _, tamper := range []string{"UPDATE data.remediations SET state = 'approved' WHERE id::text = $1",
		"UPDATE data.remediations SET state = 'approved', decided_by = requested_by WHERE id::text = $1"} {
		if _, err := e.db.Exec(ctx, tamper, r.ID); err != nil {
			t.Fatal(err)
		}
		row := e.get(t, r.ID)
		err := pgx.BeginFunc(ctx, e.db, func(tx pgx.Tx) error { _, err := e.ex.execute(ctx, tx, row); return err })
		if !errors.Is(err, ErrNotApproved) || len(e.fake.Writes) != 0 {
			t.Errorf("tampered approval (%s): %v, writes %v", tamper, err, e.fake.Writes)
		}
		_, _ = e.db.Exec(ctx, "UPDATE data.remediations SET state = 'planned', decided_by = NULL WHERE id::text = $1", r.ID)
	}

	// Approved by someone else: executed exactly as planned, and the asset's exposure follows.
	if _, err := e.store.Decide(ctx, "budi@bankmega.com", r.ID, true, "confirmed with the owner", e.now); err != nil {
		t.Fatal(err)
	}
	e.run(t)
	r = e.get(t, r.ID)
	if r.State != "done" || !slices.Equal(r.Result, r.Plan) || len(e.fake.Writes) != 1 || r.Undoable {
		t.Fatalf("executed: %+v; writes %v (a deleted link is not restorable)", r, e.fake.Writes)
	}
	if f, exp := flags(t, e.db, aid); len(f) != 0 || exp != 6 {
		t.Errorf("after remediation: %v %d", f, exp)
	}
	// Nothing left to do for the same action now.
	n, _ := e.store.Request(ctx, "ani@bankmega.com", aid, revoke, "", e.now)
	e.run(t)
	if e.get(t, n.ID).State != "nothing_to_do" {
		t.Errorf("second revoke: %s", e.get(t, n.ID).State)
	}

	var actions []string
	rows, _ := e.db.Query(ctx, "SELECT actor || ':' || action FROM audit.audit_log WHERE action LIKE 'data.remediation.%' ORDER BY seq")
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	want := []string{"ani@bankmega.com:data.remediation.request", "connector-worker:data.remediation.plan", "budi@bankmega.com:data.remediation.approve",
		"connector-worker:data.remediation.execute", "ani@bankmega.com:data.remediation.request", "connector-worker:data.remediation.nothing_to_do"}
	if !slices.Equal(actions, want) {
		t.Errorf("audit:\n got %v\nwant %v", actions, want)
	}
}

// The source changed between plan and approval: the approved plan is not what would happen, so nothing runs.
func TestStalePlan(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	aid := e.asset(t, "y", m365test.UserPerm("budi@bankmega.com", "owner"), m365test.GroupPerm("Everyone except external users"))
	r, _ := e.store.Request(ctx, "ani@bankmega.com", aid, connector.Action{Kind: connector.RemoveGrants, Grants: []string{"Everyone except external users", "partner@konsultan.co.id"}}, "", e.now)
	e.run(t)
	// Someone also shares it with the partner before the approval.
	e.fake.Share("lib-1", "y", []map[string]any{m365test.UserPerm("budi@bankmega.com", "owner"), m365test.GroupPerm("Everyone except external users"),
		m365test.UserPerm("partner@konsultan.co.id", "write")})
	e.fake.Writes = nil
	_, _ = e.store.Decide(ctx, "budi@bankmega.com", r.ID, true, "", e.now)
	e.run(t)
	if r = e.get(t, r.ID); r.State != "stale" || len(e.fake.Writes) != 0 || len(r.Plan) != 2 {
		t.Fatalf("stale: %+v, writes %v", r, e.fake.Writes)
	}
	// A plan nobody approves in time expires.
	r2, _ := e.store.Request(ctx, "ani@bankmega.com", aid, connector.Action{Kind: connector.Quarantine}, "", e.now)
	e.run(t)
	if _, err := e.store.Decide(ctx, "budi@bankmega.com", r2.ID, true, "", e.now.Add(PlanTTL+time.Minute)); !errors.Is(err, ErrState) || e.get(t, r2.ID).State != "expired" {
		t.Errorf("late approval: %v, %s", err, e.get(t, r2.ID).State)
	}
}

// Undo is a remediation of its own: planned, approved by someone else, executed.
func TestUndo(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	aid := e.asset(t, "z", m365test.UserPerm("budi@bankmega.com", "owner"), m365test.UserPerm("ani@bankmega.com", "read"))
	r, _ := e.store.Request(ctx, "ani@bankmega.com", aid, connector.Action{Kind: connector.Quarantine}, "", e.now)
	e.run(t)
	_, _ = e.store.Decide(ctx, "budi@bankmega.com", r.ID, true, "", e.now)
	e.run(t)
	if r = e.get(t, r.ID); r.State != "done" || !r.Undoable || e.fake.Item("lib-1", "z").Parent != "folder-wantimpres26-quarantine" {
		t.Fatalf("quarantine: %+v", r)
	}
	u, err := e.store.RequestUndo(ctx, "ani@bankmega.com", r.ID, "false positive", e.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.RequestUndo(ctx, "ani@bankmega.com", r.ID, "", e.now); !errors.Is(err, ErrState) {
		t.Errorf("second undo: %v", err)
	}
	e.run(t)
	if u = e.get(t, u.ID); u.State != "planned" || e.fake.Item("lib-1", "z").Parent != "folder-wantimpres26-quarantine" {
		t.Fatalf("undo planned: %+v", u)
	}
	_, _ = e.store.Decide(ctx, "budi@bankmega.com", u.ID, true, "", e.now)
	e.run(t)
	if e.get(t, u.ID).State != "done" || e.get(t, r.ID).State != "undone" || e.fake.Item("lib-1", "z").Parent != "folder-kredit" || len(e.fake.Item("lib-1", "z").Perms) != 2 {
		t.Errorf("undone: %+v %+v", e.get(t, u.ID), e.fake.Item("lib-1", "z"))
	}
	if _, err := e.store.RequestUndo(ctx, "ani@bankmega.com", u.ID, "", e.now); !errors.Is(err, ErrState) {
		t.Errorf("undo of an undo: %v", err)
	}
}
