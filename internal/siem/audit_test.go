package siem

import (
	"context"
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

// The audit tail exports every entry once, in order, and reports its lag; a second replica holding the cursor
// row must not export the same entries again.
func TestAuditTail(t *testing.T) {
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
	name := fmt.Sprintf("siem_test_%d", time.Now().UnixNano()%1e9)
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
	for i := range 3 {
		if _, err := al.Append(ctx, "00000000-0000-0000-0000-000000000001", "admin", "policy.version.approve", map[string]any{"n": i}); err != nil {
			t.Fatal(err)
		}
	}

	sink := &fakeSink{name: "s"}
	d, _ := deliverer(sink)
	tail := &AuditTail{DB: db, Audit: al, Deliver: d, Every: 50 * time.Millisecond, Log: slog.New(slog.DiscardHandler)}
	other := &AuditTail{DB: db, Audit: al, Deliver: d, Every: 50 * time.Millisecond, Log: slog.New(slog.DiscardHandler)}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	go func() { _ = tail.Run(runCtx) }()
	go func() { _ = other.Run(runCtx) }()
	waitFor := func(n int) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); len(sink.records()) < n && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		}
	}
	waitFor(3)
	if _, err := al.Append(ctx, "00000000-0000-0000-0000-000000000001", "dpo1", "evidence.unmask", map[string]any{"justification": "NIK 3171234567890001"}); err != nil {
		t.Fatal(err)
	}
	waitFor(4)
	time.Sleep(300 * time.Millisecond) // give a duplicate the chance to appear
	stop()
	got := sink.records()
	var ids []string
	for _, r := range got {
		ids = append(ids, r.ID)
	}
	if strings.Join(ids, ",") != "audit-1,audit-2,audit-3,audit-4" {
		t.Errorf("exported %v, want each entry once in order", ids)
	}
	if strings.Contains(got[3].CEF(), "3171234567890001") {
		t.Error("NIK in exported audit entry")
	}
	if c := max(tail.Cursor(), other.Cursor()); c != 4 || tail.Lag() != 0 || other.Lag() != 0 {
		t.Errorf("cursor %d lag %d/%d", c, tail.Lag(), other.Lag())
	}
}
