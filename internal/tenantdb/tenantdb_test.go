package tenantdb_test

import (
	"context"
	"fmt"
	neturl "net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/incident"
	"wantimpres26/internal/lifecycle"
	"wantimpres26/internal/riskcal"
	"wantimpres26/internal/similarity"
	"wantimpres26/internal/tenantdb"
	"wantimpres26/internal/tokvault"
	"wantimpres26/internal/tuning"
	"wantimpres26/policy"
)

// notIsolated are tables with a tenant_id that deliberately stay outside row level security (ADR-0003).
var notIsolated = map[string]string{
	"audit.audit_log": "one hash chain over every tenant: verification, the WORM anchor and the SIEM tail read it whole",
}

// TestRowLevelSecurity (ticket 42 AC): every table with a tenant_id, and every table hanging off one, is under a
// forced tenant policy; the application role sees only its tenant, nothing without a tenant, and cannot write
// another tenant's rows, the table owner included.
func TestRowLevelSecurity(t *testing.T) {
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
	name := fmt.Sprintf("tenantdb_test_%d", time.Now().UnixNano()%1e9)
	role := name + "_app"
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+role)
		admin.Close()
	})
	u, _ := neturl.Parse(dbURL)
	u.Path = "/" + name
	db, err := pgxpool.New(ctx, u.String()) // superuser: applies the schemas and seeds both tenants
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)

	a, b := uuid.NewString(), uuid.NewString()
	kek := make([]byte, 32)
	al, err := audit.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(al.Close)
	ls, err := lifecycle.Open(ctx, db, a, policy.Files)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := incident.Open(ctx, db, al, kek); err != nil {
		t.Fatal(err)
	}
	if err := riskcal.Open(ctx, &riskcal.Store{DB: db, Tenant: a, Policies: ls, FS: policy.Files}); err != nil {
		t.Fatal(err)
	}
	if err := similarity.Open(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := tuning.Open(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := tokvault.Open(ctx, db, al, b, kek); err != nil { // creates tenant b's key
		t.Fatal(err)
	}
	// Twice: a restart changes nothing.
	if err := tenantdb.Isolate(ctx, db, "riskcal.versions"); err != nil {
		t.Fatal(err)
	}

	// Structure: every table with tenant_id, and every table with a foreign key to one of those, is forced.
	rows, err := db.Query(ctx, `
		WITH tenant AS (
		  SELECT c.oid FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid
		  WHERE c.relkind = 'r' AND a.attname = 'tenant_id' AND NOT a.attisdropped),
		child AS (SELECT conrelid AS oid FROM pg_constraint WHERE contype = 'f' AND confrelid IN (SELECT oid FROM tenant))
		SELECT n.nspname || '.' || c.relname, c.relrowsecurity, c.relforcerowsecurity,
		  coalesce((SELECT p.qual || '|' || p.with_check FROM pg_policies p WHERE p.schemaname = n.nspname AND p.tablename = c.relname AND p.policyname = 'tenant'), ''),
		  c.oid IN (SELECT oid FROM tenant)
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.oid IN (SELECT oid FROM tenant UNION SELECT oid FROM child) ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	var isolated []string
	for rows.Next() {
		var table, policy string
		var enabled, forced, direct bool
		if err := rows.Scan(&table, &enabled, &forced, &policy, &direct); err != nil {
			t.Fatal(err)
		}
		if notIsolated[table] != "" {
			continue
		}
		qual, check, _ := strings.Cut(policy, "|")
		want := "tenant_id = (current_setting('app.tenant_id'::text, true))::uuid"
		if !direct {
			want = "SELECT incidents.id"
		}
		if !enabled || !forced || !strings.Contains(qual, want) || qual != check {
			t.Errorf("%s: rls %v forced %v policy %q", table, enabled, forced, policy)
		}
		isolated = append(isolated, table)
	}
	if len(isolated) != 16 {
		t.Errorf("%d isolated tables: %v", len(isolated), isolated)
	}

	// Data for both tenants (the superuser bypasses the policies).
	inc := map[string]string{a: uuid.NewString(), b: uuid.NewString()}
	for _, ten := range []string{a, b} {
		i := inc[ten]
		for _, q := range []string{
			`INSERT INTO incident.incidents (id, tenant_id, dedup_key, title, state, severity, max_risk, event_count, first_event_at, last_event_at, dek_wrapped)
			 VALUES ('%[2]s', '%[1]s', 'k', 't', 'New', 'low', 40, 1, now(), now(), '\x00')`,
			`INSERT INTO incident.blocks (tenant_id, incident_id, principal_id, app_id, expires_at, created_by, created_at) VALUES ('%[1]s', '%[2]s', 'p', 'chatgpt', now(), 'soc', now())`,
			`INSERT INTO incident.incident_events (incident_id, event_id, ts, risk_score, event) VALUES ('%[2]s', gen_random_uuid(), now(), 40, '{}')`,
			`INSERT INTO incident.evidence (incident_id, kind, ciphertext, sha256, expires_at) VALUES ('%[2]s', 'prompt', '\x00', 'h', now())`,
			`INSERT INTO incident.transitions (incident_id, actor, from_state, to_state) VALUES ('%[2]s', 'soc', 'New', 'Triaged')`,
			`INSERT INTO incident.actions (incident_id, action, params, result, actor, at) VALUES ('%[2]s', 'open_ticket', '{}', '{}', 'soc', now())`,
			`INSERT INTO incident.tickets (incident_id, system, ref, url, created_at) VALUES ('%[2]s', 'jira-sm', 'S-1', 'u', now())`,
			`INSERT INTO incident.unmask_requests (incident_id, evidence_id, requester, justification, created_at) VALUES ('%[2]s', gen_random_uuid(), 'dpo', 'j', now())`,
			`INSERT INTO riskcal.versions (tenant_id, version, state, config, author) VALUES ('%[1]s', 1, 'draft', '{}', 'x')`,
			`INSERT INTO similarity.docs (tenant_id, name, sensitivity, content_hmac, fingerprints, registered_by, registered_at) VALUES ('%[1]s', 'd', 'restricted', 'h', '{1}', 'x', now())`,
			`INSERT INTO tokvault.tokens (tenant_id, class, token_mac, expires_at) VALUES ('%[1]s', 'PII_ID.NIK', 'm', now())`,
			`INSERT INTO tuning.optin (tenant_id, enabled, note, actor, at) VALUES ('%[1]s', true, 'n', 'dpo', now())`,
			`INSERT INTO tuning.labels (tenant_id, event_id, class, tp, labeled_by, labeled_at) VALUES ('%[1]s', gen_random_uuid(), 'PCI.PAN', true, 'soc', now())`,
			`INSERT INTO tuning.models (tenant_id, version, stage, weights, gate, labels, trained_by, trained_at, changed_at) VALUES ('%[1]s', 1, 'candidate', '{}', '{}', 1, 'x', now(), now())`,
			`INSERT INTO tuning.holdout (tenant_id, quarter, event_id, class, tp) VALUES ('%[1]s', '2026Q4', gen_random_uuid(), 'PCI.PAN', true)`,
		} {
			if _, err := db.Exec(ctx, fmt.Sprintf(q, ten, i)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := db.Exec(ctx, fmt.Sprintf("INSERT INTO tokvault.keys (tenant_id, wrapped) VALUES ('%s', '\\x00')", a)); err != nil {
		t.Fatal(err)
	}

	// The application role: no superuser, no BYPASSRLS, and owner of the tables (it applies the schemas in
	// production), so FORCE is what holds it.
	if _, err := admin.Exec(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD 'app' NOSUPERUSER NOBYPASSRLS", role)); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"incident", "riskcal", "similarity", "tokvault", "tuning"} {
		if _, err := db.Exec(ctx, fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO %s", s, role)); err != nil {
			t.Fatal(err)
		}
	}
	for _, tb := range isolated {
		if _, err := db.Exec(ctx, fmt.Sprintf("ALTER TABLE %s OWNER TO %s", tb, role)); err != nil {
			t.Fatal(err)
		}
	}
	appURL := *u
	appURL.User = neturl.UserPassword(role, "app")

	asA, err := tenantdb.Pool(ctx, appURL.String(), a)
	if err != nil {
		t.Fatal(err)
	}
	defer asA.Close()
	none, err := pgxpool.New(ctx, appURL.String()) // the same role without a tenant
	if err != nil {
		t.Fatal(err)
	}
	defer none.Close()
	for _, tb := range isolated {
		var n, foreign int
		if err := none.QueryRow(ctx, "SELECT count(*) FROM "+tb).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s without a tenant: %d rows, %v", tb, n, err)
		}
		if err := asA.QueryRow(ctx, "SELECT count(*) FROM "+tb).Scan(&n); err != nil || n != 1 {
			t.Errorf("%s as tenant a: %d rows (want 1), %v", tb, n, err)
		}
		col := "tenant_id::text"
		if !strings.HasPrefix(tb, "riskcal") && !strings.HasPrefix(tb, "similarity") && !strings.HasPrefix(tb, "tokvault") &&
			!strings.HasPrefix(tb, "tuning") && tb != "incident.incidents" && tb != "incident.blocks" {
			col = "(SELECT tenant_id::text FROM incident.incidents i WHERE i.id = incident_id)"
		}
		if err := asA.QueryRow(ctx, fmt.Sprintf("SELECT count(*) FROM %s WHERE %s <> $1", tb, col), a).Scan(&foreign); err != nil || foreign != 0 {
			t.Errorf("%s as tenant a sees %d rows of another tenant, %v", tb, foreign, err)
		}
	}
	// Writing another tenant's rows: refused on insert, invisible to update and delete.
	for _, q := range []string{
		fmt.Sprintf("INSERT INTO riskcal.versions (tenant_id, version, state, config, author) VALUES ('%s', 2, 'draft', '{}', 'x')", b),
		fmt.Sprintf("INSERT INTO incident.transitions (incident_id, actor, from_state, to_state) VALUES ('%s', 'x', 'New', 'Triaged')", inc[b]),
		fmt.Sprintf("UPDATE incident.incidents SET tenant_id = '%s' WHERE id = '%s'", b, inc[a]),
	} {
		if _, err := asA.Exec(ctx, q); err == nil || !strings.Contains(err.Error(), "row-level security") {
			t.Errorf("as tenant a: %s: %v", q[:40], err)
		}
	}
	for _, q := range []string{"UPDATE tuning.models SET stage = 'retired' WHERE tenant_id = $1", "DELETE FROM tokvault.keys WHERE tenant_id = $1"} {
		if tag, err := asA.Exec(ctx, q, b); err != nil || tag.RowsAffected() != 0 {
			t.Errorf("as tenant a: %s: %d rows, %v", q, tag.RowsAffected(), err)
		}
	}
	// The owner cannot switch the policies off for itself by accident: FORCE survives a new session.
	var forced bool
	if err := asA.QueryRow(ctx, "SELECT relforcerowsecurity FROM pg_class WHERE oid = 'incident.incidents'::regclass").Scan(&forced); err != nil || !forced {
		t.Errorf("forced: %v %v", forced, err)
	}

	// The pool refuses a role the policies do not bind, and a malformed tenant.
	if _, err := tenantdb.Pool(ctx, u.String(), a); err == nil || !strings.Contains(err.Error(), "bypasses row level security") {
		t.Errorf("superuser pool: %v", err)
	}
	t.Setenv("DATABASE_ALLOW_BYPASSRLS", "true")
	if p, err := tenantdb.Pool(ctx, u.String(), a); err != nil {
		t.Errorf("superuser pool allowed for development: %v", err)
	} else {
		p.Close()
	}
	if _, err := tenantdb.Pool(ctx, appURL.String(), "not-a-uuid"); err == nil {
		t.Error("malformed tenant accepted")
	}
}
