package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/audit"
)

const tenant = "00000000-0000-0000-0000-000000000001"

// setup gives the test a database of its own (packages run in parallel and share the Postgres).
func setup(t *testing.T) (*Store, *pgxpool.Pool, *audit.Store) {
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
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name := fmt.Sprintf("identity_test_%x", b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		admin.Close()
	})
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
	s, err := Open(ctx, db, tenant)
	if err != nil {
		t.Fatal(err)
	}
	return s, db, al
}

type scimClient struct {
	t     *testing.T
	srv   *httptest.Server
	token string
}

func (c scimClient) do(method, path, body string) (int, map[string]any) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/scim+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var v map[string]any
	_ = json.Unmarshal(raw, &v)
	return resp.StatusCode, v
}

func roles(t *testing.T, s *Store, user string) []string {
	t.Helper()
	bs, err := s.Bindings(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, b := range bs {
		out = append(out, b.Role)
	}
	slices.Sort(out)
	return out
}

// SCIM provisioning from the IdP, then role bindings: who holds what follows group membership and activation,
// and every change that moves permissions is in the audit log (ticket 06 AC 2).
func TestSCIMAndBindings(t *testing.T) {
	s, db, al := setup(t)
	ctx := context.Background()
	sum := sha256.Sum256([]byte("scim-secret"))
	srv := httptest.NewServer(s.SCIMHandler(sum[:], "https://wantimpres26.bank.local"))
	defer srv.Close()
	scim := scimClient{t, srv, "scim-secret"}

	if code, _ := (scimClient{t, srv, "wrong"}).do("GET", "/scim/v2/Users", ""); code != 401 {
		t.Fatalf("bad SCIM token: %d", code)
	}

	// Entra ID style user create.
	code, budi := scim.do("POST", "/scim/v2/Users", `{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "Budi@BankMega.com", "externalId": "e-1", "active": true, "displayName": "Budi",
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": "SOC"}}`)
	if code != 201 || budi["id"] == "" {
		t.Fatalf("create user: %d %v", code, budi)
	}
	budiID := budi["id"].(string)
	if code, _ := scim.do("POST", "/scim/v2/Users", `{"userName": "budi@bankmega.com"}`); code != 409 {
		t.Errorf("duplicate userName (case-insensitive): %d", code)
	}
	_, ani := scim.do("POST", "/scim/v2/Users", `{"userName": "ani@bankmega.com", "active": true}`)
	aniID := ani["id"].(string)

	code, list := scim.do("GET", "/scim/v2/Users?filter="+neturl.QueryEscape(`userName eq "budi@bankmega.com"`), "")
	if code != 200 || list["totalResults"] != float64(1) {
		t.Errorf("filter: %d %v", code, list)
	}
	if code, _ := scim.do("GET", "/scim/v2/Users?filter="+neturl.QueryEscape(`title co "x"`), ""); code != 400 {
		t.Errorf("unsupported filter: %d", code)
	}

	code, grp := scim.do("POST", "/scim/v2/Groups", fmt.Sprintf(`{"displayName": "SG-WANTIMPRES26-SOC", "members": [{"value": %q}]}`, budiID))
	if code != 201 {
		t.Fatalf("create group: %d %v", code, grp)
	}
	grpID := grp["id"].(string)

	// Nobody has a role until one is bound: deny by default.
	if got := roles(t, s, "budi@bankmega.com"); len(got) != 0 {
		t.Errorf("roles before binding: %v", got)
	}
	soc, err := s.Bind(ctx, "admin1", RoleBinding{Group: "SG-WANTIMPRES26-SOC", Role: "soc_analyst"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bind(ctx, "admin1", RoleBinding{User: "ani@bankmega.com", Role: "auditor", ExpiresAt: ptr(time.Now().Add(-time.Minute))}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []RoleBinding{{User: "ani@bankmega.com", Role: "root"}, {User: "ani@bankmega.com", Role: "break_glass"},
		{User: "ani@bankmega.com", Group: "SG-WANTIMPRES26-SOC", Role: "ciso"}, {User: "ghost@bankmega.com", Role: "ciso"}} {
		if _, err := s.Bind(ctx, "admin1", bad); err == nil {
			t.Errorf("bound %+v", bad)
		}
	}
	if got := roles(t, s, "BUDI@bankmega.com"); !slices.Equal(got, []string{"soc_analyst"}) {
		t.Errorf("budi via group: %v", got)
	}
	if got := roles(t, s, "ani@bankmega.com"); len(got) != 0 {
		t.Errorf("expired time-boxed binding still active: %v", got)
	}

	// Entra PATCH: add ani to the group, then remove budi with a filter path.
	if code, _ := scim.do("PATCH", "/scim/v2/Groups/"+grpID, fmt.Sprintf(`{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "Add", "path": "members", "value": [{"value": %q}]}]}`, aniID)); code != 200 {
		t.Fatalf("patch add member: %d", code)
	}
	if got := roles(t, s, "ani@bankmega.com"); !slices.Equal(got, []string{"soc_analyst"}) {
		t.Errorf("ani after joining group: %v", got)
	}
	if code, g := scim.do("PATCH", "/scim/v2/Groups/"+grpID, fmt.Sprintf(`{"Operations": [{"op": "Remove", "path": "members[value eq \"%s\"]"}]}`, budiID)); code != 200 || len(g["members"].([]any)) != 1 {
		t.Fatalf("patch remove member: %d %v", code, g)
	}
	if got := roles(t, s, "budi@bankmega.com"); len(got) != 0 {
		t.Errorf("budi kept the role after leaving the group: %v", got)
	}

	// Deactivation (Entra sends the string "False") removes every role.
	if code, u := scim.do("PATCH", "/scim/v2/Users/"+aniID, `{"Operations": [{"op": "Replace", "path": "active", "value": "False"}]}`); code != 200 || u["active"] != false {
		t.Fatalf("deactivate: %d %v", code, u)
	}
	if got := roles(t, s, "ani@bankmega.com"); len(got) != 0 {
		t.Errorf("deactivated user still has %v", got)
	}
	// Extension attributes survive a path-less replace.
	if code, u := scim.do("PATCH", "/scim/v2/Users/"+budiID, `{"Operations": [{"op": "Replace", "value": {"displayName": "Budi S.",
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"employeeNumber": "42"}}}]}`); code != 200 ||
		u["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"].(map[string]any)["department"] != "SOC" {
		t.Errorf("path-less replace: %d %v", code, u)
	}

	if err := s.Unbind(ctx, "admin1", soc.ID); err != nil {
		t.Fatal(err)
	}
	if code, _ := scim.do("DELETE", "/scim/v2/Groups/"+grpID, ""); code != 204 {
		t.Errorf("delete group: %d", code)
	}
	if code, _ := scim.do("GET", "/scim/v2/Groups/"+grpID, ""); code != 404 {
		t.Errorf("deleted group still there: %d", code)
	}

	var got []string
	rows, _ := db.Query(ctx, "SELECT actor || ':' || action || ':' || target::text FROM audit.audit_log ORDER BY seq")
	for rows.Next() {
		var line string
		_ = rows.Scan(&line)
		got = append(got, line)
	}
	wantPrefixes := []string{
		"scim:identity.user.create", "scim:identity.user.create", "scim:identity.group.create",
		"admin1:identity.role.bind", "admin1:identity.role.bind",
		"scim:identity.group.update", "scim:identity.group.update", "scim:identity.user.update", "scim:identity.user.update",
		"admin1:identity.role.unbind", "scim:identity.group.delete",
	}
	if len(got) != len(wantPrefixes) {
		t.Fatalf("audit log:\n%s", strings.Join(got, "\n"))
	}
	for i, p := range wantPrefixes {
		if !strings.HasPrefix(got[i], p) {
			t.Errorf("audit[%d] = %s, want %s…", i, got[i], p)
		}
	}
	for _, needle := range []string{`"members_added": ["` + aniID, `"members_removed": ["` + budiID, `"active": false`, `"role": "soc_analyst"`} {
		if !strings.Contains(strings.Join(got, "\n"), needle) {
			t.Errorf("audit log lacks %s", needle)
		}
	}
	prevSeq, prevHash, entries, err := al.Range(ctx, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil || audit.Verify(prevSeq, prevHash, entries) != nil {
		t.Errorf("audit chain: %v", err)
	}
}

func ptr[T any](v T) *T { return &v }
