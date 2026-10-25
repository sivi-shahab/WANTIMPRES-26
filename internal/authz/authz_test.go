package authz_test

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"wantimpres26/internal/authz"
	"wantimpres26/internal/authz/authztest"
)

var now = time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)

func clock() time.Time { return now }

func TestCanABACAndExpiry(t *testing.T) {
	c := authz.Caller{Bindings: []authz.Binding{
		{Role: "app_owner", Attrs: authz.Attrs{BusinessUnits: []string{"retail"}, Regions: []string{"ID"}, Clearance: "confidential"}},
		{Role: "auditor", Expires: now.Add(time.Hour)},
		{Role: "dpo", Expires: now}, // expired at now
		{Role: "no_such_role"},
	}}
	cases := []struct {
		perm string
		res  authz.Resource
		want bool
	}{
		{authz.AppRead, authz.Resource{BusinessUnit: "retail", Region: "ID", Sensitivity: "internal"}, true},
		{authz.AppRead, authz.Resource{BusinessUnit: "corporate"}, false},
		{authz.AppRead, authz.Resource{Region: "SG"}, false},
		{authz.AppRead, authz.Resource{Sensitivity: "restricted"}, false},
		{authz.AppRead, authz.Resource{Sensitivity: "confidential"}, true},
		{authz.AppRead, authz.Resource{Sensitivity: "bogus"}, false},
		{authz.AuditRead, authz.Resource{}, true},       // time-boxed auditor, still valid
		{authz.EvidenceUnmask, authz.Resource{}, false}, // only via the expired dpo binding
		{authz.ConfigWrite, authz.Resource{}, false},    // nobody granted it
	}
	for _, tc := range cases {
		if got := c.Can(tc.perm, tc.res, now); got != tc.want {
			t.Errorf("Can(%s, %+v) = %v, want %v", tc.perm, tc.res, got, tc.want)
		}
	}
	if c.Can(authz.AuditRead, authz.Resource{}, now.Add(time.Hour)) {
		t.Error("auditor binding outlived its expiry")
	}
	unrestricted := authz.Attrs{BusinessUnits: []string{"*"}}
	if !unrestricted.Covers(authz.Resource{BusinessUnit: "anything", Region: "US", Sensitivity: "restricted"}) {
		t.Error("* and empty attributes should not restrict")
	}
}

func TestEveryRoleUsesKnownPermissions(t *testing.T) {
	known := []string{authz.DashboardRead, authz.IncidentRead, authz.IncidentWrite, authz.EvidenceUnmask, authz.PolicyRead,
		authz.PolicyWrite, authz.PolicyPublish, authz.ConfigRead, authz.ConfigWrite, authz.ComplianceRead, authz.ComplianceWrite,
		authz.AuditRead, authz.AppRead, authz.FeedbackWrite, authz.AgentRead, authz.AgentWrite, authz.AgentApprove, authz.AgentKillGlobal, authz.DataRemediate, authz.DataApprove,
		authz.SelfService, authz.IdentityRead, authz.IdentityAdmin, authz.BreakGlassAccess}
	for role, perms := range authz.Roles {
		for _, p := range perms {
			if !slices.Contains(known, p) {
				t.Errorf("role %s: unknown permission %q", role, p)
			}
		}
	}
	// Ticket 20: the CISO sees the dashboard and changes nothing.
	for _, p := range authz.Roles["ciso"] {
		if !strings.HasSuffix(p, ".read") {
			t.Errorf("ciso holds non-read permission %s", p)
		}
	}
	if !slices.Contains(authz.Roles["ciso"], authz.DashboardRead) {
		t.Error("ciso cannot read the dashboard")
	}
	// Separation of duties: whoever writes policy cannot publish it alone (4-eyes, ticket 12).
	for role, perms := range authz.Roles {
		if role != "break_glass" && slices.Contains(perms, authz.PolicyWrite) && slices.Contains(perms, authz.PolicyPublish) {
			t.Errorf("role %s can both write and publish policy", role)
		}
	}
}

func serve(t *testing.T, users map[string]authztest.User) (*httptest.Server, *authztest.Audit) {
	t.Helper()
	a, audit := authztest.New(users, clock, nil)
	rt := authz.NewRouter(a)
	ok := func(w http.ResponseWriter, _ *http.Request, c authz.Caller) {
		_, _ = w.Write([]byte("hello " + c.Username))
	}
	rt.Handle("GET /incidents", authz.IncidentRead, ok)
	rt.Handle("GET /raw", authz.EvidenceUnmask, ok)
	rt.Handle("GET /me", authz.Authenticated, ok)
	rt.Public("GET /metrics", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv := httptest.NewServer(rt)
	t.Cleanup(srv.Close)
	return srv, audit
}

func get(t *testing.T, srv *httptest.Server, path, token, justification string) (int, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if justification != "" {
		req.Header.Set("X-Justification", justification)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header
}

func TestAuthentication(t *testing.T) {
	srv, _ := serve(t, map[string]authztest.User{
		"soc":    authztest.Role("soc_analyst"),
		"nomfa":  {Bindings: []authz.Binding{{Role: "soc_analyst"}}, NoMFA: true},
		"nobody": {},
	})
	cases := []struct {
		path, token string
		want        int
	}{
		{"/incidents", "", 401},
		{"/incidents", "forged", 401},
		{"/incidents", "nomfa", 401}, // admin login without MFA
		{"/incidents", "nobody", 403},
		{"/incidents", "soc", 200},
		{"/me", "nobody", 200}, // authenticated, no permission needed
		{"/me", "", 401},
		{"/metrics", "", 200},
		{"/unknown", "soc", 404},
	}
	for _, tc := range cases {
		if got, _ := get(t, srv, tc.path, tc.token, ""); got != tc.want {
			t.Errorf("%s as %q: %d, want %d", tc.path, tc.token, got, tc.want)
		}
	}
	if _, h := get(t, srv, "/incidents", "nomfa", ""); !strings.Contains(h.Get("WWW-Authenticate"), "insufficient_user_authentication") {
		t.Errorf("no step-up challenge: %q", h.Get("WWW-Authenticate"))
	}
}

// Sensitive permissions: fresh login + justification, and every attempt audited.
func TestSensitivePermission(t *testing.T) {
	srv, audit := serve(t, map[string]authztest.User{
		"dpo":   authztest.Role("dpo"),
		"stale": {Bindings: []authz.Binding{{Role: "dpo"}}, LoginAge: 6 * time.Minute},
		"soc":   authztest.Role("soc_analyst"),
	})
	const why = "UU PDP breach assessment INC-7"
	cases := []struct {
		token, justification string
		want                 int
		stepUp               bool
	}{
		{"soc", why, 403, false},  // no permission
		{"stale", why, 401, true}, // login older than 5 min
		{"dpo", "", 403, false},
		{"dpo", "because", 403, false}, // too short
		{"dpo", why, 200, false},
	}
	for _, tc := range cases {
		got, h := get(t, srv, "/raw", tc.token, tc.justification)
		if got != tc.want || strings.Contains(h.Get("WWW-Authenticate"), "insufficient_user_authentication") != tc.stepUp {
			t.Errorf("%s/%q: %d %q, want %d step-up=%v", tc.token, tc.justification, got, h.Get("WWW-Authenticate"), tc.want, tc.stepUp)
		}
	}
	want := []string{"soc:access.sensitive.denied", "stale:access.sensitive.denied", "dpo:access.sensitive.denied",
		"dpo:access.sensitive.denied", "dpo:access.sensitive"}
	if got := audit.Actions(); !slices.Equal(got, want) {
		t.Errorf("audit = %v, want %v", got, want)
	}
	audit.Fail = true
	if got, _ := get(t, srv, "/raw", "dpo", why); got != 500 {
		t.Errorf("sensitive access without an audit record: %d, want 500", got)
	}
}

func TestBreakGlass(t *testing.T) {
	srv, audit := serve(t, map[string]authztest.User{"bg": {BreakGlass: true}})
	if got, _ := get(t, srv, "/incidents", "bg", ""); got != 200 {
		t.Fatalf("break-glass read: %d", got)
	}
	if got, _ := get(t, srv, "/raw", "bg", "IdP down, containing INC-9"); got != 403 {
		t.Errorf("break-glass must not unmask evidence: %d", got)
	}
	if got := audit.Actions(); len(got) != 3 || got[0] != "bg:breakglass.request" || got[1] != "bg:breakglass.request" {
		t.Errorf("break-glass requests not all audited: %v", got)
	}
	audit.Fail = true
	if got, _ := get(t, srv, "/incidents", "bg", ""); got != 500 {
		t.Errorf("break-glass without audit: %d, want 500", got)
	}
}

func TestRoutesNeedAPermission(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Handle accepted a route without a permission")
		}
	}()
	a, _ := authztest.New(nil, clock, nil)
	authz.NewRouter(a).Handle("GET /x", "", func(http.ResponseWriter, *http.Request, authz.Caller) {})
}
