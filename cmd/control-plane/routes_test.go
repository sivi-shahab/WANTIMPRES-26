package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"sort"
	"testing"
	"time"

	"wantimpres26/internal/authz"
	"wantimpres26/internal/authz/authztest"
)

var noop = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

// Ticket 06: every role against every endpoint of the real route table. A role reaches a route exactly when one
// of its permissions is the route's; everyone else is refused (deny by default).
func TestRouteMatrix(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC) }
	users := map[string]authztest.User{"nobody": {}}
	for role := range authz.Roles {
		users[role] = authztest.Role(role)
	}
	users["break_glass"] = authztest.User{BreakGlass: true}
	a, _ := authztest.New(users, now, nil)
	rt := authz.NewRouter(a)
	routes(rt, deps{scim: noop, metrics: noop, mcpGateway: noop})

	// The unauthenticated surface is pinned: adding to it must be a deliberate change here.
	var public []string
	for _, r := range rt.Routes() {
		if r.Perm == "" {
			public = append(public, r.Method+" "+r.Pattern)
		}
	}
	sort.Strings(public)
	wantPublic := []string{"DELETE /scim/v2/", "GET /metrics", "GET /scim/v2/",
		"PATCH /scim/v2/", "POST /mcp/approvals/claim", "POST /mcp/approvals/request", "POST /mcp/tools/observed",
		"POST /scim/v2/", "PUT /scim/v2/"}
	if !slices.Equal(public, wantPublic) {
		t.Errorf("public routes = %v, want %v", public, wantPublic)
	}

	placeholder := regexp.MustCompile(`\{[^}]+\}`)
	roles := append(slices.Sorted(func(yield func(string) bool) {
		for r := range authz.Roles {
			if !yield(r) {
				return
			}
		}
	}), "nobody")
	checked := 0
	for _, route := range rt.Routes() {
		if route.Perm == "" {
			continue
		}
		path := placeholder.ReplaceAllString(route.Pattern, "x")
		for _, role := range roles {
			req := httptest.NewRequest(route.Method, path, nil)
			req.Header.Set("Authorization", "Bearer "+role)
			req.Header.Set("X-Justification", "route matrix test, ticket 06")
			got := rt.Check(req)
			allowed := route.Perm == authz.Authenticated || slices.Contains(authz.Roles[role], route.Perm)
			if role == "nobody" {
				allowed = route.Perm == authz.Authenticated
			}
			if (got == 0) != allowed {
				t.Errorf("%s %s (%s) as %s: status %d, want allowed=%v", route.Method, route.Pattern, route.Perm, role, got, allowed)
			}
			checked++
		}
		req := httptest.NewRequest(route.Method, path, nil)
		if got := rt.Check(req); got != http.StatusUnauthorized {
			t.Errorf("%s %s without a token: %d, want 401", route.Method, route.Pattern, got)
		}
	}
	if checked < 100 {
		t.Errorf("only %d role/route pairs checked", checked)
	}
	if got := rt.Check(httptest.NewRequest("GET", "/admin/secret", nil)); got != http.StatusNotFound {
		t.Errorf("unregistered path: %d", got)
	}
}
