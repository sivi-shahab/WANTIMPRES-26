package main

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/agents"
	"wantimpres26/internal/authz"
	"wantimpres26/internal/catalog"
	"wantimpres26/internal/compliance"
	"wantimpres26/internal/datascan"
	"wantimpres26/internal/identity"
	"wantimpres26/internal/incident"
	"wantimpres26/internal/lifecycle"
	"wantimpres26/internal/posture"
	"wantimpres26/internal/remediate"
	"wantimpres26/internal/riskcal"
	"wantimpres26/internal/similarity"
	"wantimpres26/internal/tuning"
)

// deps are the handlers and stores routes need. Nil stores are fine for the route matrix test: it never calls a
// handler, only the router's authentication and authorization.
type deps struct {
	scim, metrics     http.Handler
	mcpGateway        http.Handler // MCP gateway: tools/list reports, approval requests and claims (own token)
	incidents         *incident.Store
	identity          *identity.Store
	policies          *lifecycle.Store
	simulator         *lifecycle.Simulator
	apps              *catalog.Store
	feedKey           []byte
	posture           posture.Sources
	agents            *agents.Store
	data              *pgxpool.Pool // data-at-rest findings (ticket 31)
	remediations      *remediate.Store
	compliance        *compliance.Store
	complianceSources compliance.Sources
	register          compliance.RegisterSources
	corpus            *similarity.Store // registered confidential documents (ticket 37)
	tuning            *tuning.Store     // per-tenant detector tuning (ticket 38)
	risk              *riskcal.Store    // risk weight calibration (ticket 25)
}

// workloadRoutes are for other workloads only, on the mTLS listener (ticket 40): the signed bundle (ticket 11) for
// the OPA sidecars' identities in MTLS_ALLOW. Not on the admin API: the bundle's data (catalog, agent registry,
// exceptions) is not for anyone on the network.
func workloadRoutes(bundles http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("GET /bundles/wantimpres26.tar.gz", bundles)
	return mux
}

// routes is the complete admin API. Everything not listed as Public needs a permission (deny by default);
// routes_test.go checks every route against every role.
func routes(rt *authz.Router, d deps) {
	// GET /healthz is added by server.Run.
	rt.Public("GET /metrics", d.metrics)
	for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		rt.Public(m+" /scim/v2/", d.scim) // IdP provisioning client, own bearer token
	}
	for _, p := range []string{"/mcp/tools/observed", "/mcp/approvals/request", "/mcp/approvals/claim"} {
		rt.Public("POST "+p, d.mcpGateway) // MCP gateway, own bearer token (tickets 29, 30)
	}
	incident.Routes(rt, d.incidents, time.Now)
	identity.Routes(rt, d.identity)
	lifecycle.Routes(rt, d.policies, d.simulator, time.Now)
	catalog.Routes(rt, d.apps, d.feedKey, time.Now)
	posture.Routes(rt, d.posture, time.Now)
	agents.Routes(rt, d.agents, time.Now)
	datascan.Routes(rt, d.data)
	remediate.Routes(rt, d.remediations, time.Now)
	compliance.Routes(rt, d.compliance, d.complianceSources, d.register, time.Now)
	similarity.Routes(rt, d.corpus, time.Now)
	tuning.Routes(rt, d.tuning, time.Now)
	riskcal.Routes(rt, d.risk, time.Now)
}
