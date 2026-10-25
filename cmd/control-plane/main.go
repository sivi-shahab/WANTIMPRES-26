package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sr"

	"wantimpres26/internal/agents"
	"wantimpres26/internal/audit"
	"wantimpres26/internal/authz"
	"wantimpres26/internal/catalog"
	"wantimpres26/internal/compliance"
	"wantimpres26/internal/events"
	"wantimpres26/internal/extract"
	"wantimpres26/internal/identity"
	"wantimpres26/internal/incident"
	"wantimpres26/internal/ingest"
	"wantimpres26/internal/lifecycle"
	"wantimpres26/internal/policysvc"
	"wantimpres26/internal/posture"
	"wantimpres26/internal/privacy"
	"wantimpres26/internal/remediate"
	"wantimpres26/internal/riskcal"
	"wantimpres26/internal/server"
	"wantimpres26/internal/similarity"
	"wantimpres26/internal/tenantdb"
	"wantimpres26/internal/tuning"
	"wantimpres26/policy"
)

// Env: bundle signing (see bundleSigner), DATABASE_URL, INCIDENT_KEK_FILE (32 raw bytes), KAFKA_* (events.KafkaOpts), SCHEMA_REGISTRY_URL,
// TENANT_ID, TENANT_PEPPER (similarity fingerprints, ticket 37), TIKA_URL (optional: PDF registration), PUBLIC_URL, CATALOG_FEED_URL + CATALOG_FEED_PUBKEY_FILE (signed app catalog feed), OPENSEARCH_* (ingest.OpenSearchFromEnv; policy simulation reads stored events), and identity (ADR-0002): OIDC_ISSUER, OIDC_AUDIENCE, OIDC_MFA_ACR (comma-separated acr
// values that mean MFA), BREAK_GLASS_SUBS (comma-separated token subs), SCIM_TOKEN_SHA256 (hex),
// MCP_GATEWAY_TOKEN_SHA256 (hex; the MCP gateway reporting tools/list and asking for approvals, tickets 29-30),
// APPROVAL_TTL (Go duration, default 15m), APPROVAL_WEBHOOK_URL (chat webhook for new approval requests; optional),
// ITSM_* (incident tickets; see wireIncidents).
func main() {
	// `control-plane audit anchor|verify ...`: run by the audit-anchor CronJob or via kubectl exec.
	if len(os.Args) > 1 && os.Args[1] == "audit" {
		os.Exit(audit.Main(context.Background(), os.Args[2:], os.Stdout))
	}
	log := privacy.NewLogger("control-plane")
	fail := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithCancel(context.Background())

	// No key, no bundle: sidecars must never be offered an unsigned policy.
	signer, err := bundleSigner()
	if err != nil {
		fail("bundle signer", err)
	}

	// Incidents: Postgres (with the audit log), Kafka for decision events.
	auditLog, err := audit.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		fail("audit log", err)
	}
	// Pinned to the tenant: row level security shows this process only its tenant's rows (ticket 42).
	db, err := tenantdb.Pool(ctx, os.Getenv("DATABASE_URL"), os.Getenv("TENANT_ID"))
	if err != nil {
		fail("database", err)
	}
	kek, err := os.ReadFile(os.Getenv("INCIDENT_KEK_FILE"))
	if err != nil {
		fail("read incident KEK", err)
	}
	incidents, err := incident.Open(ctx, db, auditLog, kek)
	if err != nil {
		fail("incident store", err)
	}
	rc, err := sr.NewClient(sr.URLs(os.Getenv("SCHEMA_REGISTRY_URL")))
	if err != nil {
		fail("schema registry client", err)
	}
	go func() {
		for t := time.NewTicker(time.Hour); ctx.Err() == nil; <-t.C {
			if n, err := incidents.PurgeExpired(ctx, time.Now()); err != nil {
				log.Error("purge expired evidence", "err", err)
			} else if n > 0 {
				log.Info("purged expired raw evidence", "count", n)
			}
		}
	}()

	// Policy lifecycle: releases from Postgres become the signed bundle on every replica.
	policies, err := lifecycle.Open(ctx, db, os.Getenv("TENANT_ID"), policy.Files)
	if err != nil {
		fail("policy store", err)
	}
	// Risk weight calibration (ticket 25): the active version rides in every policy release, so it registers before
	// any module that cuts releases (catalog seed, agent registry) runs.
	riskWeights := &riskcal.Store{DB: db, Tenant: os.Getenv("TENANT_ID"), Policies: policies, FS: policy.Files}
	if err := riskcal.Open(ctx, riskWeights); err != nil {
		fail("riskcal schema", err)
	}
	// Containment blocks ride in every release too (ticket 26).
	policies.AddExtra(incident.ContainmentDoc(os.Getenv("TENANT_ID")))
	incidents.Release = policies.CutRelease
	// The app catalog joins every release (ticket 16): open it before the first bundle is built.
	var feedKey []byte
	if f := os.Getenv("CATALOG_FEED_PUBKEY_FILE"); f != "" {
		if feedKey, err = os.ReadFile(f); err != nil {
			fail("catalog feed key", err)
		}
	}
	apps, err := catalog.Open(ctx, db, os.Getenv("TENANT_ID"), policies)
	if err != nil {
		fail("app catalog", err)
	}
	if err := remediate.Open(ctx, db); err != nil { // includes the data scan store
		fail("data scan store", err)
	}
	registry, err := agents.Open(ctx, db, os.Getenv("TENANT_ID"), policies)
	if err != nil {
		fail("agent registry", err)
	}
	if v := os.Getenv("APPROVAL_TTL"); v != "" {
		if registry.ApprovalTTL, err = time.ParseDuration(v); err != nil || registry.ApprovalTTL <= 0 {
			fail("APPROVAL_TTL", fmt.Errorf("positive Go duration: %q", v))
		}
	}
	if url := os.Getenv("APPROVAL_WEBHOOK_URL"); url != "" {
		registry.Notify = agents.WebhookNotifier(url, os.Getenv("PUBLIC_URL"), &http.Client{Timeout: 10 * time.Second}, log)
	}
	bundles := &policysvc.Server{}
	releaser := &lifecycle.Releaser{Store: policies, Server: bundles, FS: policy.Files, Signer: signer, Log: log, Poll: 15 * time.Second}
	if err := releaser.Sync(ctx); err != nil {
		fail("build policy bundle", err)
	}
	go releaser.Run(ctx)
	corpus, err := lifecycle.LoadCorpus(policy.Files)
	if err != nil {
		fail("simulation corpus", err)
	}
	search, err := ingest.OpenSearchFromEnv(os.Getenv, time.Minute)
	if err != nil {
		fail("opensearch config", err)
	}
	simulator := &lifecycle.Simulator{Store: policies, Source: search.Events, Corpus: corpus, MaxEvents: 100_000, Log: log}
	go func() {
		for t := time.NewTicker(time.Hour); ctx.Err() == nil; <-t.C {
			if n, err := registry.Reconcile(ctx); err != nil {
				log.Error("agent owner reconcile", "err", err)
			} else if n > 0 {
				log.Info("agents quarantined: no active owner", "count", n)
			}
			if err := apps.PurgeUsage(ctx, time.Now()); err != nil {
				log.Error("purge app usage", "err", err)
			}
			if url := os.Getenv("CATALOG_FEED_URL"); url != "" {
				if v, err := apps.PullFeed(ctx, &http.Client{Timeout: time.Minute}, url, feedKey); err != nil {
					log.Error("catalog feed pull", "err", err)
				} else if v > 0 {
					log.Info("catalog feed imported", "version", v)
				}
			}
			if expired, notified, err := policies.Sweep(ctx, time.Now()); err != nil {
				log.Error("exception sweep", "err", err)
			} else if expired+notified > 0 {
				log.Info("exception sweep", "expired", expired, "expiry_notices", notified)
			}
		}
	}()

	ids, err := identity.Open(ctx, db, os.Getenv("TENANT_ID"))
	if err != nil {
		fail("identity store", err)
	}
	verify, err := authz.KeycloakVerifier(ctx, os.Getenv("OIDC_ISSUER"), os.Getenv("OIDC_AUDIENCE"))
	if err != nil {
		fail("oidc issuer", err)
	}
	scimHash, err := hex.DecodeString(os.Getenv("SCIM_TOKEN_SHA256"))
	if err != nil || len(scimHash) != sha256.Size {
		fail("SCIM_TOKEN_SHA256 must be a hex SHA-256", err)
	}
	mcpHash, err := hex.DecodeString(os.Getenv("MCP_GATEWAY_TOKEN_SHA256"))
	if err != nil || len(mcpHash) != sha256.Size {
		fail("MCP_GATEWAY_TOKEN_SHA256 must be a hex SHA-256", err)
	}
	breakGlass := map[string]bool{}
	for _, sub := range strings.Split(os.Getenv("BREAK_GLASS_SUBS"), ",") {
		if sub = strings.TrimSpace(sub); sub != "" {
			breakGlass[sub] = true
		}
	}
	var breakGlassRequests atomic.Int64
	rt := authz.NewRouter(&authz.Authenticator{
		Verify:     verify,
		MFAACR:     strings.Split(os.Getenv("OIDC_MFA_ACR"), ","),
		BreakGlass: breakGlass,
		Bindings:   ids.Bindings,
		Audit: func(ctx context.Context, actor, action string, target map[string]any) error {
			if action == "breakglass.request" {
				breakGlassRequests.Add(1)
			}
			_, err := auditLog.Append(ctx, os.Getenv("TENANT_ID"), actor, action, target)
			return err
		},
		StepUpAge: 5 * time.Minute,
		Now:       time.Now,
	})
	metrics := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := incidents.Overdue(r.Context(), time.Now())
		if err != nil {
			http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
			return
		}
		// Prometheus text format, not HTML: the semgrep XSS rule on the writes below does not apply.
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = fmt.Fprintf(w, "# TYPE incident_ack_overdue gauge\nincident_ack_overdue %d\n", n)                                     // nosemgrep: no-fprintf-to-responsewriter
		_, _ = fmt.Fprintf(w, "# TYPE breakglass_requests_total counter\nbreakglass_requests_total %d\n", breakGlassRequests.Load()) // nosemgrep: no-fprintf-to-responsewriter
		_, _ = fmt.Fprintf(w, "# TYPE policy_release_current gauge\npolicy_release_current %d\n", releaser.Current())                // nosemgrep: no-fprintf-to-responsewriter
		// FR-INC-6: alert on breach_timer_remaining_hours < 24 (the sweep also escalates and notifies the SIEM/SOAR).
		if running, least, err := incidents.BreachTimers(r.Context(), time.Now()); err == nil {
			_, _ = fmt.Fprintf(w, "# TYPE breach_timers_running gauge\nbreach_timers_running %d\n", running) // nosemgrep: no-fprintf-to-responsewriter
			if least != nil {
				_, _ = fmt.Fprintf(w, "# TYPE breach_timer_remaining_hours gauge\nbreach_timer_remaining_hours %g\n", *least) // nosemgrep: no-fprintf-to-responsewriter
			}
		}
		// Ticket 45: unmask volume per analyst (alerts UnmaskVolumeHigh, UnmaskSamePrincipalRepeated).
		if vols, err := incidents.UnmaskVolumes(r.Context(), time.Now().Add(-24*time.Hour)); err == nil {
			incident.WriteUnmaskMetrics(w, vols)
		}
		if n, err := policies.ExpiringSoon(r.Context(), time.Now()); err == nil {
			_, _ = fmt.Fprintf(w, "# TYPE policy_exceptions_expiring gauge\npolicy_exceptions_expiring %d\n", n) // nosemgrep: no-fprintf-to-responsewriter
		}
	})
	// One consumer group feeds every control-plane module that learns from decision events.
	kafka, err := events.KafkaOpts(os.Getenv)
	if err != nil {
		fail("kafka config", err)
	}
	kc, err := kgo.NewClient(append(kafka, kgo.ConsumerGroup(consumerGroup), kgo.ConsumeTopics(events.Topic), kgo.DisableAutoCommit())...)
	if err != nil {
		fail("kafka client", err)
	}
	go func() {
		if err := events.Consume(ctx, kc, &events.Decoder{SR: rc}, log,
			events.OnlyTenant(os.Getenv("TENANT_ID"), incidents.Handle, apps.Handle, registry.Handle)...); err != nil {
			fail("decision event consumer stopped", err)
		}
	}()

	// Compliance (ticket 34): evidence from the running platform, collected hourly and on demand.
	postureSrc := posture.Sources{Search: search.Search, Apps: apps, Incidents: incidents, Policies: policies, Agents: registry}
	complianceStore, err := compliance.Open(ctx, db, os.Getenv("TENANT_ID"), time.Now())
	if err != nil {
		fail("compliance store", err)
	}
	complianceSrc := compliance.Sources{DB: db, Posture: postureSrc.Compute, Agents: registry.Summarize, Incidents: incidents.Summarize,
		Rules: func(ctx context.Context) (string, []map[string]any, error) {
			rel, err := policies.Latest(ctx)
			if err != nil {
				return "", nil, err
			}
			var items []map[string]any
			raw, _ := rel.Rules["items"].([]any)
			for _, it := range raw {
				if m, ok := it.(map[string]any); ok {
					items = append(items, m)
				}
			}
			return fmt.Sprintf("release-%d", rel.Number), items, nil
		},
		AuditChain: func(ctx context.Context, from, to time.Time) (int, error) {
			prevSeq, prevHash, entries, err := auditLog.Range(ctx, from, to)
			if err != nil {
				return 0, err
			}
			return len(entries), audit.Verify(prevSeq, prevHash, entries)
		}}
	register := compliance.RegisterSources{
		Apps: func(ctx context.Context) ([]catalog.View, error) {
			vs, _, err := apps.List(ctx, catalog.ListOptions{}, time.Now())
			return vs, err
		},
		Agents: func(ctx context.Context) ([]agents.Agent, error) { return registry.List(ctx, "") },
	}
	go func() {
		for t := time.NewTicker(time.Hour); ctx.Err() == nil; <-t.C {
			if _, err := complianceStore.Collect(ctx, complianceSrc, "control-plane", time.Now()); err != nil {
				log.Error("compliance evidence", "err", err)
			}
		}
	}()
	// Registered confidential documents (ticket 37): fingerprints keyed with the tenant pepper, read by detection-svc
	// and the connector worker.
	if err := similarity.Open(ctx, db); err != nil {
		fail("similarity schema", err)
	}
	if os.Getenv("TENANT_PEPPER") == "" {
		fail("config", fmt.Errorf("TENANT_PEPPER is required"))
	}
	confidential := &similarity.Store{DB: db, Tenant: os.Getenv("TENANT_ID"), Pepper: []byte(os.Getenv("TENANT_PEPPER"))}
	if u := os.Getenv("TIKA_URL"); u != "" {
		confidential.Tika = &extract.Tika{URL: u, HTTP: &http.Client{Timeout: 2 * time.Minute}}
	}
	// Per-tenant detector tuning (ticket 38): triage labels, opt-in training, gated rollout.
	if err := tuning.Open(ctx, db); err != nil {
		fail("tuning schema", err)
	}
	tuner := &tuning.Store{DB: db, Tenant: os.Getenv("TENANT_ID"), Pepper: []byte(os.Getenv("TENANT_PEPPER"))}
	riskWeights.Source = search.Events
	remediations := &remediate.Store{DB: db, Tenant: os.Getenv("TENANT_ID")}
	if err := wireIncidents(ctx, incidents, registry, remediations, log); err != nil {
		fail("incident integrations", err)
	}
	routes(rt, deps{scim: ids.SCIMHandler(scimHash, os.Getenv("PUBLIC_URL")), metrics: metrics, mcpGateway: registry.GatewayHandler(mcpHash, time.Now), incidents: incidents, identity: ids,
		policies: policies, simulator: simulator, apps: apps, feedKey: feedKey,
		posture: postureSrc, compliance: complianceStore, complianceSources: complianceSrc, register: register,
		agents: registry, data: db, remediations: remediations, corpus: confidential, tuning: tuner, risk: riskWeights})
	server.RunMTLS("control-plane", rt.Mux, workloadRoutes(bundles))
	cancel()
	kc.Close()
}

// consumerGroup is the control-plane's group on the decision event topic (incidents, app usage, shadow agents).
const consumerGroup = "control-plane"
