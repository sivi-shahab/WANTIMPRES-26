package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	neturl "net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/agents"
	"wantimpres26/internal/audit"
	"wantimpres26/internal/catalog"
	"wantimpres26/internal/incident"
	"wantimpres26/internal/lifecycle"
	"wantimpres26/internal/posture"
	"wantimpres26/internal/remediate"
	"wantimpres26/policy"
)

const tenant = "00000000-0000-0000-0000-000000000001"

// The library loads, every control maps somewhere, and the desk research corrected spec §14 (ticket 34).
func TestLibrary(t *testing.T) {
	lib, err := LoadLibrary(library)
	if err != nil {
		t.Fatal(err)
	}
	has := func(ctl, fw, req string) *Mapping {
		for i, m := range lib.Mappings {
			if m.Control == ctl && m.Framework == fw && m.Requirement == req {
				return &lib.Mappings[i]
			}
		}
		return nil
	}
	// Wrong cells of §14 are out, their replacements in.
	for _, gone := range [][3]string{{"CTL-AUDIT", "nist-ai-rmf", "GOVERN 4"}, {"CTL-AUDIT", "nist-ai-rmf", "MEASURE 4"}, {"CTL-RESIDENCY", "nist-ai-rmf", "GOVERN 6"}, {"CTL-MCP", "owasp-asi", "ASI07"}} {
		if has(gone[0], gone[1], gone[2]) != nil {
			t.Errorf("%v still mapped", gone)
		}
	}
	for _, in := range [][3]string{{"CTL-INCIDENT", "pojk-11-2022", "Pasal 60"}, {"CTL-RESIDENCY", "pojk-11-2022", "Pasal 35-36"}, {"CTL-RESIDENCY", "nist-ai-rmf", "GOVERN 1.1"},
		{"CTL-AUDIT", "pojk-11-2022", "Pasal 54(2)"}, {"CTL-INCIDENT", "uu-pdp", "Pasal 46"}, {"CTL-MCP", "owasp-asi", "ASI02"}} {
		if has(in[0], in[1], in[2]) == nil {
			t.Errorf("%v missing", in)
		}
	}
	for _, m := range lib.Mappings {
		if m.Research.Source == "" {
			t.Errorf("%+v without a source", m)
		}
		if m.Framework == "iso-42001" && m.Research.Verdict != "unverifiable" {
			t.Errorf("ISO 42001 cannot be verified from free sources: %+v", m)
		}
	}
	// A mapping to an unknown requirement or an unmapped control is refused.
	bad := fstest.MapFS{
		"library/frameworks/x.json": {Data: []byte(`{"id":"x","name":"X","version":"1","source":"s","requirements":[{"id":"R1","title":"t"}]}`)},
		"library/mappings.json":     {Data: []byte(`{"mappings":[{"control":"CTL-DLP","framework":"x","framework_version":"1","requirement":"R2","research":{"verdict":"supported","source":"s"}}]}`)},
	}
	if _, err := LoadLibrary(bad); err == nil {
		t.Error("unknown requirement accepted")
	}
}

type env struct {
	db  *pgxpool.Pool
	s   *Store
	src Sources
	now time.Time
	// fake source state
	rules   []map[string]any
	agents  agents.Summary
	decided float64
	chain   error
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
	name := fmt.Sprintf("compliance_test_%d", time.Now().UnixNano()%1e9)
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
	ls, err := lifecycle.Open(ctx, db, tenant, policy.Files)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agents.Open(ctx, db, tenant, ls); err != nil {
		t.Fatal(err)
	}
	if err := remediate.Open(ctx, db); err != nil {
		t.Fatal(err)
	}
	e := &env{db: db, now: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), decided: 95}
	if e.s, err = Open(ctx, db, tenant, e.now); err != nil {
		t.Fatal(err)
	}
	// The real built-in rule set: what a release carries.
	var rules struct {
		Items []map[string]any `json:"items"`
	}
	b, _ := policy.Files.ReadFile("wantimpres26/rules/data.json")
	_ = json.Unmarshal(b, &rules)
	e.rules = rules.Items
	e.src = Sources{DB: db,
		Rules: func(context.Context) (string, []map[string]any, error) { return "release-1", e.rules, nil },
		Posture: func(context.Context, time.Time) (posture.Report, error) {
			var r posture.Report
			v := e.decided
			r.Metrics = []posture.Metric{{Name: "Shadow AI apps identified and given a status (top-100 by usage)", Value: &v}}
			return r, nil
		},
		Agents:     func(context.Context) (agents.Summary, error) { return e.agents, nil },
		Incidents:  func(context.Context, time.Time, time.Time) (incident.Summary, error) { return incident.Summary{}, nil },
		AuditChain: func(context.Context, time.Time, time.Time) (int, error) { return 42, e.chain },
	}
	return e
}

func (e *env) collect(t *testing.T) map[string]ControlState {
	t.Helper()
	st, err := e.s.Collect(context.Background(), e.src, "control-plane", e.now)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]ControlState{}
	for _, c := range st {
		m[c.ID] = c
	}
	return m
}

func TestCollectAndHistory(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	st := e.collect(t)
	for id, want := range map[string]string{"CTL-INVENTORY": "pass", "CTL-DLP": "pass", "CTL-INJECTION": "pass", "CTL-AGENT": "pass", "CTL-MCP": "pass",
		"CTL-RATE": "partial", "CTL-RESIDENCY": "pass", "CTL-INCIDENT": "partial", "CTL-AUDIT": "pass", "CTL-POSTURE": "pass", "CTL-DATA": "fail"} {
		if st[id].Status != want {
			t.Errorf("%s: %s %v, want %s", id, st[id].Status, st[id].Reasons, want)
		}
	}
	// Changes show up as transitions; an unchanged hour adds evidence but no history row.
	e.now = e.now.Add(time.Hour)
	e.collect(t)
	e.now = e.now.Add(time.Hour)
	e.rules = slices.DeleteFunc(slices.Clone(e.rules), func(r map[string]any) bool { return r["id"] == "tpl.secret-to-any-ai" })
	e.agents.WithoutOwnerOrPolicy = []string{"orphan-bot"}
	e.chain = &audit.BrokenError{Seq: 7, Reason: "content does not match hash"}
	e.decided = 40
	st = e.collect(t)
	if st["CTL-DLP"].Status != "partial" || !strings.Contains(strings.Join(st["CTL-DLP"].Reasons, " "), "tpl.secret-to-any-ai") ||
		st["CTL-AGENT"].Status != "fail" || st["CTL-AUDIT"].Status != "fail" || st["CTL-INVENTORY"].Status != "fail" {
		t.Errorf("after changes: %+v", st)
	}
	e.src.Agents = func(context.Context) (agents.Summary, error) { return agents.Summary{}, errors.New("registry down") }
	e.now = e.now.Add(time.Hour)
	if st = e.collect(t); st["CTL-AGENT"].Status != "unknown" || st["CTL-AGENT"].Reasons[0] != "agent registry: registry down" {
		t.Errorf("source down: %+v", st["CTL-AGENT"])
	}
	h, _ := e.s.History(ctx, "CTL-DLP", e.now.Add(-24*time.Hour), e.now.Add(time.Hour))
	if len(h) != 2 || h[0].Status != "pass" || h[1].Status != "partial" {
		t.Errorf("DLP history %+v", h)
	}
	var evidence int
	_ = e.db.QueryRow(ctx, "SELECT count(*) FROM compliance.evidence WHERE control_id = 'CTL-DLP'").Scan(&evidence)
	if evidence != 4 {
		t.Errorf("evidence rows %d, want one per collection", evidence)
	}
	// History is append-only.
	for _, sql := range []string{"DELETE FROM compliance.control_status", "UPDATE compliance.evidence SET status = 'pass'", "DELETE FROM compliance.frameworks"} {
		if _, err := e.db.Exec(ctx, sql); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: %v", sql, err)
		}
	}
}

// AC (ticket 34): export a report for a sample audit period; a new framework version does not erase the old.
func TestExportAndVersions(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	q2 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	e.collect(t) // 1 Jul: all as configured
	e.now = q2.Add(10 * 24 * time.Hour)
	e.rules = slices.DeleteFunc(slices.Clone(e.rules), func(r map[string]any) bool { return r["id"] == "tpl.injection-high" })
	e.collect(t) // 11 Jul: injection rule disabled
	e.now = q2.Add(20 * 24 * time.Hour)
	if _, err := e.s.Attach(ctx, "dpo@bankmega.com", "CTL-INJECTION", "pass", strings.Repeat("a", 64), "AgentDojo suite report, ticket 28", e.now); err != nil {
		t.Fatal(err)
	}
	// The compliance team signs off one mapping against the official text, and rejects another.
	verify := func(ctl, fw, ver, req, status string) error {
		return e.s.Verify(ctx, "dpo@bankmega.com", Mapping{Control: ctl, Framework: fw, Version: ver, Requirement: req}, status, "UU 27/2022 Pasal 46 ayat (1)", "", e.now)
	}
	if err := verify("CTL-INCIDENT", "uu-pdp", "27/2022", "Pasal 46", "verified"); err != nil {
		t.Fatal(err)
	}
	if err := verify("CTL-RATE", "nist-ai-rmf", "1.0", "MANAGE 2", "rejected"); err != nil {
		t.Fatal(err)
	}
	if err := verify("CTL-RATE", "nist-ai-rmf", "1.0", "MANAGE 9", "verified"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown mapping: %v", err)
	}
	if err := e.s.Verify(ctx, "dpo@bankmega.com", Mapping{Control: "CTL-RATE", Framework: "nist-ai-rmf", Version: "1.0", Requirement: "MANAGE 2"}, "verified", "", "", e.now); !errors.Is(err, ErrInvalid) {
		t.Errorf("sign-off without a source: %v", err)
	}

	e.now = q2.AddDate(0, 3, 0)
	rep, err := e.s.Export(ctx, "auditor@bankmega.com", q2, q2.AddDate(0, 3, 0), e.now)
	if err != nil {
		t.Fatal(err)
	}
	ctl := map[string]ReportControl{}
	for _, c := range rep.Controls {
		ctl[c.ID] = c
	}
	inj := ctl["CTL-INJECTION"]
	if inj.StatusAtStart != "pass" || inj.StatusAtEnd != "partial" || len(inj.Transitions) != 2 || inj.Evidence.Automatic != 2 || len(inj.Attachments) != 1 {
		t.Errorf("injection over the period: %+v", inj)
	}
	var uupdp ReportFramework
	for _, f := range rep.Frameworks {
		if f.Framework == "uu-pdp" {
			uupdp = f
		}
	}
	if uupdp.Version != "27/2022" || !strings.HasPrefix(uupdp.VerifiedShare, "1/") {
		t.Errorf("uu-pdp: %+v", uupdp)
	}
	sha := rep.SHA256
	rep.SHA256 = ""
	if canonicalSHA(rep) != sha || len(sha) != 64 {
		t.Error("report hash does not match its content")
	}
	csvb, _ := rep.CSV()
	if lines := strings.Split(strings.TrimSpace(string(csvb)), "\n"); len(lines) < 60 || !strings.Contains(string(csvb), "uu-pdp,27/2022,Pasal 46") || !strings.Contains(string(csvb), ",verified,dpo@bankmega.com,") {
		t.Errorf("csv: %d lines\n%s", len(lines), csvb[:min(len(csvb), 600)])
	}

	// A new UU PDP library version (here: a requirement re-titled, one dropped) is a new row next to the old.
	e.now = q2.AddDate(0, 4, 0)
	lib, _ := LoadLibrary(library)
	for i, f := range lib.Frameworks {
		if f.ID == "uu-pdp" {
			f.Version = "27/2022-r2"
			f.Requirements = slices.DeleteFunc(slices.Clone(f.Requirements), func(r Requirement) bool { return r.ID == "Pasal 36" })
			lib.Frameworks[i] = f
		}
	}
	var mm []Mapping
	for _, m := range lib.Mappings {
		if m.Framework == "uu-pdp" && m.Requirement != "Pasal 36" {
			m.Version = "27/2022-r2"
			mm = append(mm, m)
		}
	}
	lib.Mappings = mm
	if err := e.s.Import(ctx, lib, e.now); err != nil {
		t.Fatal(err)
	}
	// Changing a stored version's document without a new version is refused.
	lib.Frameworks[0].Name += " (edited)"
	if err := e.s.Import(ctx, lib, e.now); err == nil {
		t.Error("stored framework version rewritten")
	}
	old, _ := e.s.Mappings(ctx, "uu-pdp", "27/2022", e.now)
	if len(old) == 0 || !slices.ContainsFunc(old, func(m MappingState) bool { return m.Requirement == "Pasal 36" }) ||
		!slices.ContainsFunc(old, func(m MappingState) bool { return m.Verification != nil && m.Verification.Status == "verified" }) {
		t.Errorf("old version mappings or sign-off lost: %+v", old)
	}
	again, err := e.s.Export(ctx, "auditor@bankmega.com", q2, q2.AddDate(0, 3, 0), e.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range again.Frameworks {
		if f.Framework == "uu-pdp" && (f.Version != "27/2022" || f.VerifiedShare != uupdp.VerifiedShare) {
			t.Errorf("past period now reports %s %s", f.Version, f.VerifiedShare)
		}
	}
	later, _ := e.s.Export(ctx, "auditor@bankmega.com", q2.AddDate(0, 3, 0), q2.AddDate(0, 4, 0).Add(time.Hour), e.now.Add(time.Hour))
	for _, f := range later.Frameworks {
		if f.Framework == "uu-pdp" && (f.Version != "27/2022-r2" || f.VerifiedShare[0] != '0') {
			t.Errorf("new period: %s %s (sign-offs belong to the version they were made on)", f.Version, f.VerifiedShare)
		}
	}
	var exports int
	_ = e.db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_log WHERE action = 'compliance.report.export'").Scan(&exports)
	if exports != 3 {
		t.Errorf("exports audited: %d", exports)
	}
}

func TestRegister(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	owner, ojk := "budi@bankmega.com", "S-123/PB.3/2026"
	_, _ = e.db.Exec(ctx, `INSERT INTO agents.mcp_tools (server, name, hash, definition, risk, score, status, first_seen, last_seen)
		VALUES ('bank', 'send_money', 'h', '{}', 'low', 0, 'approved', now(), now())`)
	_, _ = e.db.Exec(ctx, "INSERT INTO data.containers (source_id, container_id, name, kind) VALUES ('claude', 'claude', 'Claude Enterprise', 'claude_enterprise')")
	src := RegisterSources{
		Apps: func(context.Context) ([]catalog.View, error) {
			v := catalog.View{Sanction: "sanctioned", Owner: &owner}
			v.ID, v.Name, v.Vendor, v.HostingRegion, v.OJKApprovalRef = "copilot", "Microsoft Copilot", "Microsoft", "SG", &ojk
			return []catalog.View{v}, nil
		},
		Agents: func(context.Context) ([]agents.Agent, error) {
			return []agents.Agent{{ID: "invoice-bot", Name: "Invoice bot", Owner: &owner, BusinessUnit: "finance", Purpose: "reconcile", RiskTier: "high", Status: "active"}}, nil
		},
	}
	es, err := e.s.Register(ctx, src, e.now)
	if err != nil || len(es) != 4 {
		t.Fatalf("register %+v %v", es, err)
	}
	kinds := []string{}
	for _, x := range es {
		kinds = append(kinds, x.Kind)
	}
	if !slices.Equal(kinds, []string{"ai_app", "agent", "mcp_tool", "enterprise_ai"}) || es[0].OJKRef != ojk || es[1].Owner != owner {
		t.Errorf("entries %+v", es)
	}
	b, _ := RegisterCSV(es)
	if !strings.Contains(string(b), "ai_app,copilot,Microsoft Copilot,Microsoft,budi@bankmega.com,,,,sanctioned,SG,S-123/PB.3/2026") {
		t.Errorf("csv:\n%s", b)
	}
}
