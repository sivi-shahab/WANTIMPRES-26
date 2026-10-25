package incident

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	"wantimpres26/internal/authz"
	"wantimpres26/internal/authz/authztest"
	"wantimpres26/internal/events"
)

// Ticket 45: unmask is limited to analysts whose unit/region/clearance cover the incident, restricted evidence needs
// a second analyst, and every refusal is audited.
func TestUnmaskABACAndFourEyes(t *testing.T) {
	s, _, db := setup(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Second)
	clock := t0
	scoped := func(units ...string) authztest.User {
		return authztest.User{Bindings: []authz.Binding{{Role: "dpo", Attrs: authz.Attrs{BusinessUnits: units, Regions: []string{"jakarta"}}}}}
	}
	auth, _ := authztest.New(map[string]authztest.User{
		"dpo-retail": scoped("retail"), "dpo-retail2": scoped("retail"), "dpo-treasury": scoped("treasury"),
		"dpo-low": {Bindings: []authz.Binding{{Role: "dpo", Attrs: authz.Attrs{Clearance: "confidential"}}}},
	}, func() time.Time { return clock }, func(ctx context.Context, actor, action string, target map[string]any) error {
		_, err := s.audit.Append(ctx, tenant, actor, action, target)
		return err
	})
	rt := authz.NewRouter(auth)
	Routes(rt, s, func() time.Time { return clock })
	a := api{t, httptest.NewServer(rt)}
	defer a.srv.Close()
	j := "?justification=" + neturl.QueryEscape("UU PDP breach assessment INC-45")

	open := func(principal, sensitivity string) (string, string) {
		t.Helper()
		e, raw := ev(principal, t0, 80, func(e *events.Event) {
			e.PrincipalGroups, e.Sensitivity = []string{"staff", "bu:retail", "region:jakarta"}, sensitivity
		}, "PII_ID.NIK")
		id, _, err := s.Ingest(ctx, e, raw, t0)
		if err != nil {
			t.Fatal(err)
		}
		eid, err := s.AddRawEvidence(ctx, id, "prompt", []byte("NIK 3171234567890001"), t0)
		if err != nil {
			t.Fatal(err)
		}
		return id, eid
	}

	// Confidential evidence of a retail/jakarta incident: retail unmasks, treasury does not.
	id, eid := open("p1", "confidential")
	if inc, _ := s.Get(ctx, id); inc.BusinessUnit != "retail" || inc.Region != "jakarta" || inc.Sensitivity != "confidential" {
		t.Fatalf("attributes %+v", inc)
	}
	raw := "/incidents/" + id + "/evidence/" + eid + "/raw" + j
	if code, body := a.do("GET", raw, "dpo-treasury", ""); code != 403 || !strings.Contains(body, "outside the caller's scope") {
		t.Errorf("other unit: %d %s", code, body)
	}
	if code, body := a.do("GET", raw, "dpo-retail", ""); code != 200 || body != "NIK 3171234567890001" {
		t.Errorf("same unit: %d %s", code, body)
	}

	// Restricted: refused without an approval, the requester cannot approve, nor can someone outside the unit.
	id, eid = open("p2", "restricted")
	raw = "/incidents/" + id + "/evidence/" + eid + "/raw" + j
	if code, body := a.do("GET", raw, "dpo-retail", ""); code != 403 || !strings.Contains(body, "second analyst") {
		t.Errorf("restricted without approval: %d %s", code, body)
	}
	if code, _ := a.do("GET", raw, "dpo-low", ""); code != 403 {
		t.Errorf("clearance below restricted: %d", code)
	}
	code, body := a.do("POST", "/incidents/"+id+"/evidence/"+eid+"/unmask-requests"+j, "dpo-retail", "")
	var req UnmaskRequest
	_ = json.Unmarshal([]byte(body), &req)
	if code != 200 || req.ID == "" {
		t.Fatalf("request: %d %s", code, body)
	}
	approve := "/incidents/" + id + "/unmask-requests/" + req.ID + "/approve" + j
	if code, body := a.do("POST", approve, "dpo-retail", ""); code != 403 || !strings.Contains(body, "own unmask") {
		t.Errorf("self-approval: %d %s", code, body)
	}
	if code, _ := a.do("POST", approve, "dpo-treasury", ""); code != 403 {
		t.Errorf("approval from outside the unit: %d", code)
	}
	if code, _ := a.do("POST", approve, "dpo-retail2", ""); code != 200 {
		t.Errorf("approval: %d", code)
	}
	if code, _ := a.do("POST", approve, "dpo-retail2", ""); code != 409 {
		t.Errorf("approved twice: %d", code)
	}
	if code, _ := a.do("GET", raw, "dpo-retail2", ""); code != 403 {
		t.Errorf("the approver used the requester's approval: %d", code)
	}
	if code, body := a.do("GET", raw, "dpo-retail", ""); code != 200 || body != "NIK 3171234567890001" {
		t.Errorf("approved unmask: %d %s", code, body)
	}
	if code, _ := a.do("GET", raw, "dpo-retail", ""); code != 403 {
		t.Errorf("one approval, two unmasks: %d", code)
	}
	// An approval not used within the hour lapses.
	_, _ = a.do("POST", "/incidents/"+id+"/evidence/"+eid+"/unmask-requests"+j, "dpo-retail", "")
	reqs, _ := s.UnmaskRequests(ctx, id)
	_, _ = a.do("POST", "/incidents/"+id+"/unmask-requests/"+reqs[1].ID+"/approve"+j, "dpo-retail2", "")
	clock = t0.Add(UnmaskApprovalTTL + time.Minute)
	if code, _ := a.do("GET", raw, "dpo-retail", ""); code != 403 {
		t.Errorf("stale approval used: %d", code)
	}

	var got []string
	rows, _ := db.Query(ctx, "SELECT actor || ':' || action || ':' || coalesce(target->>'denied', '') FROM audit.audit_log WHERE action LIKE 'evidence.unmask%' ORDER BY seq")
	for rows.Next() {
		var x string
		_ = rows.Scan(&x)
		got = append(got, strings.SplitN(x, " (", 2)[0])
	}
	want := []string{
		"dpo-treasury:evidence.unmask.denied:incident outside the caller's scope",
		"dpo-retail:evidence.unmask:",
		"dpo-retail:evidence.unmask.denied:restricted evidence needs an approved request from a second analyst",
		"dpo-low:evidence.unmask.denied:incident outside the caller's scope",
		"dpo-retail:evidence.unmask.request:",
		"dpo-retail:evidence.unmask.approve.denied:the requester cannot approve their own unmask",
		"dpo-treasury:evidence.unmask.approve.denied:incident outside the caller's scope",
		"dpo-retail2:evidence.unmask.approve:",
		"dpo-retail2:evidence.unmask.denied:restricted evidence needs an approved request from a second analyst",
		"dpo-retail:evidence.unmask:",
		"dpo-retail:evidence.unmask.denied:restricted evidence needs an approved request from a second analyst",
		"dpo-retail:evidence.unmask.request:",
		"dpo-retail2:evidence.unmask.approve:",
		"dpo-retail:evidence.unmask.denied:restricted evidence needs an approved request from a second analyst",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("audit:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	var approver string
	_ = db.QueryRow(ctx, "SELECT target->>'approver' FROM audit.audit_log WHERE action = 'evidence.unmask' ORDER BY seq DESC LIMIT 1").Scan(&approver)
	if approver != "dpo-retail2" {
		t.Errorf("granted restricted unmask names approver %q", approver)
	}
}

// Ticket 45 AC: the volume gauges the alerts read, from granted unmasks only.
func TestUnmaskVolumeMetric(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	now := time.Now().UTC()
	c := authz.Caller{Username: "soc-x", Bindings: []authz.Binding{{Role: "dpo"}}}
	evidence := func(principal string) (string, string) {
		e, raw := ev(principal, now, 60, func(e *events.Event) { e.Sensitivity = "confidential" }, "PII_ID.NIK")
		id, _, _ := s.Ingest(ctx, e, raw, now)
		eid, _ := s.AddRawEvidence(ctx, id, "prompt", []byte("x"), now)
		return id, eid
	}
	// Six unmasks about one person across six incidents, two about others; one refused (short justification).
	for i := range 6 {
		id, eid := evidence("same-person")
		if _, err := s.Unmask(ctx, c, id, eid, fmt.Sprintf("lookup number %d", i), now); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"p-a", "p-b"} {
		id, eid := evidence(p)
		_, _ = s.Unmask(ctx, c, id, eid, "routine triage check", now)
	}
	id, eid := evidence("p-c")
	if _, err := s.Unmask(ctx, c, id, eid, "x", now); err == nil {
		t.Fatal("short justification unmasked")
	}
	vols, err := s.UnmaskVolumes(ctx, now.Add(-24*time.Hour))
	if err != nil || len(vols) != 1 || vols[0] != (UnmaskVolume{Analyst: "soc-x", Unmasks: 8, SamePrincipal: 6}) {
		t.Fatalf("volumes %+v %v", vols, err)
	}
	if v, _ := s.UnmaskVolumes(ctx, now.Add(time.Minute)); len(v) != 0 {
		t.Errorf("outside the window: %+v", v)
	}
	var buf bytes.Buffer
	WriteUnmaskMetrics(&buf, append(vols, UnmaskVolume{Analyst: `odd"name`, Unmasks: 1}))
	for _, want := range []string{`evidence_unmasks_24h{analyst="soc-x"} 8`, `evidence_unmask_same_principal_24h{analyst="soc-x"} 6`, `analyst="odd\"name"`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("metrics lack %s:\n%s", want, buf.String())
		}
	}

	// The alerts read exactly these gauges, and these values trip them.
	raw, err := os.ReadFile("../../deploy/cluster/alerts.yaml")
	if err != nil {
		t.Fatal(err)
	}
	exprs := map[string]string{}
	for _, doc := range strings.Split(string(raw), "\n---\n") {
		var rule struct {
			Spec struct {
				Groups []struct {
					Rules []struct{ Alert, Expr string }
				}
			}
		}
		if err := yaml.Unmarshal([]byte(doc), &rule); err != nil {
			t.Fatal(err)
		}
		for _, g := range rule.Spec.Groups {
			for _, r := range g.Rules {
				exprs[r.Alert] = r.Expr
			}
		}
	}
	if exprs["UnmaskVolumeHigh"] != "max by (analyst) (evidence_unmasks_24h) > 20" ||
		exprs["UnmaskSamePrincipalRepeated"] != "max by (analyst) (evidence_unmask_same_principal_24h) >= 5" {
		t.Errorf("alert exprs %q / %q", exprs["UnmaskVolumeHigh"], exprs["UnmaskSamePrincipalRepeated"])
	}
	if vols[0].SamePrincipal < 5 {
		t.Error("scenario does not reach the alert threshold")
	}
}
