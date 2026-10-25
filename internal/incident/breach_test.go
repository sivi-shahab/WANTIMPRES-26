package incident

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"

	"wantimpres26/internal/authz"
	"wantimpres26/internal/authz/authztest"
	"wantimpres26/internal/events"
	"wantimpres26/internal/lifecycle"
	"wantimpres26/internal/policysvc"
	"wantimpres26/policy"
)

// ev is event() with changes: action, trace, …
func ev(principal string, at time.Time, risk int, mut func(*events.Event), classes ...string) (events.Event, []byte) {
	e, _ := event(principal, at, risk, classes...)
	if mut != nil {
		mut(&e)
	}
	raw, _ := json.Marshal(e)
	return e, raw
}

func allowed(e *events.Event) { e.Action = "allow" }

func apiFor(t *testing.T, s *Store, now func() time.Time) api {
	t.Helper()
	auth, _ := authztest.New(map[string]authztest.User{
		"soc1": authztest.Role("soc_analyst"), "ciso1": authztest.Role("ciso"), "dpo1": authztest.Role("dpo"),
	}, now, func(ctx context.Context, actor, action string, target map[string]any) error {
		_, err := s.audit.Append(ctx, tenant, actor, action, target)
		return err
	})
	rt := authz.NewRouter(auth)
	Routes(rt, s, now)
	a := api{t, httptest.NewServer(rt)}
	t.Cleanup(a.srv.Close)
	return a
}

// FR-INC-1 chain: one trace (an agent session) is one incident whatever the keys of its events; without a trace,
// or a trace gone quiet for longer than the window, the dedup key decides.
func TestTraceChain(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	trace := strings.Repeat("c", 32)
	in := func(principal string, at time.Time, tr string, classes ...string) string {
		t.Helper()
		e, raw := ev(principal, at, 60, func(e *events.Event) { e.TraceID = tr }, classes...)
		id, _, err := s.Ingest(ctx, e, raw, at)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	a := in("agent-1", t0, trace, "SECRET.AWS_KEY")
	if b := in("agent-1", t0.Add(2*time.Minute), trace, "PII_ID.NIK"); b != a {
		t.Error("tool call of the same session opened another incident")
	}
	if c := in("agent-2", t0.Add(3*time.Minute), trace, "PCI.PAN"); c != a {
		t.Error("another key in the same trace opened another incident")
	}
	if d := in("agent-1", t0.Add(3*time.Minute), strings.Repeat("d", 32), "PCI.PAN"); d == a {
		t.Error("another trace joined the chain")
	}
	if z := in("agent-9", t0, strings.Repeat("0", 32), "PCI.PAN"); z == a || in("agent-8", t0, strings.Repeat("0", 32), "PCI.PAN") == z {
		t.Error("all-zero trace ids chained")
	}
	if late := in("agent-3", t0.Add(3*time.Minute+DedupWindow+time.Second), trace, "PCI.PAN"); late == a {
		t.Error("trace quiet for longer than the window still chained")
	}
	if inc, _ := s.Get(ctx, a); inc.EventCount != 3 {
		t.Errorf("chain has %d events, want 3", inc.EventCount)
	}
}

// Ticket 26 AC: the timer starts when personal data got out; a draft report is there right away (well within
// 24 h of detection); less than 24 h left escalates once; the DPO closes it.
func TestBreachWorkflow(t *testing.T) {
	s, _, db := setup(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	clock := t0
	a := apiFor(t, s, func() time.Time { return clock })

	// Blocked, redacted, or not personal data: no timer.
	for _, mut := range []func(*events.Event){nil, func(e *events.Event) { e.Action = "redact" }} {
		e, raw := ev("p1", t0, 60, mut, "PII_ID.NIK")
		id, _, _ := s.Ingest(ctx, e, raw, t0)
		if inc, _ := s.Get(ctx, id); inc.Breach != nil {
			t.Errorf("%s event started a breach timer", e.Action)
		}
	}
	e, raw := ev("p1", t0, 60, allowed, "SECRET.AWS_KEY")
	id, _, _ := s.Ingest(ctx, e, raw, t0)
	if inc, _ := s.Get(ctx, id); inc.Breach != nil {
		t.Error("a leaked secret is not a personal data breach")
	}
	if code, _ := a.do("GET", "/incidents/"+id+"/breach/report", "dpo1", ""); code != 409 {
		t.Errorf("report without a timer: %d", code)
	}

	// Allowed NIK and card number to ChatGPT, in one session: the timer starts at detection, severity at least high.
	trace := strings.Repeat("e", 32)
	e1, raw1 := ev("p2", t0, 55, func(e *events.Event) {
		allowed(e)
		e.TraceID = trace
		e.Classes[0].Count = 3
		e.Sensitivity = "confidential"
	}, "PII_ID.NIK")
	id, _, _ = s.Ingest(ctx, e1, raw1, t0)
	e2, raw2 := ev("p2", t0.Add(5*time.Minute), 55, func(e *events.Event) { allowed(e); e.TraceID = trace }, "PCI.PAN", "SECRET.JWT")
	_, _, _ = s.Ingest(ctx, e2, raw2, t0.Add(5*time.Minute))
	e3, raw3 := ev("p2", t0.Add(6*time.Minute), 55, func(e *events.Event) { e.TraceID = trace }, "PII_ID.NIK") // blocked
	_, _, _ = s.Ingest(ctx, e3, raw3, t0.Add(6*time.Minute))
	inc, _ := s.Get(ctx, id)
	if inc.Breach == nil || !inc.Breach.StartedAt.Equal(t0) || !inc.Breach.Deadline.Equal(t0.Add(72*time.Hour)) || inc.Breach.Basis != "auto" || inc.Severity != "high" {
		t.Fatalf("breach %+v severity %s", inc.Breach, inc.Severity)
	}

	// Handling before the draft: triage and a containment block (no release wired: refused, not recorded).
	clock = t0.Add(20 * time.Minute)
	_, _ = s.Transition(ctx, id, Triaged, "", "soc1", clock)
	if code, _ := a.do("POST", "/incidents/"+id+"/actions", "soc1", `{"action": "block_access"}`); code != 400 {
		t.Errorf("block without releases: %d", code)
	}

	clock = t0.Add(90 * time.Minute)
	code, body := a.do("GET", "/incidents/"+id+"/breach/report", "dpo1", "")
	var r BreachReport
	_ = json.Unmarshal([]byte(body), &r)
	if code != 200 || len(r.PersonalData) != 2 || r.PersonalData[0] != (Exposure{Class: "PCI.PAN", Specific: true, Values: 1, Events: 1}) ||
		r.PersonalData[1] != (Exposure{Class: "PII_ID.NIK", Values: 3, Events: 1}) || r.Subjects.UpperBound != 4 || r.Subjects.Determinable ||
		len(r.Timeline) != 3 || r.Principals != 1 || fmt.Sprint(r.Destinations) != "[chatgpt]" || r.HoursLeft != 70.5 ||
		len(r.Handling) != 1 || !strings.Contains(r.Handling[0].What, "New -> Triaged") || r.Timer.DraftedAt == nil {
		t.Fatalf("report %d %s", code, body)
	}
	code, md := a.do("GET", "/incidents/"+id+"/breach/report?format=md", "ciso1", "")
	for _, want := range []string{"## a. Data pribadi yang terungkap", "| PCI.PAN | spesifik | 1 | 1 |", "## b. Kapan", "## c. Upaya penanganan", "2026-10-06 16:00 WIB"} {
		if code != 200 || !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}
	// The first draft is the metric: hours from detection, audited once.
	var drafts int
	var since float64
	_ = db.QueryRow(ctx, "SELECT count(*), max((target->>'hours_since_detection')::float8) FROM audit.audit_log WHERE action = 'incident.breach.draft'").Scan(&drafts, &since)
	if drafts != 1 || since > 24 {
		t.Errorf("drafts audited %d, %.1f h after detection", drafts, since)
	}

	// Escalation: nothing with more than 24 h left; once below, critical and audited; once only.
	if n, _ := s.SweepBreaches(ctx, t0.Add(47*time.Hour)); n != 0 {
		t.Errorf("escalated with 25 h left: %d", n)
	}
	if n, _ := s.SweepBreaches(ctx, t0.Add(49*time.Hour)); n != 1 {
		t.Errorf("not escalated with 23 h left: %d", n)
	}
	if n, _ := s.SweepBreaches(ctx, t0.Add(50*time.Hour)); n != 0 {
		t.Errorf("escalated twice: %d", n)
	}
	inc, _ = s.Get(ctx, id)
	var left float64
	_ = db.QueryRow(ctx, "SELECT (target->>'remaining_hours')::float8 FROM audit.audit_log WHERE action = 'incident.breach.escalate'").Scan(&left)
	if inc.Severity != "critical" || inc.Breach.EscalatedAt == nil || left != 23 {
		t.Errorf("after escalation: severity %s breach %+v remaining %v", inc.Severity, inc.Breach, left)
	}
	if running, least, _ := s.BreachTimers(ctx, t0.Add(49*time.Hour)); running != 1 || least == nil || *least != 23 {
		t.Errorf("metric: %d %v", running, least)
	}

	// Closing: DPO only, with a note, once.
	if code, _ := a.do("POST", "/incidents/"+id+"/breach/close", "soc1", `{"outcome": "notified", "note": "x"}`); code != 403 {
		t.Errorf("SOC closed the timer: %d", code)
	}
	if code, _ := a.do("POST", "/incidents/"+id+"/breach/close", "dpo1", `{"outcome": "notified"}`); code != 400 {
		t.Errorf("closed without a note: %d", code)
	}
	clock = t0.Add(60 * time.Hour)
	if code, body := a.do("POST", "/incidents/"+id+"/breach/close", "dpo1", `{"outcome": "notified", "note": "Surat ke Lembaga PDP no. 12/2026"}`); code != 200 || !strings.Contains(body, `"outcome":"notified"`) {
		t.Errorf("close: %d %s", code, body)
	}
	if code, _ := a.do("POST", "/incidents/"+id+"/breach/close", "dpo1", `{"outcome": "dismissed", "note": "x"}`); code != 409 {
		t.Errorf("closed twice: %d", code)
	}
	if running, least, _ := s.BreachTimers(ctx, clock); running != 0 || least != nil {
		t.Errorf("metric after close: %d %v", running, least)
	}

	// Declaring by hand: SOC, with a note, starts from now.
	other, raw := ev("p7", t0, 50, nil, "PII_ID.NIK")
	oid, _, _ := s.Ingest(ctx, other, raw, t0)
	if code, _ := a.do("POST", "/incidents/"+oid+"/breach/declare", "soc1", `{}`); code != 400 {
		t.Errorf("declared without a note: %d", code)
	}
	if code, body := a.do("POST", "/incidents/"+oid+"/breach/declare", "soc1", `{"note": "data keluar lewat email, di luar PEP"}`); code != 200 || !strings.Contains(body, `"basis":"declared"`) {
		t.Errorf("declare: %d %s", code, body)
	}
	if code, _ := a.do("POST", "/incidents/"+oid+"/breach/declare", "soc1", `{"note": "again"}`); code != 409 {
		t.Errorf("declared twice: %d", code)
	}
	if code, body := a.do("GET", "/incidents/"+oid+"/breach/report", "dpo1", ""); code != 200 || !strings.Contains(body, `"class":"PII_ID.NIK"`) {
		t.Errorf("declared breach lists the personal data events: %d %s", code, body)
	}
}

// FR-INC-5: a containment block reaches the PDP with the next release, cannot be widened beyond the incident, and
// can be lifted; an action needing another permission is refused (and audited) for the SOC.
func TestContainmentBlock(t *testing.T) {
	s, _, db := setup(t)
	ctx := context.Background()
	ls, err := lifecycle.Open(ctx, db, tenant, policy.Files)
	if err != nil {
		t.Fatal(err)
	}
	ls.AddExtra(ContainmentDoc(tenant))
	s.Release = ls.CutRelease
	now := time.Now().UTC().Truncate(time.Second)
	a := apiFor(t, s, func() time.Time { return now })
	e, raw := ev(strings.Repeat("a", 64), now, 60, func(e *events.Event) {
		allowed(e)
		e.Sensitivity, e.Sanction, e.Region = "confidential", "sanctioned", "ID" // what the PDP needs from the event
	}, "PII_ID.NIK")
	id, _, _ := s.Ingest(ctx, e, raw, now)

	decide := func() map[string]any {
		t.Helper()
		rel, err := ls.Latest(ctx)
		if err != nil {
			t.Fatal(err)
		}
		pq, err := policysvc.Query(ctx, policy.Files, rel.Overrides(), "data.wantimpres26.decision.result")
		if err != nil {
			t.Fatal(err)
		}
		in, _ := e.PDPInput()
		rs, err := pq.Eval(ctx, rego.EvalInput(in))
		if err != nil || len(rs) != 1 {
			t.Fatal(err)
		}
		return rs[0].Expressions[0].Value.(map[string]any)
	}
	before := decide()["action"]

	if code, _ := a.do("POST", "/incidents/"+id+"/actions", "soc1", `{"action": "block_access", "params": {"app_id": "claude"}}`); code != 400 {
		t.Errorf("block outside the incident: %d", code)
	}
	if code, _ := a.do("POST", "/incidents/"+id+"/actions", "soc1", `{"action": "block_access", "params": {"hours": "9999"}}`); code != 400 {
		t.Errorf("block longer than MaxBlock: %d", code)
	}
	if code, _ := a.do("POST", "/incidents/"+id+"/actions", "ciso1", `{"action": "block_access"}`); code != 403 {
		t.Errorf("read-only role contained: %d", code)
	}
	code, body := a.do("POST", "/incidents/"+id+"/actions", "soc1", `{"action": "block_access", "params": {"hours": "4"}}`)
	var rec ActionRecord
	_ = json.Unmarshal([]byte(body), &rec)
	if code != 200 || rec.Result["release"] == nil {
		t.Fatalf("block: %d %s", code, body)
	}
	if d := decide(); d["action"] != "block" || fmt.Sprint(d["reason_codes"]) != "[CONTAINMENT_BLOCK]" {
		t.Errorf("PDP after block: %v (before: %v)", d, before)
	}
	blocks, _ := s.BlocksOf(ctx, id)
	if len(blocks) != 1 || blocks[0].AppID != "chatgpt" || !blocks[0].ExpiresAt.Equal(now.Add(4*time.Hour)) {
		t.Fatalf("blocks %+v", blocks)
	}
	if code, _ := a.do("POST", fmt.Sprintf("/incidents/%s/blocks/%d/lift", id, blocks[0].ID), "soc1", ""); code != 200 {
		t.Errorf("lift: %d", code)
	}
	if d := decide(); d["action"] != before {
		t.Errorf("PDP after lift: %v, want %v", d["action"], before)
	}
	if code, _ := a.do("POST", fmt.Sprintf("/incidents/%s/blocks/%d/lift", id, blocks[0].ID), "soc1", ""); code != 404 {
		t.Errorf("lifted twice: %d", code)
	}

	// An action owned by another module, with its own permission.
	var ran atomic.Int32
	s.Actions["revoke_share_link"] = Action{Perm: authz.DataRemediate, Run: func(context.Context, string, Incident, map[string]string, time.Time) (map[string]any, error) {
		ran.Add(1)
		return map[string]any{}, nil
	}}
	if code, _ := a.do("POST", "/incidents/"+id+"/actions", "soc1", `{"action": "revoke_share_link"}`); code != 403 || ran.Load() != 0 {
		t.Errorf("SOC without data.remediate: %d (ran %d)", code, ran.Load())
	}
	if code, body := a.do("POST", "/incidents/"+id+"/actions", "soc1", `{"action": "reboot_dc"}`); code != 400 || !strings.Contains(body, "block_access") {
		t.Errorf("unknown action: %d %s", code, body)
	}
	var audited []string
	rows, _ := db.Query(ctx, "SELECT action FROM audit.audit_log WHERE action LIKE 'incident.contain%' OR action = 'incident.block.lift' ORDER BY seq")
	for rows.Next() {
		var x string
		_ = rows.Scan(&x)
		audited = append(audited, x)
	}
	if fmt.Sprint(audited) != "[incident.contain incident.block.lift incident.contain.denied]" {
		t.Errorf("audit %v", audited)
	}
	if _, body := a.do("GET", "/incidents/"+id, "soc1", ""); !strings.Contains(body, `"action":"block_access"`) || !strings.Contains(body, `"lifted_by":"soc1"`) {
		t.Errorf("detail lacks the action and the lifted block: %s", body)
	}
}

// Ticket 26 AC "test integrasi ITSM": ServiceNow Table API and Jira SM request API as the bank's instances would
// see them: auth, fields, severity mapping, no content, one ticket per incident.
func TestITSM(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	a := apiFor(t, s, func() time.Time { return now })

	type call struct {
		path, auth string
		body       map[string]any
	}
	var calls []call
	itsm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		calls = append(calls, call{r.URL.String(), r.Header.Get("Authorization"), body})
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/now/table/incident":
			w.WriteHeader(201)
			_, _ = io.WriteString(w, `{"result": {"sys_id": "9d385017c611228701d22104cc95c371", "number": "INC0010042"}}`)
		case "/rest/servicedeskapi/request":
			_, _ = io.WriteString(w, `{"issueKey": "SECOPS-17", "_links": {"web": "https://jira.example/servicedesk/customer/portal/3/SECOPS-17"}}`)
		default:
			w.WriteHeader(500)
		}
	}))
	defer itsm.Close()

	if code, _ := a.do("POST", "/incidents/"+uuid()+"/actions", "soc1", `{"action": "open_ticket"}`); code != 404 {
		t.Errorf("unknown incident: %d", code)
	}
	e, raw := ev("p1", now, 95, allowed, "PII_ID.NIK")
	sn, _, _ := s.Ingest(ctx, e, raw, now)
	if _, err := s.AddRawEvidence(ctx, sn, "prompt", []byte("NIK 3171234567890001"), now); err != nil {
		t.Fatal(err)
	}
	if code, _ := a.do("POST", "/incidents/"+sn+"/actions", "soc1", `{"action": "open_ticket"}`); code != 400 {
		t.Errorf("no ITSM configured: %d", code)
	}

	s.ITSM = &ServiceNow{URL: itsm.URL, Auth: "Basic c3ZjOnB3", Client: itsm.Client()}
	for range 2 {
		code, body := a.do("POST", "/incidents/"+sn+"/actions", "soc1", `{"action": "open_ticket", "params": {"note": "Mohon reset kredensial p1"}}`)
		if code != 200 || !strings.Contains(body, `"ref":"INC0010042"`) || !strings.Contains(body, "sys_id=9d385017c611228701d22104cc95c371") {
			t.Errorf("servicenow: %d %s", code, body)
		}
	}
	if len(calls) != 1 {
		t.Fatalf("servicenow called %d times, want 1", len(calls))
	}
	c := calls[0]
	desc, _ := c.body["description"].(string)
	if c.path != "/api/now/table/incident?sysparm_fields=sys_id,number" || c.auth != "Basic c3ZjOnB3" || c.body["urgency"] != "1" || c.body["impact"] != "1" ||
		c.body["correlation_id"] != sn || !strings.HasPrefix(c.body["short_description"].(string), "[WANTIMPRES-26] allow PII_ID.NIK to chatgpt") ||
		!strings.Contains(desc, "UU PDP breach timer") || !strings.Contains(desc, "Mohon reset kredensial p1") || strings.Contains(fmt.Sprint(c.body), "3171") {
		t.Errorf("servicenow request %+v", c)
	}

	e, raw = ev("p2", now, 50, nil, "PCI.PAN")
	js, _, _ := s.Ingest(ctx, e, raw, now)
	s.ITSM = &JiraSM{URL: itsm.URL, Auth: "Bearer pat", ServiceDeskID: "3", RequestTypeID: "41", Client: itsm.Client()}
	code, body := a.do("POST", "/incidents/"+js+"/actions", "soc1", `{"action": "open_ticket"}`)
	if code != 200 || !strings.Contains(body, `"ref":"SECOPS-17"`) || !strings.Contains(body, `"system":"jira-sm"`) {
		t.Errorf("jira: %d %s", code, body)
	}
	c = calls[1]
	fields, _ := c.body["requestFieldValues"].(map[string]any)
	if c.path != "/rest/servicedeskapi/request" || c.auth != "Bearer pat" || c.body["serviceDeskId"] != "3" || c.body["requestTypeId"] != "41" ||
		!strings.Contains(fields["summary"].(string), "PCI.PAN") || !strings.Contains(fields["description"].(string), js) {
		t.Errorf("jira request %+v", c)
	}
	if _, body := a.do("GET", "/incidents/"+js, "soc1", ""); !strings.Contains(body, `"ref":"SECOPS-17"`) {
		t.Errorf("detail lacks the ticket: %s", body)
	}

	// An ITSM error is reported and nothing is recorded, so a retry opens the ticket.
	s.ITSM = &ServiceNow{URL: itsm.URL + "/down", Auth: "x", Client: itsm.Client()}
	e, raw = ev("p3", now, 50, nil, "PCI.PAN")
	down, _, _ := s.Ingest(ctx, e, raw, now)
	if code, _ := a.do("POST", "/incidents/"+down+"/actions", "soc1", `{"action": "open_ticket"}`); code != 500 {
		t.Errorf("ITSM down: %d", code)
	}
	if tk, _ := s.TicketOf(ctx, down); tk != nil {
		t.Errorf("ticket recorded after an ITSM error: %+v", tk)
	}
}
