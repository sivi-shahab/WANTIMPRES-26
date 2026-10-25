package events

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"wantimpres26/policy"
)

func valid() Event {
	return Event{
		EventID: "7f9c1b0e-3d1a-4c55-9a3e-2b6f0c8d1e21", TenantID: "00000000-0000-0000-0000-000000000001",
		TS: "2026-10-03T08:00:00.123Z", TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		Channel: "ai_gateway", Direction: "request", PrincipalID: strings.Repeat("a", 64), AppID: "chatgpt",
		Action: "redact", ReasonCodes: []string{"PCI_PAN"}, PolicyVersion: "builtin-1",
		RiskScore: 64, RiskVersion: "risk-1", Classes: []Class{{Type: "PCI.PAN", Count: 1, Confidence: 0.99}},
		ContentHash: strings.Repeat("b", 64), Snippet: "kartu [REDACTED:PCI.PAN] exp 12/27",
	}
}

func payload(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	b, _ := json.Marshal(valid())
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	mutate(m)
	b, _ = json.Marshal(m)
	return b
}

// Privacy test (spec §10.2): raw content in any shape is rejected, with a reason the metric can count.
func TestCheck(t *testing.T) {
	schema, err := Compile(SchemaV1)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"valid", func(map[string]any) {}, ""},
		{"top-level prompt", func(m map[string]any) { m["prompt"] = "NIK saya 3171234567890001" }, RejectRawContent},
		{"case-insensitive", func(m map[string]any) { m["Messages"] = []any{"hi"} }, RejectRawContent},
		{"nested in classes", func(m map[string]any) {
			m["classes"] = []any{map[string]any{"type": "PCI.PAN", "count": 1, "text": "4111..."}}
		}, RejectRawContent},
		{"response body", func(m map[string]any) { m["response"] = "..." }, RejectRawContent},
		{"NIK in snippet", func(m map[string]any) { m["snippet"] = "NIK 3171234567890001 tolong cek" }, RejectUnredacted},
		{"spaced PAN in snippet", func(m map[string]any) { m["snippet"] = "kartu 4111 1111 1111 1111" }, RejectUnredacted},
		{"dashed PAN in snippet", func(m map[string]any) { m["snippet"] = "4111-1111-1111-1111" }, RejectUnredacted},
		{"short numbers are fine", func(m map[string]any) { m["snippet"] = "invoice 2026-10 total 1.250.000" }, ""},
		{"snippet over 200", func(m map[string]any) { m["snippet"] = strings.Repeat("x", 201) }, RejectSchema},
		{"unknown field", func(m map[string]any) { m["user_email"] = "a@bank.co.id" }, RejectSchema},
		{"raw principal", func(m map[string]any) { m["principal_id"] = "budi@bankmega.com" }, RejectSchema},
		{"missing trace_id", func(m map[string]any) { delete(m, "trace_id") }, RejectSchema},
		{"bad uuid", func(m map[string]any) { m["event_id"] = "nope" }, RejectSchema},
		{"risk out of range", func(m map[string]any) { m["risk_score"] = 101 }, RejectSchema},
	}
	for _, c := range cases {
		if got := Check(payload(t, c.mutate), schema); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	if got := Check([]byte("not json"), schema); got != RejectNotJSON {
		t.Errorf("garbage: %q", got)
	}
}

// The Go struct and the JSON Schema must describe the same event.
func TestMarshalMatchesSchema(t *testing.T) {
	schema, _ := Compile(SchemaV1)
	if _, err := Marshal(valid(), schema); err != nil {
		t.Fatal(err)
	}
	minimal := valid()
	minimal.Snippet, minimal.Classes, minimal.ReasonCodes = "", []Class{}, []string{}
	if _, err := Marshal(minimal, schema); err != nil {
		t.Fatalf("minimal event: %v", err)
	}
	bad := valid()
	bad.Snippet = "NIK 3171234567890001"
	if _, err := Marshal(bad, schema); err == nil {
		t.Error("producer would publish an unredacted snippet")
	}
}

// Replayed inputs must pass the PDP's own input schema, or simulation would only ever see INPUT_SCHEMA_INVALID.
func TestPDPInputMatchesPDPSchema(t *testing.T) {
	raw, _ := policy.Files.ReadFile("wantimpres26/schema/data.json")
	var doc struct {
		Input json.RawMessage `json:"input"`
	}
	_ = json.Unmarshal(raw, &doc)
	pdp, err := Compile(string(doc.Input))
	if err != nil {
		t.Fatal(err)
	}
	f, yes := 0.4, true
	full := valid()
	full.Sensitivity, full.Sanction, full.Region = "confidential", "unsanctioned", "US"
	full.PrincipalGroups, full.PrincipalRisk, full.Device, full.AccountContext = []string{"SG-A"}, &f, "unmanaged", "personal"
	full.InjectionScore, full.VolumeRatio, full.TrainsOnData = &f, &f, &yes
	full.AgentID, full.ToolRisk, full.AgentAction, full.AgentRegistered, full.SessionInjectionMax = "agent-1", "high", "financial", &yes, &f
	full.Classes = []Class{{Type: "PCI.PAN", Count: 2}}
	for name, e := range map[string]Event{"full": full, "minimal": func() Event {
		m := valid()
		m.Sensitivity, m.Sanction, m.Region = "public", "sanctioned", "ID"
		return m
	}()} {
		in, ok := e.PDPInput()
		if !ok {
			t.Fatalf("%s: not replayable", name)
		}
		b, _ := json.Marshal(in)
		v, _ := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err := pdp.Validate(v); err != nil {
			t.Errorf("%s: rebuilt input fails the PDP schema: %v\n%s", name, err, b)
		}
		if _, err := Marshal(e, mustCompile(t)); err != nil {
			t.Errorf("%s: event itself invalid: %v", name, err)
		}
	}
	if _, ok := valid().PDPInput(); ok {
		t.Error("event without sensitivity/sanction/region claimed replayable")
	}
}

func mustCompile(t *testing.T) *jsonschema.Schema {
	s, err := Compile(SchemaV1)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Ticket 42: an event of another tenant never reaches the handlers (its rows would break row level security and
// stall the consumer).
func TestOnlyTenant(t *testing.T) {
	var got []string
	h := func(_ context.Context, e Event, _ []byte) error { got = append(got, e.TenantID); return nil }
	hs := OnlyTenant("a", h, h)
	for _, tenant := range []string{"a", "b", ""} {
		for _, f := range hs {
			if err := f(context.Background(), Event{TenantID: tenant}, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	if strings.Join(got, ",") != "a,a" {
		t.Errorf("handled %v", got)
	}
}
