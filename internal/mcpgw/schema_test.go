package mcpgw

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"

	"wantimpres26/internal/policysvc"
	"wantimpres26/policy"
)

// Ticket 47: the gateways skip the PDP's schema check when Go says the input is valid, so Go must never accept
// what the PDP's json.match_schema rejects. And checked must decide exactly like result.
func TestInputSchemaMatchesPDP(t *testing.T) {
	ctx := context.Background()
	q, err := policysvc.Query(ctx, policy.Files, policysvc.Overrides{}, `v := [x | x := data.wantimpres26.decision.valid_input]; c := [x | x := data.wantimpres26.decision.checked]; r := [x | x := data.wantimpres26.decision.result]`)
	if err != nil {
		t.Fatal(err)
	}
	f, err := policy.Files.Open("corpus/templates.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var inputs []map[string]any
	for sc := bufio.NewScanner(f); sc.Scan(); {
		var c struct {
			Input map[string]any `json:"input"`
		}
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, c.Input)
	}
	agent := `{"channel": "mcp_gateway", "direction": "tool_call", "principal": {"type": "agent", "id": "a"},
		"destination": {"app_id": "x", "sanction": "sanctioned", "region": "ID"}, "content": {"sensitivity": "internal", "classes": []},
		"agent": {"agent_id": "a1", "tool": "t", "tool_risk": "high", "registered": true, "chain_depth": 1, "behavior_anomalies": ["new_tool"]}}`
	base := `{"channel": "ai_gateway", "direction": "request", "principal": {"type": "user", "id": "u", "risk": 0.2, "groups": ["g"]},
		"destination": {"app_id": "chatgpt", "sanction": "sanctioned", "region": "US"},
		"content": {"sensitivity": "confidential", "classes": [{"type": "PII_ID.NIK", "count": 1, "confidence": 0.97}], "injection_score": 0.1, "tokens": 10}}`
	for _, mut := range []func(m map[string]any){
		func(map[string]any) {},
		func(m map[string]any) { delete(m, "channel") },
		func(m map[string]any) { m["channel"] = "email" },
		func(m map[string]any) { m["prompt"] = "raw text" },
		func(m map[string]any) { m["principal"].(map[string]any)["id"] = "" },
		func(m map[string]any) { m["principal"].(map[string]any)["risk"] = 1.5 },
		func(m map[string]any) { m["destination"].(map[string]any)["region"] = "id" },
		func(m map[string]any) { m["destination"].(map[string]any)["sanction"] = "ok" },
		func(m map[string]any) { m["content"].(map[string]any)["classes"] = "PII_ID.NIK" },
		func(m map[string]any) { m["content"].(map[string]any)["sensitivity"] = "secret" },
		func(m map[string]any) { m["content"].(map[string]any)["injection_score"] = -0.1 },
		func(m map[string]any) { m["content"].(map[string]any)["tokens"] = 1.5 },
		func(m map[string]any) {
			m["content"].(map[string]any)["classes"] = []any{map[string]any{"type": "nik", "count": 1, "confidence": 0.9}}
		},
		func(m map[string]any) {
			m["content"].(map[string]any)["classes"] = []any{map[string]any{"type": "PII_ID.NIK", "count": 0, "confidence": 0.9}}
		},
		func(m map[string]any) { m["agent"] = map[string]any{"tool": "t"} },
	} {
		var m map[string]any
		_ = json.Unmarshal([]byte(base), &m)
		mut(m)
		inputs = append(inputs, m)
	}
	for _, mut := range []func(m map[string]any){
		func(map[string]any) {},
		func(m map[string]any) { m["agent"].(map[string]any)["tool_risk"] = "extreme" },
		func(m map[string]any) { m["agent"].(map[string]any)["behavior_anomalies"] = []any{"odd"} },
		func(m map[string]any) { m["agent"].(map[string]any)["tool_hash"] = "abc" },
		func(m map[string]any) { m["agent"].(map[string]any)["chain_depth"] = -1 },
	} {
		var m map[string]any
		_ = json.Unmarshal([]byte(agent), &m)
		mut(m)
		inputs = append(inputs, m)
	}

	valid := 0
	for i, in := range inputs {
		rs, err := q.Eval(ctx, rego.EvalInput(in))
		if err != nil || len(rs) != 1 {
			t.Fatalf("%d: %v %v", i, rs, err)
		}
		b := rs[0].Bindings
		pdp := len(b["v"].([]any)) == 1
		if got := validInput(in); got != pdp {
			t.Errorf("input %d: Go valid=%v, PDP valid=%v: %v", i, got, pdp, in)
		}
		if pdp {
			valid++
			if !reflect.DeepEqual(b["c"], b["r"]) {
				t.Errorf("input %d: checked %v != result %v", i, b["c"], b["r"])
			}
		}
	}
	if valid < 5 || valid == len(inputs) {
		t.Errorf("%d of %d inputs valid: the cases do not cover both sides", valid, len(inputs))
	}
}

// A sidecar still on a bundle without decision.checked (rollout) answers undefined: Decide asks result instead.
func TestDecideFallsBackToResult(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/checked") {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		_, _ = w.Write([]byte(`{"result": {"action": "redact"}}`))
	}))
	defer srv.Close()
	in := map[string]any{"channel": "ai_gateway", "direction": "request", "principal": map[string]any{"type": "user", "id": "u"},
		"destination": map[string]any{"app_id": "chatgpt", "sanction": "sanctioned", "region": "US"},
		"content":     map[string]any{"sensitivity": "internal", "classes": []any{}}}
	d, err := (&OPA{URL: srv.URL, HTTP: srv.Client()}).Decide(context.Background(), in)
	if err != nil || d.Action != "redact" || !slices.Equal(paths, []string{"/v1/data/wantimpres26/decision/checked", "/v1/data/wantimpres26/decision/result"}) {
		t.Errorf("%+v %v %v", d, err, paths)
	}
}
