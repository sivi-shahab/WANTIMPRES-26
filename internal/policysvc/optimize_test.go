package policysvc

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"

	"wantimpres26/policy"
)

// Ticket 47: the sidecars run the partially evaluated bundle, simulation and the tests run the source. They must
// decide alike, and the bundle must still answer result (invalid input fails closed) and the MCP queries.
func TestOptimizedBundleDecidesAsSource(t *testing.T) {
	ctx := context.Background()
	priv, pub := keyPair(t)
	tarball, _, err := Build(ctx, policy.Files, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := read(tarball, pub)
	if err != nil {
		t.Fatal(err)
	}
	const query = `c := [x | x := data.wantimpres26.decision.checked]; r := [x | x := data.wantimpres26.decision.result]`
	built, err := rego.New(rego.Query(query), rego.ParsedBundle("wantimpres26", &b)).PrepareForEval(ctx)
	if err != nil {
		t.Fatal(err)
	}
	source, err := Query(ctx, policy.Files, nil, query)
	if err != nil {
		t.Fatal(err)
	}

	var inputs []map[string]any
	for _, dir := range []string{"request", "response", "tool_call"} {
		for _, sanction := range []string{"sanctioned", "tolerated", "unsanctioned", "blocked"} {
			for _, sens := range []string{"public", "internal", "confidential", "restricted"} {
				for i, classes := range [][]any{{}, {class("PII_ID.NIK", 1)}, {class("PII_ID.NIK", 60)}, {class("PCI.PAN", 1)},
					{class("SECRET.AWS_KEY", 1)}, {class("FIN.ACCOUNT", 3), class("PHI.DIAGNOSIS", 1)}} {
					in := map[string]any{"channel": "ai_gateway", "direction": dir,
						"principal":   map[string]any{"type": "user", "id": "u", "account_context": []string{"corporate", "personal"}[i%2]},
						"destination": map[string]any{"app_id": []string{"chatgpt", "unknown-app"}[i%2], "sanction": sanction, "region": []string{"US", "ID", "CN"}[i%3]},
						"content":     map[string]any{"sensitivity": sens, "classes": classes, "injection_score": float64(i) / 5, "tokens": 100 * i}}
					if dir == "tool_call" {
						in["channel"] = "mcp_gateway"
						in["agent"] = map[string]any{"agent_id": "a1", "tool": "t", "tool_risk": []string{"low", "high"}[i%2],
							"action": []string{"read", "external_send", "financial"}[i%3], "chain_depth": i, "hitl_available": i%2 == 0}
					}
					inputs = append(inputs, in)
				}
			}
		}
	}
	inputs = append(inputs, map[string]any{"channel": "ai_gateway", "prompt": "raw"}) // invalid: result must block

	actions := map[string]int{}
	for i, in := range inputs {
		want, err := source.Eval(ctx, rego.EvalInput(in))
		if err != nil {
			t.Fatal(err)
		}
		got, err := built.Eval(ctx, rego.EvalInput(in))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got[0].Bindings, want[0].Bindings) {
			t.Fatalf("input %d %v:\nbundle %v\nsource %v", i, in, got[0].Bindings, want[0].Bindings)
		}
		if r, _ := want[0].Bindings["r"].([]any); len(r) == 1 {
			actions[fmt.Sprint(r[0].(map[string]any)["action"])]++
		}
	}
	if actions["allow"] == 0 || actions["block"] == 0 || len(actions) < 3 {
		t.Errorf("actions %v: the inputs do not exercise the rule set", actions)
	}
	if r, _ := mustEval(t, built, inputs[len(inputs)-1])["r"].([]any); len(r) != 1 || r[0].(map[string]any)["action"] != "block" {
		t.Errorf("invalid input through the bundle: %v", r)
	}

	mcp, err := rego.New(rego.Query(`k := data.wantimpres26.kills; a := [x | x := data.wantimpres26.mcp.agent]`), rego.ParsedBundle("wantimpres26", &b),
		rego.Input(map[string]any{"identity": "nobody"})).Eval(ctx)
	if err != nil || len(mcp) != 1 {
		t.Errorf("MCP queries on the bundle: %v %v", mcp, err)
	}
}

func class(typ string, n int) any {
	return map[string]any{"type": typ, "count": n, "confidence": 0.95}
}

func mustEval(t *testing.T, q rego.PreparedEvalQuery, in any) rego.Vars {
	t.Helper()
	rs, err := q.Eval(context.Background(), rego.EvalInput(in))
	if err != nil || len(rs) != 1 {
		t.Fatal(rs, err)
	}
	return rs[0].Bindings
}
