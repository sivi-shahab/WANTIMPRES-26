package wantimpres26.decision_test

import rego.v1

import data.wantimpres26.agent
import data.wantimpres26.decision
import data.wantimpres26.mcp

base := {
	"channel": "ai_gateway",
	"direction": "request",
	"principal": {"type": "user", "id": "u-hmac-1"},
	"destination": {"app_id": "copilot", "sanction": "sanctioned", "region": "ID"},
	"content": {"sensitivity": "internal", "classes": []},
}

with_patch(patch) := object.union(base, patch)

decide(inp) := r if {
	r := decision.result with input as inp
}

rule(id, action) := {"id": id, "when": [{"field": "channel", "op": "eq", "value": "ai_gateway"}], "action": action, "reason": upper(id)}

# --- engine -------------------------------------------------------------------------------------

test_no_match_allows if {
	r := decide(base)
	r.action == "allow"
	r.matched_rules == []
	r.policy_version == "builtin-1"
}

test_output_matches_schema if {
	json.match_schema(decide(base), data.wantimpres26.schema.output)[0]
	json.match_schema(decide({"bogus": true}), data.wantimpres26.schema.output)[0]
}

test_strictest_action_wins_for_every_pair if {
	order := ["allow", "warn", "redact", "tokenize", "require_approval", "quarantine", "block"]
	every i, weaker in order {
		every stronger in array.slice(order, i + 1, count(order)) {
			r := decision.result with input as base
				with data.wantimpres26.rules.items as [rule("a", weaker), rule("b", stronger)]
			r.action == stronger
		}
	}
}

test_obligations_and_reasons_are_merged if {
	rules := [
		object.union(rule("a", "redact"), {"obligations": [{"type": "redact", "classes": ["PCI.PAN"]}]}),
		object.union(rule("b", "redact"), {"obligations": [{"type": "log_evidence"}, {"type": "redact", "classes": ["PCI.PAN"]}]}),
	]
	r := decision.result with input as base with data.wantimpres26.rules.items as rules
	r.action == "redact"
	r.obligations == [{"classes": ["PCI.PAN"], "type": "redact"}, {"type": "log_evidence"}]
	r.reason_codes == ["A", "B"]
	r.matched_rules == ["a", "b"]
}

test_monitor_rules_never_change_action if {
	rules := [object.union(rule("m", "block"), {"mode": "monitor"}), rule("w", "warn")]
	r := decision.result with input as base with data.wantimpres26.rules.items as rules
	r.action == "warn"
	r.monitor_rules == ["m"]
	r.matched_rules == ["w"]
}

test_invalid_input_fails_closed if {
	every bad in [
		{},
		object.union(base, {"prompt": "raw text must never be sent"}),
		object.remove(base, ["destination"]),
		with_patch({"content": {"sensitivity": "secret", "classes": []}}),
		with_patch({"content": {"sensitivity": "internal", "classes": [{"type": "nik", "count": 1, "confidence": 1}]}}),
	] {
		r := decide(bad)
		r.action == "block"
		r.reason_codes == ["INPUT_SCHEMA_INVALID"]
	}
}

ops_input := with_patch({"content": {"sensitivity": "internal", "injection_score": 0.5, "classes": [{"type": "PII_ID.NIK", "count": 2, "confidence": 0.9}]}})

cond(c) if {
	decision.result.matched_rules == ["x"] with input as ops_input
		with data.wantimpres26.rules.items as [{"id": "x", "when": [c], "action": "warn", "reason": "X"}]
}

test_ops if {
	cond({"field": "content.sensitivity", "op": "eq", "value": "internal"})
	not cond({"field": "content.sensitivity", "op": "eq", "value": "public"})
	cond({"field": "destination.region", "op": "neq", "value": "US"})
	cond({"field": "destination.missing", "op": "neq", "value": "ID"})
	cond({"field": "destination.sanction", "op": "in", "value": ["sanctioned"]})
	cond({"field": "destination.sanction", "op": "not_in", "value": ["blocked"]})
	not cond({"field": "destination.sanction", "op": "not_in", "value": ["sanctioned"]})
	cond({"field": "content.injection_score", "op": "gte", "value": 0.5})
	not cond({"field": "content.injection_score", "op": "gte", "value": 0.51})
	cond({"field": "content.injection_score", "op": "lte", "value": 0.5})
	not cond({"field": "content.tokens", "op": "gte", "value": 0}) # missing number never compares
	cond({"field": "risk_score", "op": "gte", "value": 10}) # computed by wantimpres26.risk (~17 here)
	not cond({"field": "risk_score", "op": "gte", "value": 50})
	cond({"field": "content.classes", "op": "class_count_gte", "value": {"type": "PII_ID.*", "min": 2}})
	not cond({"field": "content.classes", "op": "class_count_gte", "value": {"type": "PII_ID.NIK", "min": 3}})
	cond({"field": "content.classes", "op": "class_any", "value": ["PII_ID.*"]})
	cond({"field": "content.classes", "op": "class_any", "value": ["PII_ID.NIK"]})
	not cond({"field": "content.classes", "op": "class_any", "value": ["PII.*"]})
	not cond({"field": "content.classes", "op": "class_any", "value": ["SECRET.*"]})
}

test_builtin_rules_are_valid if {
	count(decision.rule_errors) == 0
}

test_invalid_rules_are_reported if {
	bad := [
		rule("dup", "block"),
		rule("dup", "warn"),
		rule("act", "nuke"),
		{"id": "op", "when": [{"field": "channel", "op": "regex", "value": "."}], "action": "block", "reason": "R"},
		{"id": "empty", "when": [], "action": "block", "reason": "R"},
		{"id": "noreason", "when": [{"field": "channel", "op": "eq", "value": "x"}], "action": "block"},
		object.union(rule("mode", "warn"), {"mode": "shadow"}),
	]
	errs := decision.rule_errors with data.wantimpres26.rules.items as bad
	errs == {
		"duplicate id dup",
		"act: unknown action nuke",
		"op: unknown op regex",
		"empty: empty when",
		"noreason: missing reason",
		"mode: unknown mode shadow",
	}
}

# --- FR-POL-8 templates ---------------------------------------------------------------------------

cls(t) := [{"type": t, "count": 1, "confidence": 0.99}]

test_tpl_pii_id_to_unsanctioned if {
	every s in ["unsanctioned", "blocked", "under_review"] {
		r := decide(with_patch({"destination": {"app_id": "x", "sanction": s, "region": "ID"}, "content": {"sensitivity": "confidential", "classes": cls("PII_ID.NIK")}}))
		r.action == "block"
		"tpl.pii-id-to-unsanctioned" in r.matched_rules
	}
	decide(with_patch({"content": {"sensitivity": "confidential", "classes": cls("PII_ID.NIK")}})).action == "allow"
	decide(with_patch({"direction": "response", "destination": {"app_id": "x", "sanction": "unsanctioned", "region": "ID"}, "content": {"sensitivity": "confidential", "classes": cls("PII_ID.NIK")}})).action == "allow"
}

test_tpl_secret_to_any_ai if {
	r := decide(with_patch({"content": {"sensitivity": "restricted", "classes": cls("SECRET.AWS_KEY")}}))
	r.action == "block"
	"SECRET_TO_AI" in r.reason_codes
	decide(with_patch({"direction": "tool_call", "content": {"sensitivity": "internal", "classes": cls("SECRET.JWT")}})).action == "block"
}

test_tpl_pci_pan_redact if {
	every d in ["request", "response", "tool_result"] {
		r := decide(with_patch({"direction": d, "content": {"sensitivity": "confidential", "classes": cls("PCI.PAN")}}))
		r.action == "redact"
		{"type": "redact", "classes": ["PCI.PAN"]} in r.obligations
	}
}

test_tpl_restricted_to_sanctioned if {
	r := decide(with_patch({"content": {"sensitivity": "restricted", "classes": []}}))
	r.action == "redact"
	r.obligations == [{"classes": ["*"], "type": "redact"}, {"type": "log_evidence"}]
}

test_tpl_injection_high if {
	every d in ["request", "response", "tool_result"] {
		decide(with_patch({"direction": d, "content": {"sensitivity": "public", "classes": [], "injection_score": 0.9}})).action == "block"
	}
	decide(with_patch({"content": {"sensitivity": "public", "classes": [], "injection_score": 0.89}})).action == "allow"
}

# --- ADR-0001 residency: every sensitivity x region x sanction ---------------------------------------

expected_residency(sens, region, sanction) := "block" if {
	sanction == "blocked" # tpl.blocked-app, wherever the app runs
} else := "block" if {
	region != "ID"
	true in {sens == "restricted", sanction != "sanctioned"}
} else := "redact" if {
	region != "ID"
	sens == "confidential"
} else := "redact" if {
	# onshore: only the restricted-to-sanctioned template applies
	sens == "restricted"
	sanction == "sanctioned"
} else := "allow"

test_residency_matrix if {
	combos := {[sens, region, sanction] |
		some sens in ["public", "internal", "confidential", "restricted"]
		some region in ["ID", "SG", "US", "unknown"]
		some sanction in ["sanctioned", "tolerated", "unsanctioned", "blocked", "under_review"]
	}
	count(combos) == 80
	mismatches := {[c, got, want] |
		some c in combos
		got := decide(with_patch({
			"destination": {"app_id": "x", "sanction": c[2], "region": c[1]},
			"content": {"sensitivity": c[0], "classes": []},
		})).action
		want := expected_residency(c[0], c[1], c[2])
		got != want
	}
	print("residency mismatches:", mismatches)
	count(mismatches) == 0
}

test_residency_does_not_apply_to_inbound if {
	every d in ["response", "tool_result"] {
		decide(with_patch({"direction": d, "destination": {"app_id": "x", "sanction": "unsanctioned", "region": "US"}, "content": {"sensitivity": "restricted", "classes": []}})).action == "allow"
	}
}

# --- FR-POL-7 exceptions -------------------------------------------------------------------------

exc(rules, scope, expires) := {"id": "ex1", "rules": rules, "scope": scope, "expires_at": expires}

pii_to_unsanctioned := with_patch({
	"principal": {"type": "user", "id": "u-hmac-1", "groups": ["SG-RESEARCH"]},
	"destination": {"app_id": "deepseek", "sanction": "unsanctioned", "region": "ID"},
	"content": {"sensitivity": "confidential", "classes": cls("PII_ID.NIK")},
})

decide_with(inp, exceptions) := r if {
	r := decision.result with input as inp with data.wantimpres26.exceptions.items as exceptions
}

test_exception_lifts_rule_in_scope if {
	future := "2099-01-01T00:00:00Z"
	every scope in [{"group": "SG-RESEARCH"}, {"app_id": "deepseek"}, {"principal_id": "u-hmac-1"}, {"group": "SG-RESEARCH", "app_id": "deepseek"}] {
		r := decide_with(pii_to_unsanctioned, [exc(["tpl.pii-id-to-unsanctioned"], scope, future)])
		r.action == "allow"
		r.exempted_rules == ["tpl.pii-id-to-unsanctioned"]
		not "tpl.pii-id-to-unsanctioned" in r.matched_rules
	}
}

test_exception_does_not_apply if {
	future := "2099-01-01T00:00:00Z"
	every ex in [
		exc(["tpl.pii-id-to-unsanctioned"], {"group": "SG-OTHER"}, future), # other scope
		exc(["tpl.pii-id-to-unsanctioned"], {"group": "SG-RESEARCH", "app_id": "chatgpt"}, future), # every key must match
		exc(["tpl.pii-id-to-unsanctioned"], {}, future), # empty scope is not "everyone"
		exc(["tpl.pii-id-to-unsanctioned"], {"group": "SG-RESEARCH"}, "2020-01-01T00:00:00Z"), # expired
		exc(["tpl.secret-to-any-ai"], {"group": "SG-RESEARCH"}, future), # other rule
	] {
		r := decide_with(pii_to_unsanctioned, [ex])
		r.action == "block"
		r.exempted_rules == []
	}
}

test_exception_only_lifts_named_rule if {
	inp := object.union(pii_to_unsanctioned, {"content": {"sensitivity": "confidential", "classes": array.concat(cls("PII_ID.NIK"), cls("SECRET.AWS_KEY"))}})
	r := decide_with(inp, [exc(["tpl.pii-id-to-unsanctioned"], {"group": "SG-RESEARCH"}, "2099-01-01T00:00:00Z")])
	r.action == "block"
	r.matched_rules == ["tpl.secret-to-any-ai"]
	r.exempted_rules == ["tpl.pii-id-to-unsanctioned"]
}

# --- ticket 16: the catalog is the source of truth for known apps ----------------------------------------

catalog := {"version": 3, "apps": {
	"deepseek": {"sanction": "blocked", "region": "CN", "trains_on_data": true},
	"copilot": {"sanction": "sanctioned", "region": "ID", "trains_on_data": false},
}}

test_catalog_overrides_pep_destination if {
	# The PEP thinks deepseek is sanctioned and onshore; the catalog says blocked and offshore.
	inp := with_patch({"destination": {"app_id": "deepseek", "sanction": "sanctioned", "region": "ID"}, "content": {"sensitivity": "internal", "classes": []}})
	r := decision.result with input as inp with data.wantimpres26.catalog as catalog
	r.action == "block"
	"res.offshore-unsanctioned" in r.matched_rules
	r.destination.sanction == "blocked"
	r.destination.region == "CN"
	r.risk_score >= 20
}

test_catalog_unknown_app_keeps_pep_values if {
	inp := with_patch({"destination": {"app_id": "new-ai-tool", "sanction": "unsanctioned", "region": "US"}, "content": {"sensitivity": "public", "classes": []}})
	r := decision.result with input as inp with data.wantimpres26.catalog as catalog
	r.destination == {"app_id": "new-ai-tool", "sanction": "unsanctioned", "region": "US"}
	r.action == "block" # offshore + unsanctioned
}

test_catalog_change_flips_decision if {
	inp := with_patch({"destination": {"app_id": "copilot", "sanction": "sanctioned", "region": "ID"}, "content": {"sensitivity": "internal", "classes": []}})
	before := decision.result with input as inp with data.wantimpres26.catalog as catalog
	before.action == "allow"
	blocked := json.patch(catalog, [{"op": "replace", "path": "/apps/copilot/sanction", "value": "blocked"}])
	r := decision.result with input as inp with data.wantimpres26.catalog as blocked
	r.destination.sanction == "blocked"
	r.risk_score > before.risk_score
}

# --- ticket 27: the agent registry decides registration and status ---------------------------------------

agents := {"version": 2, "items": {
	"invoice-bot": {"status": "active", "risk_tier": "high", "identity": "spiffe://bank.local/invoice-bot", "tools": [
		{"name": "erp.read", "risk": "low"},
		{"name": "payments.transfer", "risk": "high", "scopes": {"amount": {"max": 25000000}}},
	]},
	"orphan-bot": {"status": "quarantined", "risk_tier": "medium", "identity": "orphan-client", "tools": [{"name": "erp.read", "risk": "low"}]},
}}

agent_call(id, claims) := with_patch({
	"direction": "tool_call",
	"agent": object.union({"agent_id": id, "tool": "erp.read", "tool_risk": "low"}, claims),
	"content": {"sensitivity": "internal", "classes": []},
})

test_registry_decides_registration if {
	active := decision.result with input as agent_call("invoice-bot", {}) with data.wantimpres26.agents as agents
	active.action == "allow"
	not "tpl.agent-not-active" in active.matched_rules
	# A quarantined agent is blocked even if the PEP claims it is registered.
	q := decision.result with input as agent_call("orphan-bot", {"registered": true}) with data.wantimpres26.agents as agents
	q.action == "block"
	q.reason_codes == ["AGENT_NOT_ACTIVE"]
	# Unknown agents are unregistered (risk floor applies to high tools); with no allow-list they may call no tool.
	u := decision.result with input as agent_call("shadow-bot", {"registered": true, "tool_risk": "high"}) with data.wantimpres26.agents as agents
	u.risk_overrides == ["unregistered-agent-high-tool"]
	u.risk_score >= 90
	u.reason_codes == ["TOOL_NOT_ALLOWED"]
}

# --- ticket 28: MCP gateway -----------------------------------------------------------------------------

test_tool_allow_list_and_registry_risk if {
	# Not on the allow-list: blocked, even for an active agent.
	r := decision.result with input as agent_call("invoice-bot", {"tool": "hr.export"}) with data.wantimpres26.agents as agents
	r.reason_codes == ["TOOL_NOT_ALLOWED"]
	# The registry's tool risk replaces the PEP's claim: payments.transfer is high whatever the PEP says.
	h := agent.agent with input as agent_call("invoice-bot", {"tool": "payments.transfer", "tool_risk": "low"}) with data.wantimpres26.agents as agents
	h.tool_risk == "high"
	h.tool_allowed
	# Outside tool_call (e.g. an agent's own LLM request) the allow-list does not apply.
	l := decision.result with input as object.union(agent_call("invoice-bot", {"tool": "hr.export"}), {"direction": "request"}) with data.wantimpres26.agents as agents
	l.action == "allow"
}

test_tool_scope_rate_and_depth if {
	every patch, reason in {
		{"scope_violations": 1}: "TOOL_SCOPE_VIOLATION",
		{"rate_exceeded": true}: "TOOL_RATE_LIMITED",
		{"chain_depth": 4}: "AGENT_CHAIN_TOO_DEEP",
	} {
		r := decision.result with input as agent_call("invoice-bot", patch) with data.wantimpres26.agents as agents
		r.reason_codes == [reason]
		r.action == "block"
	}
	ok := decision.result with input as agent_call("invoice-bot", {"scope_violations": 0, "rate_exceeded": false, "chain_depth": 3}) with data.wantimpres26.agents as agents
	ok.action == "allow"
}

test_indirect_injection_in_tool_result if {
	inp := object.union(agent_call("invoice-bot", {}), {"direction": "tool_result", "content": {"sensitivity": "internal", "classes": [], "injection_score": 0.72}})
	r := decision.result with input as inp with data.wantimpres26.agents as agents
	r.action == "block"
	r.reason_codes == ["INDIRECT_INJECTION"]
	# The same score in the agent's own request stays under the direct threshold (0.9).
	q := decision.result with input as object.union(inp, {"direction": "request"}) with data.wantimpres26.agents as agents
	q.action == "allow"
}

test_injection_tainted_session_needs_approval_for_high_tool if {
	tainted := {"tool": "payments.transfer", "session_injection_max": 0.6}
	r := decision.result with input as agent_call("invoice-bot", tainted) with data.wantimpres26.agents as agents
	r.action == "require_approval"
	r.reason_codes == ["INJECTION_THEN_HIGH_TOOL"]
	# Low tools stay usable in a tainted session; a clean session may use the high tool.
	low := decision.result with input as agent_call("invoice-bot", {"session_injection_max": 0.6}) with data.wantimpres26.agents as agents
	low.action == "allow"
	clean := decision.result with input as agent_call("invoice-bot", {"tool": "payments.transfer", "session_injection_max": 0.1}) with data.wantimpres26.agents as agents
	clean.action == "allow"
}

test_mcp_lookup_by_workload_identity if {
	a := mcp.agent with input as {"identity": "spiffe://bank.local/invoice-bot"} with data.wantimpres26.agents as agents
	a.agent_id == "invoice-bot"
	a.tools[1].scopes.amount.max == 25000000
	not mcp.agent with input as {"identity": "unknown"} with data.wantimpres26.agents as agents
}

# --- ticket 29: MCP tool definitions pinned and re-approved on change -----------------------------------------

pin := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

mcp_tools := {"version": 3, "items": {
	"erp/erp.read": {"status": "approved", "hash": pin},
	"erp/payments.transfer": {"status": "under_review", "hash": pin},
	"hr/erp.read": {"status": "rejected", "hash": ""},
}}

mcp_call(server, tool, hash) := agent_call("invoice-bot", object.union({"tool": tool, "mcp_server": server}, {"tool_hash": hash | hash != ""}))

test_mcp_tool_must_be_approved_and_unchanged if {
	ok := decision.result with input as mcp_call("erp", "erp.read", pin) with data.wantimpres26.agents as agents with data.wantimpres26.mcp_tools as mcp_tools
	ok.action == "allow"
	# The gateway did not see tools/list on this replica: the approved status alone decides.
	unseen := decision.result with input as mcp_call("erp", "erp.read", "") with data.wantimpres26.agents as agents with data.wantimpres26.mcp_tools as mcp_tools
	unseen.action == "allow"
	every inp in [
		mcp_call("erp", "erp.read", concat("", ["b", substring(pin, 1, -1)])), # rug pull: served definition is not the pin
		mcp_call("erp", "payments.transfer", pin), # changed earlier, waiting for re-approval
		mcp_call("hr", "erp.read", ""), # rejected
		mcp_call("crm", "erp.read", ""), # never seen
	] {
		r := decision.result with input as inp with data.wantimpres26.agents as agents with data.wantimpres26.mcp_tools as mcp_tools
		r.action == "block"
		"TOOL_NOT_APPROVED" in r.reason_codes
	}
	# Tool calls outside the MCP gateway (no mcp_server) are not subject to definition pins.
	other := decision.result with input as agent_call("invoice-bot", {}) with data.wantimpres26.agents as agents with data.wantimpres26.mcp_tools as mcp_tools
	other.action == "allow"
}

test_mcp_tools_for_gateway_fallback if {
	ts := mcp.tools with input as {"server": "erp"} with data.wantimpres26.mcp_tools as mcp_tools
	ts == {"erp.read": {"status": "approved", "hash": pin}, "payments.transfer": {"status": "under_review", "hash": pin}}
}

# --- ticket 30: HITL approval and kill switch ----------------------------------------------------------------

test_kill_switch_scopes if {
	call := agent_call("invoice-bot", {})
	every kills in [
		{"global": true, "agent": {}, "tool": {}, "app": {}},
		{"global": false, "agent": {"invoice-bot": "INC-1"}, "tool": {}, "app": {}},
		{"global": false, "agent": {}, "tool": {"erp.read": "rug pull"}, "app": {}},
		{"global": false, "agent": {}, "tool": {}, "app": {"copilot": "vendor breach"}},
	] {
		r := decision.result with input as call with data.wantimpres26.agents as agents with data.wantimpres26.kills as kills
		r.action == "block"
		"KILL_SWITCH" in r.reason_codes
	}
	other := {"global": false, "agent": {"other-bot": "x"}, "tool": {"hr.export": "x"}, "app": {"erp": "x"}}
	ok := decision.result with input as call with data.wantimpres26.agents as agents with data.wantimpres26.kills as other
	ok.action == "allow"
	# An approval never lifts a kill switch.
	k := decision.result with input as agent_call("invoice-bot", {"approval_granted": true}) with data.wantimpres26.agents as agents
		with data.wantimpres26.kills as {"global": true, "agent": {}, "tool": {}, "app": {}}
	k.action == "block"
}

test_approval_lifts_only_require_approval if {
	tainted := {"tool": "payments.transfer", "session_injection_max": 0.6}
	r := decision.result with input as agent_call("invoice-bot", object.union(tainted, {"approval_granted": true})) with data.wantimpres26.agents as agents
	r.action == "allow"
	r.exempted_rules == ["tpl.injection-then-high-tool"]
	# A stricter rule in the same decision still blocks.
	b := decision.result with input as agent_call("invoice-bot", object.union(tainted, {"approval_granted": true, "scope_violations": 1})) with data.wantimpres26.agents as agents
	b.action == "block"
}

# --- ticket 26: containment block ---------------------------------------------------------------------------

test_containment_block if {
	blocks := [{"principal_id": "u-hmac-1", "app_id": "copilot", "expires_at": "2099-01-01T00:00:00Z", "incident": "i1"}]
	r := decision.result with input as base with data.wantimpres26.containment.blocks as blocks
	r.action == "block"
	r.reason_codes == ["CONTAINMENT_BLOCK"]
	r.matched_rules == ["containment.block"]
	# Another app, another principal, or an expired block: no effect.
	other := with_patch({"destination": {"app_id": "chatgpt", "sanction": "sanctioned", "region": "ID"}})
	r2 := decision.result with input as other with data.wantimpres26.containment.blocks as blocks
	not "CONTAINMENT_BLOCK" in r2.reason_codes
	r3 := decision.result with input as with_patch({"principal": {"type": "user", "id": "u-hmac-2"}}) with data.wantimpres26.containment.blocks as blocks
	not "CONTAINMENT_BLOCK" in r3.reason_codes
	expired := [object.union(blocks[0], {"expires_at": "2020-01-01T00:00:00Z"})]
	r4 := decision.result with input as base with data.wantimpres26.containment.blocks as expired
	r4.action == "allow"
	# An exception for every rule does not lift it.
	ex := [{"rules": ["containment.block"], "scope": {"principal_id": "u-hmac-1"}, "expires_at": "2099-01-01T00:00:00Z"}]
	r5 := decision.result with input as base with data.wantimpres26.containment.blocks as blocks with data.wantimpres26.exceptions.items as ex
	r5.action == "block"
}

# --- ticket 44: memory writes -------------------------------------------------------------------------------

test_registry_decides_writes_memory if {
	mem_agents := json.patch(agents, [{"op": "add", "path": "/items/invoice-bot/tools/-", "value": {"name": "kb.save", "risk": "medium", "writes_memory": true}}])
	injected := {"sensitivity": "internal", "classes": [], "injection_score": 0.6}
	# The PEP says "not a memory write"; the registry says it is.
	w := decision.result with input as object.union(agent_call("invoice-bot", {"tool": "kb.save", "writes_memory": false}), {"content": injected})
		with data.wantimpres26.agents as mem_agents
	w.action == "block"
	"MEMORY_POISONING" in w.reason_codes
	# The PEP says "memory write" for a tool the registry does not mark: no memory rule.
	r := decision.result with input as object.union(agent_call("invoice-bot", {"writes_memory": true}), {"content": injected})
		with data.wantimpres26.agents as mem_agents
	not "MEMORY_POISONING" in r.reason_codes
	# A tainted session writing clean content: approval.
	t := decision.result with input as agent_call("invoice-bot", {"tool": "kb.save", "session_injection_max": 0.6}) with data.wantimpres26.agents as mem_agents
	t.action == "require_approval"
	t.reason_codes == ["MEMORY_WRITE_TAINTED_SESSION"]
}
