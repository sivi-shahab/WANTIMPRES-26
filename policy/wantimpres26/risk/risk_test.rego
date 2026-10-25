package wantimpres26.risk_test

import rego.v1

import data.wantimpres26.decision
import data.wantimpres26.risk

# Every factor 0: public content, sanctioned app, corporate managed user, no agent.
zero := {
	"channel": "ai_gateway",
	"direction": "request",
	"principal": {"type": "user", "id": "u1", "device": "managed", "account_context": "corporate"},
	"destination": {"app_id": "x", "sanction": "sanctioned", "region": "ID"},
	"content": {"sensitivity": "public", "classes": []},
}

patch(p) := object.union(zero, p)

factors(p) := f if f := risk.factors with input as patch(p)

score(p) := s if s := risk.score with input as patch(p)

test_zero_input_scores_zero if {
	factors({}) == {"sens": 0, "dest": 0, "attack": 0, "agency": 0, "volume": 0, "ident": 0}
	score({}) == 0
}

# --- FR-RISK-1: one row per factor value ------------------------------------------------------

test_f_sens if {
	every s, want in {"public": 0, "internal": 0.3, "confidential": 0.6, "restricted": 1} {
		factors({"content": {"sensitivity": s, "classes": []}}).sens == want
	}
	score({"content": {"sensitivity": "restricted", "classes": []}}) == 30
}

test_f_dest if {
	every s, want in {"sanctioned": 0, "tolerated": 0.4, "unsanctioned": 0.8, "under_review": 0.8, "blocked": 1} {
		factors({"destination": {"app_id": "x", "sanction": s, "region": "ID"}}).dest == want
	}
	# personal account counts as blocked, even on a sanctioned app
	factors({"principal": {"type": "user", "id": "u1", "account_context": "personal"}}).dest == 1
	score({"destination": {"app_id": "x", "sanction": "blocked", "region": "ID"}}) == 20
}

test_f_attack_is_max_of_scores if {
	factors({"content": {"sensitivity": "public", "classes": [], "injection_score": 0.2, "jailbreak_score": 0.7, "exfil_score": 0.4}}).attack == 0.7
	factors({"content": {"sensitivity": "public", "classes": [], "exfil_score": 1}}).attack == 1
	score({"content": {"sensitivity": "public", "classes": [], "exfil_score": 1}}) == 15
}

test_f_agency if {
	every a, want in {"read": 0.1, "write": 0.5, "external_send": 0.8, "financial": 1} {
		factors({"agent": {"agent_id": "a", "action": a, "registered": true}}).agency == want
	}
	# action wins over tool_risk; tool_risk is the fallback
	factors({"agent": {"agent_id": "a", "action": "read", "tool_risk": "high", "registered": true}}).agency == 0.1
	every t, want in {"low": 0.1, "medium": 0.5, "high": 1} {
		factors({"agent": {"agent_id": "a", "tool_risk": t, "registered": true}}).agency == want
	}
	factors({"agent": {"agent_id": "a", "registered": true}}).agency == 0
}

test_f_volume_steps if {
	every ratio, want in {0: 0, 1.9: 0, 2: 0.25, 5: 0.5, 8: 0.75, 15.9: 0.75, 16: 1, 1000000: 1} {
		factors({"content": {"sensitivity": "public", "classes": [], "volume_ratio": ratio}}).volume == want
	}
}

test_f_ident if {
	every d, want in {"managed": 0, "unknown": 0.3, "unmanaged": 0.6} {
		factors({"principal": {"type": "user", "id": "u1", "device": d, "account_context": "corporate"}}).ident == want
	}
	factors({"principal": {"type": "user", "id": "u1", "account_context": "personal"}}).ident == 1
	factors({"principal": {"type": "user", "id": "u1", "risk": 0.45}}).ident == 0.45
	factors({"principal": {"type": "user", "id": "u1", "device": "unmanaged", "risk": 0.9}}).ident == 0.9
}

test_weighted_sum_and_cap if {
	# restricted -> unsanctioned: 100 x (0.3 x 1 + 0.2 x 0.8) = 46
	score({"destination": {"app_id": "x", "sanction": "unsanctioned", "region": "ID"}, "content": {"sensitivity": "restricted", "classes": []}}) == 46
	# every factor at 1 is exactly 100
	score({
		"principal": {"type": "user", "id": "u1", "account_context": "personal"},
		"destination": {"app_id": "x", "sanction": "blocked", "region": "ID"},
		"content": {"sensitivity": "restricted", "classes": [], "exfil_score": 1, "volume_ratio": 99},
		"agent": {"agent_id": "a", "action": "financial", "registered": true},
	}) == 100
}

# --- FR-RISK-2: one row per override, plus the near miss that must not fire ----------------------

cls(t, n) := [{"type": t, "count": n, "confidence": 0.99}]

unsanctioned := {"app_id": "x", "sanction": "unsanctioned", "region": "ID"}

personal := {"type": "user", "id": "u1", "account_context": "personal"}

# Ticket 27: registration comes from the registry, not from the PEP's "registered" claim.
registry := {"version": 1, "items": {"a": {"status": "active", "risk_tier": "high"}, "s": {"status": "suspended", "risk_tier": "high"}}}

high_tool(extra) := object.union({"agent_id": "a", "tool": "payments.transfer", "tool_risk": "high", "registered": true}, extra)

pan_nik := "pan-or-bulk-nik-to-personal-or-unsanctioned"

override_cases := [
	# [id, patch that fires it, near miss, want score]
	[
		"secret-to-unsanctioned",
		{"destination": unsanctioned, "content": {"sensitivity": "internal", "classes": cls("SECRET.AWS_KEY", 1)}},
		{"content": {"sensitivity": "internal", "classes": cls("SECRET.AWS_KEY", 1)}},
		100,
	],
	[
		"injection-then-high-tool",
		{"direction": "tool_call", "agent": high_tool({"session_injection_max": 0.8})},
		{"direction": "tool_call", "agent": high_tool({"session_injection_max": 0.79})},
		100,
	],
	[
		"injection-then-high-tool",
		{"direction": "tool_call", "agent": high_tool({}), "content": {"sensitivity": "public", "classes": [], "injection_score": 0.85}},
		{"direction": "tool_call", "agent": high_tool({"tool_risk": "medium"}), "content": {"sensitivity": "public", "classes": [], "injection_score": 0.85}},
		100,
	],
	[
		pan_nik,
		{"principal": personal, "content": {"sensitivity": "confidential", "classes": cls("PCI.PAN", 1)}},
		{"direction": "response", "principal": personal, "content": {"sensitivity": "confidential", "classes": cls("PCI.PAN", 1)}},
		90,
	],
	[
		pan_nik,
		{"destination": unsanctioned, "content": {"sensitivity": "confidential", "classes": cls("PCI.PAN", 1)}},
		{"destination": {"app_id": "x", "sanction": "tolerated", "region": "ID"}, "content": {"sensitivity": "confidential", "classes": cls("PCI.PAN", 1)}},
		90,
	],
	[
		pan_nik,
		{"principal": personal, "content": {"sensitivity": "confidential", "classes": cls("PII_ID.NIK", 10)}},
		{"principal": personal, "content": {"sensitivity": "confidential", "classes": cls("PII_ID.NIK", 9)}},
		90,
	],
	[
		pan_nik,
		{"destination": unsanctioned, "content": {"sensitivity": "confidential", "classes": array.concat(cls("PII_ID.NIK", 6), cls("PII_ID.NIK", 4))}},
		{"destination": unsanctioned, "content": {"sensitivity": "confidential", "classes": cls("PII_ID.NIK", 9)}},
		90,
	],
	[
		"unregistered-agent-high-tool",
		{"direction": "tool_call", "agent": high_tool({"agent_id": "rogue"})}, # not in the registry, whatever it claims
		{"direction": "tool_call", "agent": high_tool({})},
		90,
	],
	[
		"unregistered-agent-high-tool",
		{"direction": "tool_call", "agent": high_tool({"agent_id": "s"})}, # in the registry but suspended
		{"direction": "request", "agent": high_tool({"agent_id": "s"})},
		90,
	],
	[
		"agent-behavior-anomaly",
		{"direction": "tool_call", "agent": {"agent_id": "a", "tool": "crm.read", "tool_risk": "low", "registered": true, "behavior_anomalies": ["new_tool"]}},
		{"direction": "tool_call", "agent": {"agent_id": "a", "tool": "crm.read", "tool_risk": "low", "registered": true, "behavior_anomalies": []}},
		60,
	],
]

test_every_override if {
	every c in override_cases {
		fired := patch(c[1])
		risk.applied == [c[0]] with input as fired with data.wantimpres26.agents as registry
		risk.score == c[3] with input as fired with data.wantimpres26.agents as registry
		missed := risk.applied with input as patch(c[2]) with data.wantimpres26.agents as registry
		not c[0] in missed
	}
	# the table covers every configured override
	{c[0] | some c in override_cases} == object.keys(data.wantimpres26.risk.config.overrides)
}

test_override_scores_and_thresholds_are_data if {
	cfg := json.patch(data.wantimpres26.risk.config, [
		{"op": "replace", "path": "/overrides/pan-or-bulk-nik-to-personal-or-unsanctioned/nik_min", "value": 5},
		{"op": "replace", "path": "/overrides/pan-or-bulk-nik-to-personal-or-unsanctioned/score", "value": 95},
	])
	inp := patch({"principal": personal, "content": {"sensitivity": "confidential", "classes": cls("PII_ID.NIK", 5)}})
	risk.score == 95 with input as inp with data.wantimpres26.risk.config as cfg
}

test_floor_keeps_higher_base if {
	risk.base == 100 with input as patch({
		"principal": personal,
		"destination": {"app_id": "x", "sanction": "blocked", "region": "ID"},
		"content": {"sensitivity": "restricted", "classes": cls("PCI.PAN", 1), "exfil_score": 1, "volume_ratio": 99},
		"agent": {"agent_id": "a", "action": "financial", "registered": true},
	})
	risk.score == 100 with input as patch({
		"principal": personal,
		"destination": {"app_id": "x", "sanction": "blocked", "region": "ID"},
		"content": {"sensitivity": "restricted", "classes": cls("PCI.PAN", 1), "exfil_score": 1, "volume_ratio": 99},
		"agent": {"agent_id": "a", "action": "financial", "registered": true},
	})
}

test_set_beats_floor if {
	inp := patch({"destination": unsanctioned, "content": {"sensitivity": "public", "classes": array.concat(cls("SECRET.JWT", 1), cls("PCI.PAN", 1))}})
	risk.applied == [pan_nik, "secret-to-unsanctioned"] with input as inp
	risk.score == 100 with input as inp
}

# --- versioning and config validation ----------------------------------------------------------

test_decision_carries_risk_and_version if {
	r := decision.result with input as patch({"principal": personal, "content": {"sensitivity": "confidential", "classes": cls("PCI.PAN", 1)}})
	r.risk_score == 90
	r.risk_overrides == [pan_nik]
	r.risk_version == data.wantimpres26.risk.config.version
	json.match_schema(r, data.wantimpres26.schema.output)[0]
	bad := decision.result with input as {}
	bad.risk_version == data.wantimpres26.risk.config.version
}

test_policy_rules_can_use_risk_score if {
	rule := {"id": "hi", "when": [{"field": "risk_score", "op": "gte", "value": 90}], "action": "require_approval", "reason": "HIGH_RISK"}
	r := decision.result with input as patch({"principal": personal, "content": {"sensitivity": "confidential", "classes": cls("PCI.PAN", 1)}})
		with data.wantimpres26.rules.items as [rule]
	r.action == "require_approval"
}

test_builtin_config_valid if {
	count(risk.config_errors) == 0
}

test_invalid_config_reported if {
	bad := object.union(data.wantimpres26.risk.config, {
		"weights": {"sens": 0.5, "dest": 0.2, "attack": 0.15, "agency": 0.15, "volume": 0.1, "ident": 0.1},
		"levels": {"sensitivity": {"public": 0, "internal": 1.3, "confidential": 0.6, "restricted": 1}},
		"volume_steps": [{"ratio": 2, "f": -1}],
		"overrides": {
			"secret-to-unsanctioned": {"score": 150},
			"injection-then-high-tool": null,
		},
	})
	errs := risk.config_errors with data.wantimpres26.risk.config as bad
	print(errs)
	count(errs) == 5
	some e in errs
	startswith(e, "weights sum to 1.2")
}
