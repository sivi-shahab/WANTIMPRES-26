# METADATA
# title: AI-SPM policy decision point
# description: |
#   Generic engine: rules are data (data.wantimpres26.rules.items), evaluated against the canonical input
#   (data.wantimpres26.schema.input). The strictest matching action wins (DEC-2) and obligations are merged.
#   Rule shape: {id, when: [{field, op, value}], action, obligations?, reason, mode?: enforce|monitor}.
package wantimpres26.decision

import rego.v1

import data.wantimpres26.agent
import data.wantimpres26.cond
import data.wantimpres26.dest
import data.wantimpres26.risk

# DEC-2 precedence, strictest last.
rank := {
	"allow": 0,
	"warn": 1,
	"redact": 2,
	"tokenize": 3,
	"require_approval": 4,
	"quarantine": 5,
	"block": 6,
}

valid_input if json.match_schema(input, data.wantimpres26.schema.input)[0]

# Malformed input fails closed: a PEP bug must show up as blocks, never as silent allows.
result := {
	"action": "block",
	"obligations": [],
	"reason_codes": ["INPUT_SCHEMA_INVALID"],
	"matched_rules": [],
	"monitor_rules": [],
	"exempted_rules": [],
	"destination": object.get(input, "destination", {}),
	"policy_id": "wantimpres26.decision",
	"policy_version": data.wantimpres26.rules.version,
	# A malformed input is a PEP bug, not user risk: alert on INPUT_SCHEMA_INVALID, do not page the SOC.
	"risk_score": 0,
	"risk_overrides": [],
	"risk_version": data.wantimpres26.risk.config.version,
} if not valid_input

# The gateways validate their input in Go against this same schema, compiled once, and ask for checked; any input
# that fails there comes to result instead (mcpgw.OPA.Decide, ticket 47). json.match_schema compiles the schema on
# every call, about 40% of a decision. Every other caller asks for result, which validates here.
checked := {
	"action": action,
	"obligations": sort(obligations),
	"reason_codes": sort({r.reason | some r in enforced}),
	"matched_rules": sort({r.id | some r in enforced}),
	"monitor_rules": sort({r.id | some r in monitored}),
	"exempted_rules": sort({r.id | some r in exempted}),
	"destination": dest.destination,
	"policy_id": "wantimpres26.decision",
	"policy_version": data.wantimpres26.rules.version,
	"risk_score": risk.score,
	"risk_overrides": risk.applied,
	"risk_version": data.wantimpres26.risk.config.version,
}

result := checked if valid_input

matched contains rule if {
	some rule in data.wantimpres26.rules.items
	every c in rule.when {
		cond.holds(c.op, value(c.field), c.value)
	}
}

enforced contains r if {
	some r in matched
	object.get(r, "mode", "enforce") == "enforce"
	not r in exempted
}

# FR-POL-7: an approved exception lifts the listed rules for its scope until expires_at (RFC 3339). Exempted rules
# are reported in the result, never silently dropped. Every scope key must match; an empty scope matches nothing.
exempted contains r if {
	some r in matched
	object.get(r, "mode", "enforce") == "enforce"
	some ex in data.wantimpres26.exceptions.items
	r.id in ex.rules
	time.now_ns() < time.parse_rfc3339_ns(ex.expires_at)
	count(ex.scope) > 0
	every k, v in ex.scope {
		in_scope(k, v)
	}
}

# FR-AGT-6: an approval granted by a human (claimed once by the MCP gateway for exactly this call) lifts the
# require_approval rules of this decision only; stricter rules still apply.
exempted contains r if {
	some r in matched
	r.action == "require_approval"
	input.agent.approval_granted == true
}

# FR-INC-5 containment: the SOC blocked this principal from this app (data.wantimpres26.containment, released by the
# incident module). Not a rule in the rule set, so no policy edit or exception can lift it; only the SOC.
enforced contains {"id": "containment.block", "action": "block", "reason": "CONTAINMENT_BLOCK"} if {
	some b in data.wantimpres26.containment.blocks
	b.principal_id == input.principal.id
	b.app_id == dest.destination.app_id
	time.now_ns() < time.parse_rfc3339_ns(b.expires_at)
}

in_scope("principal_id", v) if input.principal.id == v

in_scope("group", v) if v in object.get(input.principal, "groups", [])

in_scope("app_id", v) if dest.destination.app_id == v

in_scope("agent_id", v) if input.agent.agent_id == v

monitored contains r if {
	some r in matched
	object.get(r, "mode", "enforce") == "monitor"
}

top := max({rank[r.action] | some r in enforced} | {0})

action := a if {
	some a, n in rank
	n == top
}

obligations contains o if {
	some r in enforced
	some o in object.get(r, "obligations", [])
}

# risk_score is computed by wantimpres26.risk, never supplied by the PEP.
value("risk_score") := risk.score

# destination.* comes from the catalog-corrected destination (wantimpres26.dest).
value(field) := object.get(dest.destination, array.slice(path, 1, count(path)), null) if {
	field != "risk_score"
	path := split(field, ".")
	path[0] == "destination"
}

# agent.* comes from the registry-corrected agent (wantimpres26.agent).
value(field) := object.get(agent.agent, array.slice(path, 1, count(path)), null) if {
	path := split(field, ".")
	path[0] == "agent"
}

value(field) := object.get(input, split(field, "."), null) if {
	field != "risk_score"
	not startswith(field, "destination.")
	not startswith(field, "agent.")
}

# Rule-set validation. The bundle builder refuses to publish while this is non-empty, so a typo in a
# rule can never turn into a rule that silently never matches.
rule_errors contains sprintf("duplicate id %s", [id]) if {
	some id in {r.id | some r in data.wantimpres26.rules.items}
	count([r | some r in data.wantimpres26.rules.items; r.id == id]) > 1
}

rule_errors contains sprintf("%v: unknown action %v", [r.id, r.action]) if {
	some r in data.wantimpres26.rules.items
	not r.action in object.keys(rank)
}

rule_errors contains sprintf("%v: unknown op %v", [r.id, c.op]) if {
	some r in data.wantimpres26.rules.items
	some c in r.when
	not c.op in cond.ops
}

rule_errors contains sprintf("%v: empty when", [r.id]) if {
	some r in data.wantimpres26.rules.items
	count(object.get(r, "when", [])) == 0
}

rule_errors contains sprintf("%v: missing reason", [r.id]) if {
	some r in data.wantimpres26.rules.items
	not r.reason
}

rule_errors contains sprintf("%v: unknown mode %v", [r.id, r.mode]) if {
	some r in data.wantimpres26.rules.items
	not r.mode in {"enforce", "monitor"}
	r.mode
}
