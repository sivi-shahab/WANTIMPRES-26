# METADATA
# description: |
#   FR-RISK-1/2 event risk score, 0-100. Weights, factor levels, override scores and thresholds are data
#   (data.wantimpres26.risk.config); the fixed FR-RISK-2 override conditions are Rego. Both ship, versioned, in the signed
#   bundle with the policy, so they are simulated with it and risk_version lands in every decision.
#   score = min(100, round(100 x sum(w_i x f_i))); set_override fixes the score, floor_override raises it.
package wantimpres26.risk

import rego.v1

import data.wantimpres26.agent
import data.wantimpres26.dest

cfg := data.wantimpres26.risk.config

levels := cfg.levels

account := object.get(input.principal, "account_context", "corporate")

f_sens := object.get(levels.sensitivity, input.content.sensitivity, 0)

# A personal account at the destination is as bad as a blocked app.
f_dest := max({object.get(levels.sanction, dest.destination.sanction, 0), object.get(levels.account_context, account, 0)})

f_attack := max({
	object.get(input.content, "injection_score", 0),
	object.get(input.content, "jailbreak_score", 0),
	object.get(input.content, "exfil_score", 0),
})

# Explicit action kind wins; otherwise fall back to the tool's risk tier. No agent, no agency.
f_agency := object.get(levels.action, input.agent.action, 0) if input.agent.action

else := object.get(levels.tool_risk, input.agent.tool_risk, 0) if input.agent.tool_risk

else := 0

# Log-scaled without a log builtin: the highest step whose ratio to the principal's baseline is reached.
f_volume := max({s.f | some s in cfg.volume_steps; object.get(input.content, "volume_ratio", 0) >= s.ratio} | {0})

f_ident := max({
	object.get(levels.device, object.get(input.principal, "device", "managed"), 0),
	object.get(levels.account_context, account, 0),
	object.get(input.principal, "risk", 0),
})

factors := {
	"sens": f_sens,
	"dest": f_dest,
	"attack": f_attack,
	"agency": f_agency,
	"volume": f_volume,
	"ident": f_ident,
}

w := cfg.weights

base := min({100, round(100 * (((((w.sens * f_sens + w.dest * f_dest) + w.attack * f_attack) + w.agency * f_agency) + w.volume * f_volume) + w.ident * f_ident))})

# FR-RISK-2 critical overrides. The list is fixed by the spec, so the logic is Rego (indexable, fast); scores
# and thresholds are data (cfg.overrides) so calibration (ticket 25) is a data change in the signed bundle.
ov := cfg.overrides

outbound if input.direction in {"request", "tool_call"}

non_sanctioned := {"unsanctioned", "blocked", "under_review"}

high_tool_call if {
	input.direction == "tool_call"
	input.agent.tool_risk == "high"
}

has_class(pattern) if glob.match(pattern, ["."], input.content.classes[_].type)

nik_count := sum([c.count | some c in input.content.classes; c.type == "PII_ID.NIK"])

to_personal_or_unsanctioned if account == "personal"

to_personal_or_unsanctioned if dest.destination.sanction in non_sanctioned

set_override["secret-to-unsanctioned"] := ov["secret-to-unsanctioned"].score if {
	outbound
	dest.destination.sanction != "sanctioned"
	has_class("SECRET.*")
}

set_override["injection-then-high-tool"] := ov["injection-then-high-tool"].score if {
	high_tool_call
	max({object.get(input.agent, "session_injection_max", 0), object.get(input.content, "injection_score", 0)}) >= ov["injection-then-high-tool"].injection_min
}

floor_override["pan-or-bulk-nik-to-personal-or-unsanctioned"] := o.score if {
	o := ov["pan-or-bulk-nik-to-personal-or-unsanctioned"]
	outbound
	to_personal_or_unsanctioned
	pan_or_bulk_nik(o.nik_min)
}

pan_or_bulk_nik(_) if has_class("PCI.PAN")

pan_or_bulk_nik(n) if nik_count >= n

# registered omitted = not registered (fail closed).
floor_override["unregistered-agent-high-tool"] := ov["unregistered-agent-high-tool"].score if {
	high_tool_call
	agent.registered != true
}

# Ticket 39 (ASI08, ASI10): a tool call outside the agent's behaviour baseline is at least an incident.
floor_override["agent-behavior-anomaly"] := ov["agent-behavior-anomaly"].score if {
	input.direction == "tool_call"
	count(object.get(input.agent, "behavior_anomalies", [])) > 0
}

applied := sort(object.keys(set_override) | object.keys(floor_override))

set_scores := {s | some s in set_override}

floor_scores := {s | some s in floor_override}

score := max(set_scores) if count(set_scores) > 0

else := max(floor_scores | {base})

# Config validation; the bundle builder refuses to publish while non-empty (with decision.rule_errors).
config_errors contains sprintf("weights sum to %v, want 1", [s]) if {
	s := sum([w | some w in cfg.weights])
	abs(s - 1) > 0.000001
}

config_errors contains sprintf("weight keys %v, want %v", [object.keys(cfg.weights), object.keys(factors)]) if {
	object.keys(cfg.weights) != {"sens", "dest", "attack", "agency", "volume", "ident"}
}

config_errors contains sprintf("%v: level %v outside [0,1]", [t, v]) if {
	some t, table in cfg.levels
	some v in table
	not between01(v)
}

config_errors contains sprintf("volume step %v outside [0,1]", [s]) if {
	some s in cfg.volume_steps
	not between01(s.f)
}

config_errors contains sprintf("override %v: missing or score outside [0,100]", [id]) if {
	some id in {"secret-to-unsanctioned", "injection-then-high-tool", "pan-or-bulk-nik-to-personal-or-unsanctioned", "unregistered-agent-high-tool", "agent-behavior-anomaly"}
	not valid_score(object.get(cfg.overrides, [id, "score"], null))
}

valid_score(v) if {
	is_number(v)
	v >= 0
	v <= 100
}

between01(v) if {
	is_number(v)
	v >= 0
	v <= 1
}
