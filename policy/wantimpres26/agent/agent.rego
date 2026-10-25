# METADATA
# description: |
#   The agent the PDP decides on. The agent registry (data.wantimpres26.agents, ticket 27) is the source of truth:
#   registered means "in the registry and active"; whatever the PEP claims about registration does not count.
#   Unknown agents are "unregistered", quarantined/suspended ones keep that status for the rules to act on.
#   The registry's tool allow-list decides tool_allowed and its tool risk replaces the PEP's (FR-AGT-4): an
#   agent outside the registry has no allow-list, so it may call no tool. Through the MCP gateway, the tool's
#   definition must also be approved and unchanged (tool_approved).
package wantimpres26.agent

import rego.v1

entry := data.wantimpres26.agents.items[input.agent.agent_id]

status := entry.status if entry

else := "unregistered"

registered := status == "active"

tool := t if {
	some t in entry.tools
	t.name == input.agent.tool
}

tool_allowed if tool

else := false

risk_tier := entry.risk_tier if entry

else := "unknown"

# MCP tool definitions (ticket 29): callable only while approved and, when the gateway saw what the server serves
# now (tool_hash), only while that is the pinned definition. A rug pull is blocked before any release lands.
mcp_tool := data.wantimpres26.mcp_tools.items[concat("/", [input.agent.mcp_server, input.agent.tool])]

tool_approved if {
	mcp_tool.status == "approved"
	not definition_changed
}

else := false

definition_changed if {
	input.agent.tool_hash
	input.agent.tool_hash != mcp_tool.hash
}

# FR-AGT-7 kill switch (data.wantimpres26.kills, released by the registry): global, or this agent, tool or app.
default killed := false

killed if data.wantimpres26.kills.global

killed if data.wantimpres26.kills.agent[input.agent.agent_id]

killed if data.wantimpres26.kills.tool[input.agent.tool]

killed if data.wantimpres26.kills.app[input.destination.app_id]

registry := {
	"registered": registered, "status": status, "risk_tier": risk_tier, "tool_allowed": tool_allowed,
	"tool_approved": tool_approved, "killed": killed,
}

# The registry's tool entry also says whether the tool writes memory (FR-AGT-9): the PEP's claim does not count.
agent := object.union(object.union(input.agent, registry), {"tool_risk": tool.risk, "writes_memory": object.get(tool, "writes_memory", false)}) if {
	input.agent
	tool
} else := object.union(input.agent, registry) if input.agent

else := {}
