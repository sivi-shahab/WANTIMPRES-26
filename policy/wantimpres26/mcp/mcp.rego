# METADATA
# description: |
#   Registry lookup for the MCP gateway (ticket 28): the agent whose workload identity (FR-AGT-2) the gateway
#   authenticated, with its tool allow-list and scopes. Undefined for an identity the registry does not know.
package wantimpres26.mcp

import rego.v1

agent := object.union(entry, {"agent_id": id}) if {
	some id, entry in data.wantimpres26.agents.items
	entry.identity == input.identity
}

# The server's tool definitions with status and pinned hash: the gateway's fallback for filtering tools/list
# when the registry cannot be reached.
tools := {name: t |
	some key, t in data.wantimpres26.mcp_tools.items
	[server, name] := split_once(key)
	server == input.server
}

split_once(key) := [substring(key, 0, i), substring(key, i + 1, -1)] if i := indexof(key, "/")
