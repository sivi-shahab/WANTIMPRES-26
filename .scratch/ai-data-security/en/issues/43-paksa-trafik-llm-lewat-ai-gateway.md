<!-- source-sha256: 06b7b89ef1671bc2 -->
# 43: Force LLM traffic through the AI gateway (egress + bypass detection)

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M2
Blocked by: 13
Spec: `../spec.md` §5.4; `docs/threat-model.md` §4.1, G4

## Context
Threat model (ticket 02) G4: without egress rules, the AI gateway is optional. An app can call an LLM provider directly with a developer's personal key.

## Scope
- Egress rules (firewall/SWG, managed by the bank's network team) that allow the LLM provider API domains in the catalog only from the AI gateway's egress IP. The repo provides the domain list from the catalog (`hosting_region`, API category).
- Posture signal: direct traffic from the server subnet to a provider API domain (from SWG/DNS logs, ticket 03) → event + posture finding.

## Acceptance criteria
- [x] Export of the provider API domain list from the catalog, with a test. *(`catalog.ProviderDomains` and `GET /catalog/egress` (JSON or `?format=txt`, `config.read`). Tested in `TestProviderDomains` and `TestGatewayBypassAPI`: provider domains are present, apps without an API are excluded, the list is sorted and unique, subdomains already covered by a parent are dropped, matching works on subdomains, and suffix tricks do not fool it.)*
- [x] Direct traffic to a provider in synthetic logs produces a "gateway bypass" posture finding. *(`TestGatewayBypass` (shadow) uses synthetic Squid/BIND/JSONL logs: server → `api.openai.com`, `api.anthropic.com`, and `generativelanguage.googleapis.com` are detected. Not reported: the gateway egress IP, workstations, non-AI hosts, apps without an API, and logs without a client IP. Findings are sent through `POST /catalog/gateway-bypass`, then appear in `GET /posture` (`gateway_bypass` and the target-0 metric, `TestReconciliation`). Every new server/domain pair is audited (`catalog.gateway_bypass` → SIEM).)*
- [x] The egress rules runbook is handed to the network team. *(`docs/runbooks/egress-ai-gateway.md`: domain list, rules table, test, detection from logs, and follow-up. The handover to the network team is done by a human.)*

## Decisions
- **Exported domains:** all domains from catalog apps that have `api_endpoints`, including their web domains (a server has no reason to open `chatgpt.com`). Subdomains already covered by a parent domain are dropped. Apps without an API (image, meeting, etc.) remain the SWG's concern for users, not part of this server egress rule. The source is the effective catalog (feed + local apps), so local apps added by the bank are exported too.
- **Detection:** `shadow-baseline -servers <CIDR> -gateways <IP>` flags clients in the server subnet (other than the gateway egress IP) that access provider domains. Log records now carry `Client` (IP). Squid and BIND always have it; JSONL via the `client_ip` field (mappable). Server addresses are reported as-is because they are infrastructure, not people. Users and workstations are still HMAC'd.
- **Path to posture:** shadow-baseline remains a batch CLI (like ticket 03). Its findings are sent to `POST /catalog/gateway-bypass` (`config.write`) and stored per server+domain (`catalog.gateway_bypass`, requests summed). New pairs are audited (SIEM event), and posture shows pairs with traffic within 30 days plus a server count metric (target 0).

## Local verification results (2026-10-10)
- The touched packages (`catalog`, `shadow`, `posture` with OpenSearch 2.19.3, `compliance`) are green. `go vet ./...` and golangci-lint v2.5.0 0 issues.
- `go test -race ./...`: three timing tests in packages not touched by this ticket (`agents.TestKillSwitchPropagation`, `mcpgw.TestKillSwitch`, the `policysvc` timeout) failed when the host load average was ~50 from parallel work. They need to be rerun on a quiet host or CI.

## Remaining
- The firewall/SWG rules are installed by the network team (runbook). The repo cannot verify them.
- Scheduling shadow-baseline and POSTing its findings (a CronJob) has not been built. For now it is manual per the runbook.
- The threat model G4 status needs updating after the egress rules are installed.
