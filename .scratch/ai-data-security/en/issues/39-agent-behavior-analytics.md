<!-- source-sha256: 5095113c670c2980 -->
# 39: Agent behavior analytics

Status: needs-gitlab-run
Type: task
Priority: P2
Milestone: M4
Blocked by: 28
Spec: `../spec.md` §3.1 P2; ASI08, ASI10

## Context
Detecting rogue agents and cascading failures from tool call patterns.

## Scope
- Baseline of tool call sequences per agent.
- Anomaly detection (new tool, volume spike, unusual sequence) → event and risk signal.

## Acceptance criteria
- [x] Evaluation on synthetic rogue agent scenarios. *(`TestRogueAgentEval`: three agents (cs-bot, payments-bot, report-bot) run a normal Markov workflow for 5 simulated working days, 10 seeds. Four scenarios are injected into copies of the baseline: a bulk export that was never used (`new_tool`), a transfer without recipient validation (`rare_sequence`), a 120x report query loop (`volume_spike`, ASI08), and a burst of account lookups (`volume_spike`). All caught in 10/10 seeds. Benign after a 5-day baseline: 0 of 21,442 calls flagged; 1-day baseline: 0.046%.)*
- [x] Alert connected to an incident. *(The gateway sends `agent.behavior_anomalies` to the PDP and to the decision event. The risk floor `agent-behavior-anomaly` = 60 ≥ `incident.MinRisk` (40), so the event opens an incident. `TestBehaviorThroughGateway` uses the real risk policy; the `PDPInput` replay carries the same signal.)*

## Decisions
- **Per-agent baseline, in-memory in the gateway:** tools ever used, tool→tool transitions per trace (session), and call rate per minute (EWMA). Scored only after a 50-call warm-up; transitions are scored once the source tool has ≥ 20 outgoing transitions; spike = > max(5× the usual rate, 20) calls/minute. The baseline keeps learning, so a new tool is flagged on its first calls, not forever.
- **All attempts are counted**, including blocked ones: a rogue agent is visible from what it attempts.
- **Signal, not block:** an anomaly raises risk to the floor of 60 (incident). Blocking remains the job of policy rules.
- **Known limits:** the profile is per replica and lost on restart (warm-up again). Persist the profile or move the analysis to an event stream consumer if agents must be supervised from the first call after a deploy.
