// Package events is the decision_event contract between PEPs and the event pipeline (spec §5.1, §10.2):
// the versioned JSON Schema, the raw-content check both sides run, and the producer PEPs use.
package events

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"wantimpres26/internal/privacy"
)

const (
	Topic = "wantimpres26.decision_event.v1"
	// Subject follows the registry's TopicNameStrategy.
	Subject = Topic + "-value"
)

//go:embed decision_event.v1.json
var SchemaV1 string

// Event is decision_event v1. Field names and rules live in decision_event.v1.json; keep the two in step.
type Event struct {
	EventID       string   `json:"event_id"`
	TenantID      string   `json:"tenant_id"`
	TS            string   `json:"ts"` // RFC 3339
	TraceID       string   `json:"trace_id"`
	Channel       string   `json:"channel"`
	Direction     string   `json:"direction"`
	PrincipalID   string   `json:"principal_id"` // HMAC, never the raw identity
	AppID         string   `json:"app_id"`
	AgentID       string   `json:"agent_id,omitempty"`
	Action        string   `json:"action"`
	ReasonCodes   []string `json:"reason_codes"`
	MatchedRules  []string `json:"matched_rules,omitempty"`
	PolicyVersion string   `json:"policy_version"`
	RiskScore     int      `json:"risk_score"`
	RiskOverrides []string `json:"risk_overrides,omitempty"`
	RiskVersion   string   `json:"risk_version"`
	Classes       []Class  `json:"classes"`
	ContentHash   string   `json:"content_hash"`
	Snippet       string   `json:"snippet,omitempty"`
	SourceApp     string   `json:"source_app,omitempty"` // internal app that called the AI gateway (ticket 13)

	// PDP input metadata (no content), for replaying the decision in policy simulation. Pointers: absent ≠ zero.
	PrincipalType       string   `json:"principal_type,omitempty"`
	PrincipalGroups     []string `json:"principal_groups,omitempty"`
	PrincipalRisk       *float64 `json:"principal_risk,omitempty"`
	Device              string   `json:"device,omitempty"`
	AccountContext      string   `json:"account_context,omitempty"`
	Sanction            string   `json:"sanction,omitempty"`
	Region              string   `json:"region,omitempty"`
	TrainsOnData        *bool    `json:"trains_on_data,omitempty"`
	Sensitivity         string   `json:"sensitivity,omitempty"`
	InjectionScore      *float64 `json:"injection_score,omitempty"`
	JailbreakScore      *float64 `json:"jailbreak_score,omitempty"`
	ExfilScore          *float64 `json:"exfil_score,omitempty"`
	VolumeRatio         *float64 `json:"volume_ratio,omitempty"`
	Tokens              *int     `json:"tokens,omitempty"`
	AgentTool           string   `json:"agent_tool,omitempty"`
	ToolRisk            string   `json:"tool_risk,omitempty"`
	AgentAction         string   `json:"agent_action,omitempty"`
	AgentRegistered     *bool    `json:"agent_registered,omitempty"`
	SessionInjectionMax *float64 `json:"session_injection_max,omitempty"`
	HITLAvailable       *bool    `json:"hitl_available,omitempty"`
	ScopeViolations     *int     `json:"scope_violations,omitempty"`
	RateExceeded        *bool    `json:"rate_exceeded,omitempty"`
	ChainDepth          *int     `json:"chain_depth,omitempty"`
	BehaviorAnomalies   []string `json:"behavior_anomalies,omitempty"`
	MCPServer           string   `json:"mcp_server,omitempty"`
	ToolHash            string   `json:"tool_hash,omitempty"`
	ApprovalID          string   `json:"approval_id,omitempty"`     // the human approval this call used (FR-AGT-6)
	MemoryWrite         *bool    `json:"memory_write,omitempty"`    // FR-AGT-9 provenance of memory writes
	ContentOrigin       string   `json:"content_origin,omitempty"`  // user | tool_result
	ContentSources      []string `json:"content_sources,omitempty"` // server/tool outputs the session read before
	L2                  *L2      `json:"l2,omitempty"`              // the L2 model's report, shadow mode (ticket 49)
}

// L2 is what the L2 model said about the content: classes and a score, never text or offsets.
type L2 struct {
	Model          string   `json:"model,omitempty"`
	Mode           string   `json:"mode"`   // shadow | enforce
	Status         string   `json:"status"` // ok | timeout | error | skipped | unavailable
	LatencyMS      float64  `json:"latency_ms"`
	Classes        []Class  `json:"classes,omitempty"`
	InjectionScore *float64 `json:"injection_score,omitempty"`
}

// ClassType reports whether t is a class type the schema accepts (e.g. PII_ID.NIK).
func ClassType(t string) bool { return classType.MatchString(t) }

var classType = regexp.MustCompile(`^(PII_ID|FIN|PCI|PHI|SECRET|CODE|LEGAL_HR|CUSTOM)\.[A-Z0-9_]+$`)

// PDPInput rebuilds the canonical PDP input (policy/wantimpres26/schema) from the event's metadata. ok is false when the
// event lacks what every decision needs (sensitivity, sanction, region): such events cannot be replayed.
func (e Event) PDPInput() (in map[string]any, ok bool) {
	if e.Sensitivity == "" || e.Sanction == "" || e.Region == "" {
		return nil, false
	}
	put := func(m map[string]any, k string, v any) {
		switch v := v.(type) {
		case string:
			if v != "" {
				m[k] = v
			}
		case *float64:
			if v != nil {
				m[k] = *v
			}
		case *bool:
			if v != nil {
				m[k] = *v
			}
		case *int:
			if v != nil {
				m[k] = *v
			}
		case []string:
			if len(v) > 0 {
				m[k] = v
			}
		}
	}
	ptype := e.PrincipalType
	if ptype == "" {
		ptype = "user"
	}
	principal := map[string]any{"type": ptype, "id": e.PrincipalID}
	put(principal, "groups", e.PrincipalGroups)
	put(principal, "risk", e.PrincipalRisk)
	put(principal, "device", e.Device)
	put(principal, "account_context", e.AccountContext)
	dest := map[string]any{"app_id": e.AppID, "sanction": e.Sanction, "region": e.Region}
	put(dest, "trains_on_data", e.TrainsOnData)
	classes := make([]any, 0, len(e.Classes))
	for _, c := range e.Classes {
		conf := c.Confidence
		if conf == 0 {
			conf = 1 // omitted confidence: the PEP reported the class, so treat it as certain
		}
		classes = append(classes, map[string]any{"type": c.Type, "count": c.Count, "confidence": conf})
	}
	content := map[string]any{"sensitivity": e.Sensitivity, "classes": classes}
	put(content, "injection_score", e.InjectionScore)
	put(content, "jailbreak_score", e.JailbreakScore)
	put(content, "exfil_score", e.ExfilScore)
	put(content, "volume_ratio", e.VolumeRatio)
	put(content, "tokens", e.Tokens)
	in = map[string]any{"channel": e.Channel, "direction": e.Direction, "principal": principal, "destination": dest, "content": content}
	if e.AgentID != "" {
		agent := map[string]any{"agent_id": e.AgentID}
		put(agent, "tool", e.AgentTool)
		put(agent, "tool_risk", e.ToolRisk)
		put(agent, "action", e.AgentAction)
		put(agent, "registered", e.AgentRegistered)
		put(agent, "session_injection_max", e.SessionInjectionMax)
		put(agent, "hitl_available", e.HITLAvailable)
		put(agent, "scope_violations", e.ScopeViolations)
		put(agent, "rate_exceeded", e.RateExceeded)
		put(agent, "chain_depth", e.ChainDepth)
		if len(e.BehaviorAnomalies) > 0 {
			agent["behavior_anomalies"] = e.BehaviorAnomalies
		}
		put(agent, "mcp_server", e.MCPServer)
		put(agent, "tool_hash", e.ToolHash)
		if e.ApprovalID != "" {
			agent["approval_granted"] = true
		}
		put(agent, "writes_memory", e.MemoryWrite)
		in["agent"] = agent
	}
	return in, true
}

type Class struct {
	Type       string  `json:"type"`
	Count      int     `json:"count"`
	Confidence float64 `json:"confidence,omitempty"`
}

// Compile parses a registered JSON Schema.
func Compile(schema string) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(schema))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("schema.json", doc); err != nil {
		return nil, err
	}
	return c.Compile("schema.json")
}

// Long digit runs in a snippet are unredacted identifiers: NIK has 16 digits, a PAN 13-19 (spaces/dashes allowed).
var digitRun = regexp.MustCompile(`\d(?:[ -]?\d){11,}`)

// Rejection reasons, used as the events_rejected_total label.
const (
	RejectNotJSON    = "not_json"
	RejectRawContent = "raw_content"
	RejectUnredacted = "unredacted_snippet"
	RejectSchema     = "schema"
)

// Check returns "" when payload is a valid event, else the rejection reason. Raw content is checked before the
// schema so it is counted as raw_content, not hidden among generic schema failures.
func Check(payload []byte, schema *jsonschema.Schema) string {
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil {
		return RejectNotJSON
	}
	if hasForbiddenField(v) {
		return RejectRawContent
	}
	if m, ok := v.(map[string]any); ok {
		if s, ok := m["snippet"].(string); ok && digitRun.MatchString(s) {
			return RejectUnredacted
		}
	}
	if schema.Validate(v) != nil {
		return RejectSchema
	}
	return ""
}

func hasForbiddenField(v any) bool {
	switch v := v.(type) {
	case map[string]any:
		for k, child := range v {
			if privacy.IsForbidden(k) || hasForbiddenField(child) {
				return true
			}
		}
	case []any:
		for _, child := range v {
			if hasForbiddenField(child) {
				return true
			}
		}
	}
	return false
}

// Marshal validates e against the embedded schema so a PEP can never emit an event the pipeline would reject.
func Marshal(e Event, schema *jsonschema.Schema) ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	if reason := Check(b, schema); reason != "" {
		return nil, fmt.Errorf("decision_event rejected: %s", reason)
	}
	return b, nil
}
