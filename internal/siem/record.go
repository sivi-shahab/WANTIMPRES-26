// Package siem exports decision events, incidents and platform security telemetry to the bank's SIEM
// (spec §11, §12.3): CEF over syslog (RFC 5424/5425) and HTTP (Splunk HEC or a JSON array), with retry and a
// dead-letter queue. Records are built from allowlisted fields only, never by forwarding an event or audit
// target whole, and every record is checked for content before it leaves.
package siem

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/events"
	"wantimpres26/internal/privacy"
)

// Record is one SIEM message, independent of the wire format.
type Record struct {
	Source      string    `json:"source"` // decision | audit | alert
	ID          string    `json:"id"`     // stable: lets the SIEM drop duplicates after a retry
	Time        time.Time `json:"time"`
	SignatureID string    `json:"signature_id"`
	Name        string    `json:"name"`
	Severity    int       `json:"severity"` // CEF 0-10
	Fields      []Field   `json:"fields"`
}

// Field is a CEF extension key and its value. Keys are CEF keys (with their *Label pairs for custom fields).
// Opaque marks machine identifiers (UUIDs, hashes, fingerprints): they must look like one, and are exempt from the
// digit-run check that would otherwise trip on a long all-digit hex string.
type Field struct {
	K, V   string
	Opaque bool
}

var opaqueRe = regexp.MustCompile(`^[0-9a-fA-F:-]+$`)

func id(k, v string) Field { return Field{K: k, V: v, Opaque: true} }

// digitRun is an identifier that escaped redaction (NIK 16 digits, PAN 13-19), as in events.Check.
var digitRun = regexp.MustCompile(`\d(?:[ -]?\d){11,}`)

// clean masks identifier-like digit runs in free text (an analyst may paste a NIK into a justification).
func clean(s string) string { return digitRun.ReplaceAllString(s, "[REDACTED:DIGITS]") }

// scrub copies an audit target, dropping forbidden content keys at any depth and masking digit runs in strings.
func scrub(v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, x := range v {
			if privacy.IsForbidden(k) {
				out[k] = "[REDACTED]"
				continue
			}
			out[k] = scrub(x)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = scrub(x)
		}
		return out
	case string:
		return clean(v)
	}
	return v
}

func custom(fields []Field, n int, label, value string, opaque bool) []Field {
	if value == "" {
		return fields
	}
	return append(fields, Field{K: fmt.Sprintf("cs%dLabel", n), V: label}, Field{K: fmt.Sprintf("cs%d", n), V: value, Opaque: opaque})
}

// FromEvent maps a decision event. Exported: ids, hashes, decision, classes, scores. Not exported: the snippet,
// even redacted (SIEM access and retention are wider than ours; spec §10.2 minimization).
func FromEvent(e events.Event) Record {
	ts, _ := time.Parse(time.RFC3339Nano, e.TS)
	classes := make([]string, 0, len(e.Classes))
	for _, c := range e.Classes {
		classes = append(classes, fmt.Sprintf("%s:%d", c.Type, c.Count))
	}
	f := []Field{
		id("externalId", e.EventID), {K: "act", V: e.Action}, {K: "cat", V: e.Channel}, id("suid", e.PrincipalID),
		{K: "cn1Label", V: "riskScore"}, {K: "cn1", V: fmt.Sprint(e.RiskScore)}, {K: "flexString1Label", V: "tenant"}, id("flexString1", e.TenantID),
	}
	switch e.Direction {
	case "request", "tool_call":
		f = append(f, Field{K: "deviceDirection", V: "1"})
	case "response", "tool_result":
		f = append(f, Field{K: "deviceDirection", V: "0"})
	}
	f = custom(f, 1, "destinationApp", clean(e.AppID), false)
	f = custom(f, 2, "reasonCodes", strings.Join(e.ReasonCodes, ","), false)
	f = custom(f, 3, "policyVersion", e.PolicyVersion, false)
	f = custom(f, 4, "traceId", e.TraceID, true)
	f = custom(f, 5, "classes", strings.Join(classes, ","), false)
	f = custom(f, 6, "agent", clean(e.AgentID), false)
	return Record{Source: "decision", ID: e.EventID, Time: ts, SignatureID: "decision." + e.Action,
		Name: fmt.Sprintf("AI %s to %s", e.Action, e.AppID), Severity: min(10, (e.RiskScore+5)/10), Fields: f}
}

// auditSeverity: what a SOC should look at first.
func auditSeverity(action string) int {
	switch {
	case strings.HasPrefix(action, "breakglass."), strings.HasSuffix(action, ".denied"), action == "incident.breach.escalate":
		return 9
	case strings.Contains(action, "unmask"), action == "access.sensitive", strings.HasPrefix(action, "identity.role."),
		action == "policy.version.approve", action == "policy.rollback", action == "policy.retire",
		strings.HasPrefix(action, "policy.exception.approve"), action == "incident.open", action == "incident.escalate",
		strings.HasPrefix(action, "incident.breach."), action == "incident.contain":
		return 7
	}
	return 3
}

// FromAudit maps an audit log entry: policy changes, unmask, role changes, break-glass, incidents (spec §12.3).
// The entry hash goes along so the SIEM copy can be checked against the chain.
func FromAudit(e audit.Entry) Record {
	target, _ := json.Marshal(scrub(map[string]any(e.Target)))
	f := []Field{
		{K: "externalId", V: fmt.Sprintf("audit-%d", e.Seq)}, {K: "suser", V: clean(e.Actor)}, {K: "act", V: e.Action},
		{K: "flexString1Label", V: "tenant"}, id("flexString1", e.TenantID),
	}
	f = custom(f, 1, "target", string(target), false)
	f = custom(f, 2, "auditHash", e.Hash, true)
	f = custom(f, 3, "auditSeq", fmt.Sprint(e.Seq), false)
	return Record{Source: "audit", ID: fmt.Sprintf("audit-%d", e.Seq), Time: e.TS, SignatureID: "audit." + e.Action,
		Name: e.Action, Severity: auditSeverity(e.Action), Fields: f}
}

// Alert is one Alertmanager webhook alert (bundle signature failures and the other alerts in deploy/cluster).
type Alert struct {
	Status      string            `json:"status"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    time.Time         `json:"startsAt"`
	Fingerprint string            `json:"fingerprint"`
}

func FromAlert(a Alert) Record {
	sev := map[string]int{"critical": 9, "warning": 6, "info": 3}[a.Labels["severity"]]
	labels, _ := json.Marshal(scrub(toAny(a.Labels)))
	f := []Field{{K: "externalId", V: clean(a.Fingerprint + ":" + a.Status + ":" + a.StartsAt.UTC().Format(time.RFC3339))},
		{K: "outcome", V: a.Status}, {K: "msg", V: clean(a.Annotations["summary"])}}
	f = custom(f, 1, "labels", string(labels), false)
	return Record{Source: "alert", ID: f[0].V, Time: a.StartsAt, SignatureID: "alert." + a.Labels["alertname"],
		Name: a.Labels["alertname"], Severity: sev, Fields: f}
}

func toAny(m map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ErrContent marks a record that still looks like it carries content; it goes to the DLQ, never to the SIEM.
var ErrContent = errors.New("record looks like content")

// Check is the last gate before any sink: no forbidden field names or labels, opaque fields really are
// identifiers, and no identifier-like digit run anywhere else.
func (r Record) Check() error {
	for _, f := range r.Fields {
		switch {
		case privacy.IsForbidden(f.K), strings.HasSuffix(f.K, "Label") && privacy.IsForbidden(f.V):
			return fmt.Errorf("%w: field %s", ErrContent, f.K)
		case f.Opaque && !opaqueRe.MatchString(f.V):
			return fmt.Errorf("%w: %s is not an identifier", ErrContent, f.K)
		case !f.Opaque && digitRun.MatchString(f.V):
			return fmt.Errorf("%w: digits in %s", ErrContent, f.K)
		}
	}
	return nil
}
