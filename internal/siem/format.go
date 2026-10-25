package siem

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Vendor/product/version in the CEF header; SIEM parsers key on these.
const (
	cefVendor  = "WANTIMPRES-26"
	cefProduct = "AI-SPM"
	cefVersion = "1.0"
)

var (
	headerEscaper    = strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\n", " ", "\r", " ")
	extensionEscaper = strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`, "\r", `\r`)
)

// CEF renders the record as an ArcSight CEF:0 line (header pipes and extension '=' escaped).
func (r Record) CEF() string {
	var b strings.Builder
	fmt.Fprintf(&b, "CEF:0|%s|%s|%s|%s|%s|%d|", cefVendor, cefProduct, cefVersion,
		headerEscaper.Replace(r.SignatureID), headerEscaper.Replace(r.Name), r.Severity)
	fmt.Fprintf(&b, "rt=%d", r.Time.UnixMilli())
	for _, f := range r.Fields {
		fmt.Fprintf(&b, " %s=%s", f.K, extensionEscaper.Replace(f.V))
	}
	return b.String()
}

// syslogSeverity maps CEF 0-10 onto RFC 5424 severities.
func syslogSeverity(cef int) int {
	switch {
	case cef >= 9:
		return 2 // critical
	case cef >= 7:
		return 3 // error
	case cef >= 4:
		return 4 // warning
	}
	return 5 // notice
}

// facility 13 = log audit (RFC 5424).
const facility = 13

// Syslog frames the CEF line as an RFC 5424 message with RFC 6587 octet counting (as RFC 5425 TLS requires).
func (r Record) Syslog(hostname string) []byte {
	msg := fmt.Sprintf("<%d>1 %s %s wantimpres26 - %s - %s", facility*8+syslogSeverity(r.Severity),
		r.Time.UTC().Format(time.RFC3339Nano), hostname, r.Source, r.CEF())
	return []byte(fmt.Sprintf("%d %s", len(msg), msg))
}

// flat is the JSON shape for HTTP sinks: the record header plus fields as keys (custom labels resolved).
func (r Record) flat() map[string]any {
	m := map[string]any{"id": r.ID, "time": r.Time.UTC().Format(time.RFC3339Nano), "source": r.Source,
		"signature_id": r.SignatureID, "name": r.Name, "severity": r.Severity}
	labels := map[string]string{}
	for _, f := range r.Fields {
		if strings.HasSuffix(f.K, "Label") {
			labels[strings.TrimSuffix(f.K, "Label")] = f.V
		}
	}
	for _, f := range r.Fields {
		if strings.HasSuffix(f.K, "Label") {
			continue
		}
		key := f.K
		if l, ok := labels[f.K]; ok {
			key = l
		}
		m[key] = f.V
	}
	return m
}

// HEC renders newline-joined Splunk HTTP Event Collector events.
func HEC(recs []Record) []byte {
	var b strings.Builder
	for _, r := range recs {
		ev, _ := json.Marshal(map[string]any{"time": float64(r.Time.UnixMilli()) / 1000, "source": "wantimpres26", "sourcetype": "wantimpres26:" + r.Source, "event": r.flat()})
		b.Write(ev)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// JSONArray renders the records as one JSON array (Logstash/Elastic HTTP input, Sentinel DCR, webhooks).
func JSONArray(recs []Record) []byte {
	out := make([]map[string]any, len(recs))
	for i, r := range recs {
		out[i] = r.flat()
	}
	b, _ := json.Marshal(out)
	return b
}
