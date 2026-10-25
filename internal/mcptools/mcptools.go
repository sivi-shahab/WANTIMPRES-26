// Package mcptools pins and scans MCP tool definitions (spec §4.8 FR-AGT-3: tool poisoning and rug pulls). The
// MCP gateway hashes what tools/list returns; the agent registry scans each new or changed definition and keeps
// it out of reach until approved.
package mcptools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"

	"wantimpres26/internal/detect"
)

// Hash is the pin of a tool definition: SHA-256 of its canonical JSON (sorted keys), so any change to name,
// description, schemas, annotations or metadata is a new definition.
func Hash(tool map[string]any) string {
	b, _ := json.Marshal(tool) // maps marshal with sorted keys
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Name is a definition's tool name ("" when missing or not a string).
func Name(tool map[string]any) string {
	n, _ := tool["name"].(string)
	return n
}

// Finding is the scan of one definition: score in [0,1], risk level, and the signals behind it.
type Finding struct {
	Score   float64  `json:"score"`
	Risk    string   `json:"risk"` // low | medium | high
	Signals []string `json:"signals"`
	Classes []string `json:"classes,omitempty"` // sensitive data (e.g. a key) inside the definition
}

// A definition is text the model reads as instructions about when and how to call tools. Phrasing that is odd in
// a chat message is the attack here (MCPTox: function hijacking, parameter tampering, privacy leakage), so these
// rules apply to tool metadata only.
var poisoning = []struct {
	signal string
	re     *regexp.Regexp
	w      float64
}{
	{"sensitive_path", regexp.MustCompile(`(?i)(?:~/\.ssh|\bid_(?:rsa|ed25519|ecdsa)\b|/etc/(?:passwd|shadow)|\.aws/credentials|\.kube/config|\.git-credentials|\.npmrc|\.netrc|mcp\.json|claude_desktop_config|\.cursor/|(?:^|[\s/"'])\.env\b|private key|kunci privat)`), 0.6},
	{"cross_tool", regexp.MustCompile(`(?i)\b(?:before|after|when(?:ever)?|prior to|sebelum|setelah|ketika|saat)\s+(?:you\s+|the\s+(?:user|assistant|agent)\s+(?:(?:asks?|wants?|requests?)\s+(?:you\s+)?to\s+)?)?(?:use|uses|using|call|calls|calling|invoke|invokes|invoking|run|runs|running|menggunakan|memanggil|memakai)\b(?:[^.\n]|\.\S){0,60}?\b(?:tool|function|fungsi|alat)\b`), 0.6},
	{"cross_tool", regexp.MustCompile(`(?i)\bthis tool (?:must|should|has to) (?:always )?be (?:called|used|invoked|run) (?:first|before)`), 0.6},
	{"cross_tool", regexp.MustCompile(`(?i)\b(?:instead of|rather than|jangan gunakan|alih-alih)\s+(?:using |calling )?(?:the\s+)?[\w.-]+\s+(?:tool|function|fungsi)`), 0.6},
	{"param_tamper", regexp.MustCompile(`(?i)\b(?:always|must|selalu|wajib)\s+(?:also\s+)?(?:set|change|replace|override|add|include|append|bcc|cc|send a copy|forward|ubah|ganti|tambahkan|sertakan|kirim salinan)\b(?:[^.\n]|\.\S){0,60}?\b(?:recipient|recipients|to|address|email|amount|account|bcc|cc|parameter|argument|penerima|alamat|jumlah|nominal|rekening)\b`), 0.6},
	{"concealment", regexp.MustCompile(`(?i)\b(?:do not|don't|never|jangan)\s+(?:tell|inform|mention|reveal|notify|show|alert|beri\s?tahu|memberi\s?tahu|sebutkan|tampilkan)\b(?:[^.\n]|\.\S){0,40}?\b(?:user|users|pengguna|nasabah)\b|\bwithout (?:telling|informing|notifying|alerting) the user\b|\b(?:secretly|silently|covertly|diam-diam)\b|\btanpa (?:memberi\s?tahu|sepengetahuan)\b|\bthe user (?:does not|doesn't) need to know\b`), 0.6},
	{"directive_tag", regexp.MustCompile(`(?i)<\s*/?\s*(?:important|instructions?|secret|hidden|critical)\s*>`), 0.5},
}

// Scan rates a tool definition. Every string in it (name, description, schema property descriptions, enums,
// defaults, annotations) is read, with the content detectors' injection signal folded in.
func Scan(tool map[string]any) Finding {
	var parts []string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			parts = append(parts, x)
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				parts = append(parts, k) // property names are read by the model too
				walk(x[k])
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(tool)
	text := strings.Join(parts, "\n\n")

	weights := map[string]float64{}
	for _, r := range poisoning {
		if r.re.MatchString(text) {
			weights[r.signal] = max(weights[r.signal], r.w)
		}
	}
	res := detect.Scan(text)
	for _, t := range res.Injection.Types {
		if t != "tool_steering" { // "call the X tool" is what tool docs legitimately say
			weights["injection:"+t] = max(weights["injection:"+t], weightOf(res.Injection, t))
		}
	}
	f := Finding{Signals: []string{}}
	for _, c := range res.Classes {
		f.Classes = append(f.Classes, c.Type)
		if strings.HasPrefix(c.Type, "SECRET.") {
			weights["embedded_secret"] = 0.6
		}
	}
	miss := 1.0
	for s, w := range weights {
		f.Signals = append(f.Signals, s)
		miss *= 1 - w
	}
	sort.Strings(f.Signals)
	f.Score = math.Round((1-miss)*1000) / 1000
	switch {
	case f.Score >= 0.7:
		f.Risk = "high"
	case f.Score > 0:
		f.Risk = "medium"
	default:
		f.Risk = "low"
	}
	return f
}

func weightOf(inj detect.Injection, typ string) float64 {
	w := 0.0
	for _, e := range inj.Evidence {
		if e.Type == "INJECTION."+typ {
			w = max(w, e.Confidence)
		}
	}
	return w
}
