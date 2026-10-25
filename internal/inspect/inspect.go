// Package inspect runs detection over the text inside a JSON value and redacts it in place, so a PEP can inspect a
// request or response body and forward it still valid (FR-DLP-1). Used by the MCP gateway (tool arguments and
// results) and the AI gateway (provider request and response bodies).
package inspect

import (
	"encoding/json"
	"path"
	"sort"
	"strings"

	"wantimpres26/internal/detect"
)

// Content is every string leaf of a JSON value, joined for one detector pass.
type Content struct {
	Text string        // the leaves, separated by blank lines
	Raw  []byte        // canonical JSON (sorted keys) of the value, for the content hash
	Res  detect.Result // L1 over Text
	// Leaves counts the strings found; zero means there was nothing to inspect.
	Leaves int

	leaves []leaf
}

type leaf struct {
	off int
	s   string
	set func(string)
}

// New walks the string leaves of v (maps and arrays, in sorted key order) and scans them. skip, when not nil,
// prunes object keys whose values are not text a model reads (roles, ids, base64 media). Writes through Redact land
// in v itself.
func New(v any, skip func(key string) bool) *Content {
	raw, _ := json.Marshal(v)
	c := &Content{Raw: raw}
	var b strings.Builder
	add := func(s string, set func(string)) {
		if b.Len() > 0 {
			b.WriteString("\n\n") // no detector joins digits or words across a blank line
		}
		c.leaves = append(c.leaves, leaf{b.Len(), s, set})
		b.WriteString(s)
	}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				if skip == nil || !skip(k) {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			for _, k := range keys {
				if s, ok := x[k].(string); ok {
					add(s, func(n string) { x[k] = n })
				} else {
					walk(x[k])
				}
			}
		case []any:
			for i, e := range x {
				if s, ok := e.(string); ok {
					add(s, func(n string) { x[i] = n })
				} else {
					walk(e)
				}
			}
		}
	}
	walk(v)
	c.Text, c.Leaves = b.String(), len(c.leaves)
	c.Res = detect.Scan(c.Text)
	return c
}

// Redact replaces the found classes matching globs (none = every class found) in place.
func (c *Content) Redact(globs []string) {
	for _, l := range c.leaves {
		var ms []detect.Match
		for _, m := range c.Res.Matches {
			if m.Span[0] >= l.off && m.Span[1] <= l.off+len(l.s) && Wanted(globs, m.Type) {
				m.Span = [2]int{m.Span[0] - l.off, m.Span[1] - l.off}
				ms = append(ms, m)
			}
		}
		if len(ms) > 0 {
			l.set(detect.Redact(l.s, ms))
		}
	}
}

// Wanted reports whether a class matches the obligation globs (none = all).
func Wanted(globs []string, typ string) bool {
	if len(globs) == 0 {
		return true
	}
	for _, g := range globs {
		if ok, _ := path.Match(g, typ); ok {
			return true
		}
	}
	return false
}

// Finding is one detector match with the text it covers (offsets into Content.Text).
type Finding struct {
	detect.Match
	Value string
}

// Findings are the sensitive-data matches (not injection evidence) and their text.
func (c *Content) Findings() []Finding {
	var fs []Finding
	for _, m := range c.Res.Matches {
		fs = append(fs, Finding{m, c.Text[m.Span[0]:m.Span[1]]})
	}
	return fs
}

// Rewrite replaces findings in place, by their span in Content.Text (FPE tokens, labels). Spans not inside one leaf
// are left alone.
func (c *Content) Rewrite(repl map[[2]int]string) {
	for _, l := range c.leaves {
		var spans [][2]int
		for sp := range repl {
			if sp[0] >= l.off && sp[1] <= l.off+len(l.s) {
				spans = append(spans, sp)
			}
		}
		if len(spans) == 0 {
			continue
		}
		sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
		var b strings.Builder
		at := 0
		for _, sp := range spans {
			a, e := sp[0]-l.off, sp[1]-l.off
			if a < at {
				continue
			}
			b.WriteString(l.s[at:a])
			b.WriteString(repl[sp])
			at = e
		}
		b.WriteString(l.s[at:])
		l.set(b.String())
	}
}

// Replace rewrites every leaf with fn (e.g. detokenisation of a response).
func (c *Content) Replace(fn func(string) string) {
	for _, l := range c.leaves {
		if n := fn(l.s); n != l.s {
			l.set(n)
		}
	}
}

// Label is what redaction puts in place of a finding.
func Label(typ string) string { return "[REDACTED:" + typ + "]" }
