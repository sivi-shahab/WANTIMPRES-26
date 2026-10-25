package aigw

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"

	"wantimpres26/internal/detect"
	"wantimpres26/internal/inspect"
	"wantimpres26/internal/mcpgw"
)

// Streaming inspection (ticket 14, FR-DLP-2). The model's text arrives as small deltas in provider SSE events. The
// gateway keeps the text per channel (an OpenAI choice or tool call, an Anthropic content block, a Gemini
// candidate) and releases it in windows: each window is scanned and decided, then sent as delta events it
// synthesises in the provider's own format, redacted if the policy says so. The last holdback bytes stay behind until
// more text arrives, so an entity cut between two deltas is whole when it is scanned, and a cut never falls inside a
// finding. Structural events (message start, block stop, finish, usage) are forwarded in order after the text before
// them has been released. A block mid-stream ends the stream the way the provider ends a filtered one.
var (
	WindowBytes = 256 * 4 // 256 tokens (spec default)
	holdback    = 128     // longer than any identifier or token the detectors look for
	ctxBytes    = 64      // already-sent text scanned again as keyword context
)

type sseEvent struct{ name, data string }

func (e sseEvent) bytes() []byte {
	var b strings.Builder
	if e.name != "" {
		b.WriteString("event: " + e.name + "\n")
	}
	for _, l := range strings.Split(e.data, "\n") {
		b.WriteString("data: " + l + "\n")
	}
	b.WriteString("\n")
	return []byte(b.String())
}

// readSSE yields each event; yield returning false stops reading.
func readSSE(r io.Reader, yield func(sseEvent) bool) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var ev sseEvent
	var data []string
	has := false
	emit := func() bool {
		if !has {
			return true
		}
		ev.data = strings.Join(data, "\n")
		ok := yield(ev)
		ev, data, has = sseEvent{}, nil, false
		return ok
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if !emit() {
				return nil
			}
		case strings.HasPrefix(line, ":"): // comment / keep-alive
		default:
			f, v, _ := strings.Cut(line, ":")
			v = strings.TrimPrefix(v, " ")
			switch f {
			case "event":
				ev.name, has = v, true
			case "data":
				data, has = append(data, v), true
			}
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	emit()
	return nil
}

// piece is model text found in an event, for a channel; make wraps released text in a delta event.
type piece struct {
	ch   string
	text string
	make func(text string) sseEvent
}

// parts is an event taken apart: open is forwarded before its text, close after it; neutral goes out at once.
type parts struct {
	open, close, neutral *sseEvent
	texts                []piece
}

type channel struct {
	pending string
	sent    string // tail of released raw text
	make    func(string) sseEvent
}

type streamer struct {
	c     *call
	ctx   context.Context
	w     io.Writer
	flush func()
	id    string // decision event id of the stream, quoted in a block notice

	order []string
	chans map[string]*channel

	first      map[string]any // first OpenAI/Gemini chunk, for the closing chunk of a block
	started    bool           // Anthropic message_start went out
	openBlocks map[float64]bool
	nextBlock  float64
	stopped    bool

	// The stream's single decision event: strictest decision, merged findings, HMAC of all released text.
	worst    mcpgw.Decision
	decided  bool
	failed   bool
	classes  map[string]detect.Class
	sens     string
	inj, exf float64
	snippet  string
	mac      hash.Hash
	bytes    int
	usage    [3]int64 // input, output, total as the provider reported them
}

func (c *call) stream(ctx context.Context, resp *http.Response, reqTokens int) {
	for k, vs := range resp.Header {
		if forwardResponseHeader(k) {
			c.w.Header()[k] = vs
		}
	}
	c.w.Header().Set("Cache-Control", "no-cache")
	c.headers()
	c.w.WriteHeader(resp.StatusCode)
	fl, _ := c.w.(http.Flusher)
	s := &streamer{c: c, ctx: ctx, w: c.w, id: uuid.NewString(), chans: map[string]*channel{}, openBlocks: map[float64]bool{},
		classes: map[string]detect.Class{}, sens: "internal", mac: hmac.New(sha256.New, c.g.Pepper)}
	s.flush = func() {
		if fl != nil {
			fl.Flush()
		}
	}
	if err := readSSE(resp.Body, s.event); err != nil {
		c.g.Log.Error("upstream stream", "provider", c.p.Name, "err", err)
	}
	if !s.stopped {
		s.release() // the provider ended without a closing event
	}
	s.finish(reqTokens)
}

func (s *streamer) event(ev sseEvent) bool {
	var m map[string]any
	if json.Unmarshal([]byte(ev.data), &m) != nil {
		if s.c.p.Kind == KindOpenAI && ev.data == "[DONE]" {
			return s.release() && s.passthrough(ev, nil)
		}
		s.write(ev) // not JSON: nothing the model wrote that we can read
		return true
	}
	s.track(m)
	var p parts
	switch s.c.p.Kind {
	case KindAnthropic:
		p = s.splitAnthropic(ev, m)
	case KindGemini:
		p = s.splitGemini(ev, m)
	default:
		p = s.splitOpenAI(ev, m)
	}
	if p.neutral != nil {
		s.write(*p.neutral)
		return true
	}
	if p.open != nil && (!s.release() || !s.passthrough(*p.open, nil)) {
		return false
	}
	for _, t := range p.texts {
		if !s.add(t) {
			return false
		}
	}
	return p.close == nil || s.release() && s.passthrough(*p.close, nil)
}

func (s *streamer) add(t piece) bool {
	ch := s.chans[t.ch]
	if ch == nil {
		ch = &channel{}
		s.chans[t.ch] = ch
		s.order = append(s.order, t.ch)
	}
	ch.make = t.make
	ch.pending += t.text
	if len(ch.pending) >= WindowBytes+holdback {
		return s.window(ch, false)
	}
	return true
}

// release sends everything pending, before a structural event or at the end.
func (s *streamer) release() bool {
	for _, k := range s.order {
		if !s.window(s.chans[k], true) {
			return false
		}
	}
	return true
}

// window scans a channel's pending text (with sent context), decides, and releases it; all of it when final, else
// all but the holdback.
func (s *streamer) window(ch *channel, final bool) bool {
	if ch.pending == "" {
		return true
	}
	ctx := ch.sent
	text := ctx + ch.pending
	res := detect.Scan(text)
	cut := len(ch.pending)
	if !final {
		cut -= holdback
		spans := make([][2]int, 0, len(res.Matches))
		for _, m := range res.Matches {
			spans = append(spans, [2]int{m.Span[0] - len(ctx), m.Span[1] - len(ctx)})
		}
		for sp := range s.c.tokenSpans(ch.pending) { // nor half of a token the gateway issued
			spans = append(spans, sp)
		}
		for moved := true; moved; { // never release half of a finding
			moved = false
			for _, sp := range spans {
				if sp[0] < cut && sp[1] > cut {
					cut, moved = max(sp[0], 0), true
				}
			}
		}
		if cut <= 0 {
			return true
		}
	}
	sc := scan{res: res, text: text, tokens: (len(text) + 3) / 4, exfil: s.c.leak.score(text)}
	d, ok := s.decide(sc)
	if !ok {
		return false
	}
	out := ch.pending[:cut]
	switch d.Action {
	case "allow", "warn":
	case "redact", "tokenize":
		globs := obligationClasses(d)
		var ms []detect.Match
		for _, m := range res.Matches {
			// A finding begun in already-released text has its remainder redacted.
			if a, b := max(0, m.Span[0]-len(ctx)), m.Span[1]-len(ctx); b > 0 && b <= cut && inspect.Wanted(globs, m.Type) {
				m.Span = [2]int{a, b}
				ms = append(ms, m)
			}
		}
		out = detect.Redact(out, ms)
	default:
		s.block(d.ReasonCodes)
		return false
	}
	if s.c.app.Detokenize && len(s.c.tokens) > 0 {
		out = s.c.detokenizer(s.ctx, out)(out)
	}
	if out != "" {
		s.write(ch.make(out))
	}
	s.mac.Write([]byte(ch.pending[:cut]))
	s.bytes += cut
	ch.sent = ch.sent + ch.pending[:cut]
	ch.sent = ch.sent[max(0, len(ch.sent)-ctxBytes):]
	ch.pending = ch.pending[cut:]
	return true
}

// passthrough forwards a structural event after inspecting any text in it (Gemini function calls, Anthropic
// message_start content); m is its parsed body when the caller has it.
func (s *streamer) passthrough(ev sseEvent, m map[string]any) bool {
	if m == nil {
		_ = json.Unmarshal([]byte(ev.data), &m)
	}
	if m != nil {
		in := inspect.New(m, skip)
		if exf := s.c.leak.score(in.Text); len(in.Res.Matches) > 0 || in.Res.Injection.Score > 0 || exf > 0 {
			d, ok := s.decide(scanOf(in, exf))
			if !ok {
				return false
			}
			switch d.Action {
			case "allow", "warn":
			case "redact", "tokenize":
				in.Redact(obligationClasses(d))
				b, _ := json.Marshal(m)
				ev.data = string(b)
			default:
				s.block(d.ReasonCodes)
				return false
			}
		}
		if s.c.p.Kind == KindAnthropic {
			idx, _ := m["index"].(float64)
			switch m["type"] {
			case "message_start":
				s.started = true
			case "content_block_start":
				s.openBlocks[idx], s.nextBlock = true, max(s.nextBlock, idx+1)
			case "content_block_stop":
				delete(s.openBlocks, idx)
			}
		}
	}
	s.write(ev)
	return true
}

// decide asks the PDP about one window and folds the answer into the stream's record. false = the stream ended.
func (s *streamer) decide(sc scan) (mcpgw.Decision, bool) {
	for _, cl := range sc.res.Classes {
		cur := s.classes[cl.Type]
		cur.Type, cur.Count, cur.Confidence = cl.Type, max(cur.Count, cl.Count), max(cur.Confidence, cl.Confidence)
		s.classes[cl.Type] = cur
	}
	if slices.Index(levels, sc.res.Sensitivity) > slices.Index(levels, s.sens) {
		s.sens = sc.res.Sensitivity
	}
	s.inj, s.exf = max(s.inj, sc.res.Injection.Score), max(s.exf, sc.exfil)
	if s.snippet == "" && (len(sc.res.Matches) > 0 || len(sc.res.Injection.Evidence) > 0) {
		s.snippet = detect.Snippet(sc.text, append(slices.Clone(sc.res.Matches), sc.res.Injection.Evidence...))
	}
	d, err := s.c.decide(s.ctx, "response", sc)
	if err != nil {
		s.c.g.count(map[bool]string{true: "fail_open_total", false: "fail_closed_total"}[s.c.app.FailMode == FailOpen], s.c.app.ID)
		s.failed = true
		if s.c.app.FailMode == FailOpen {
			return mcpgw.Decision{Action: "allow"}, true
		}
		s.worst = mcpgw.Decision{Action: "block", ReasonCodes: []string{"FAIL_CLOSED"}, PolicyVersion: "unavailable", RiskVersion: "unavailable"}
		s.decided = true
		s.block(s.worst.ReasonCodes)
		return d, false
	}
	stricter := strictest(s.worst.Action, d.Action) == d.Action && d.Action != s.worst.Action
	if !s.decided || stricter || d.Action == s.worst.Action && d.RiskScore > s.worst.RiskScore {
		s.worst = d
	}
	s.decided = true
	return d, true
}

var levels = []string{"public", "internal", "confidential", "restricted"}

// block ends the stream as the provider ends a filtered one, with a notice in place of the rest of the answer.
func (s *streamer) block(reasons []string) {
	s.stopped = true
	if !s.decided || s.worst.Action != "block" {
		s.worst.Action = "block"
		s.worst.ReasonCodes = reasons
	}
	notice := fmt.Sprintf("\n\n[WANTIMPRES-26: response stopped by policy %v. Decision ID: %s]", reasons, s.id)
	j := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	switch s.c.p.Kind {
	case KindAnthropic:
		if !s.started {
			s.write(sseEvent{"error", j(map[string]any{"type": "error", "error": map[string]any{"type": "permission_error", "message": strings.TrimSpace(notice)}})})
			return
		}
		open := make([]float64, 0, len(s.openBlocks))
		for i := range s.openBlocks {
			open = append(open, i)
		}
		slices.Sort(open)
		for _, i := range open {
			s.write(sseEvent{"content_block_stop", j(map[string]any{"type": "content_block_stop", "index": i})})
		}
		i := s.nextBlock
		s.write(sseEvent{"content_block_start", j(map[string]any{"type": "content_block_start", "index": i, "content_block": map[string]any{"type": "text", "text": ""}})})
		s.write(sseEvent{"content_block_delta", j(map[string]any{"type": "content_block_delta", "index": i, "delta": map[string]any{"type": "text_delta", "text": notice}})})
		s.write(sseEvent{"content_block_stop", j(map[string]any{"type": "content_block_stop", "index": i})})
		s.write(sseEvent{"message_delta", j(map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": "refusal", "stop_sequence": nil}, "usage": map[string]any{"output_tokens": 0}})})
		s.write(sseEvent{"message_stop", j(map[string]any{"type": "message_stop"})})
	case KindGemini:
		s.write(sseEvent{"", j(map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": notice}}},
			"finishReason": "SAFETY", "index": 0}}})})
	default:
		chunk := map[string]any{"id": "wantimpres26-" + s.id, "object": "chat.completion.chunk", "created": s.c.g.Now().Unix(), "model": ""}
		for _, k := range []string{"id", "object", "created", "model", "system_fingerprint"} {
			if v, ok := s.first[k]; ok {
				chunk[k] = v
			}
		}
		chunk["choices"] = []any{map[string]any{"index": 0, "delta": map[string]any{"content": notice}, "finish_reason": "content_filter"}}
		s.write(sseEvent{"", j(chunk)})
		s.write(sseEvent{"", "[DONE]"})
	}
}

func (s *streamer) write(ev sseEvent) {
	_, _ = s.w.Write(ev.bytes())
	s.flush()
}

// track notes the first chunk and the provider's token counts.
func (s *streamer) track(m map[string]any) {
	if s.first == nil {
		s.first = m
	}
	n := func(v any, k string) int64 {
		mm, _ := v.(map[string]any)
		f, _ := mm[k].(float64)
		return int64(f)
	}
	switch s.c.p.Kind {
	case KindAnthropic:
		if msg, ok := m["message"].(map[string]any); ok {
			s.usage[0] = max(s.usage[0], n(msg["usage"], "input_tokens"))
		}
		s.usage[1] = max(s.usage[1], n(m["usage"], "output_tokens"))
	case KindGemini:
		s.usage[2] = max(s.usage[2], n(m["usageMetadata"], "totalTokenCount"))
	default:
		s.usage[2] = max(s.usage[2], n(m["usage"], "total_tokens"))
	}
}

// finish bills the tokens and records the stream's decision event.
func (s *streamer) finish(reqTokens int) {
	used := s.usage[2]
	if used == 0 {
		used = s.usage[0] + s.usage[1]
	}
	if used == 0 {
		used = int64(reqTokens + (s.bytes+3)/4)
	}
	s.c.charge(s.ctx, used)
	res := detect.Result{Sensitivity: s.sens, Injection: detect.Injection{Score: s.inj}}
	for _, cl := range s.classes {
		res.Classes = append(res.Classes, cl)
	}
	slices.SortFunc(res.Classes, func(a, b detect.Class) int { return strings.Compare(a.Type, b.Type) })
	sc := scan{res: res, tokens: (s.bytes + 3) / 4, exfil: s.exf, hash: hex.EncodeToString(s.mac.Sum(nil)), snippet: s.snippet}
	d := s.worst
	if !s.decided {
		if s.failed {
			d = mcpgw.Decision{Action: "allow", ReasonCodes: []string{"FAIL_OPEN"}, PolicyVersion: "unavailable", RiskVersion: "unavailable"}
		} else if d, _ = s.c.decide(s.ctx, "response", sc); d.Action == "" { // no text came: one decision for the record
			d = mcpgw.Decision{Action: "allow", ReasonCodes: []string{"PDP_UNAVAILABLE"}, PolicyVersion: "unavailable", RiskVersion: "unavailable"}
		}
	} else if s.failed && d.Action == "allow" {
		d.ReasonCodes = append(slices.Clone(d.ReasonCodes), "FAIL_OPEN")
	}
	s.c.recordAs(s.ctx, s.id, "response", sc, d)
}

// --- provider stream formats ------------------------------------------------------------------------------------

func copyExcept(m map[string]any, drop ...string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if !slices.Contains(drop, k) {
			out[k] = v
		}
	}
	return out
}

func mustString(v any) string { b, _ := json.Marshal(v); return string(b) }

// splitOpenAI: chat.completion.chunk. Text is choices[].delta.content, .refusal and tool call arguments.
func (s *streamer) splitOpenAI(ev sseEvent, m map[string]any) parts {
	var p parts
	opening, closing := false, m["usage"] != nil
	base := copyExcept(m, "choices", "usage")
	for _, c := range asSlice(m["choices"]) {
		cm, _ := c.(map[string]any)
		if cm == nil {
			continue
		}
		idx := cm["index"]
		if cm["finish_reason"] != nil {
			closing = true
		}
		delta, _ := cm["delta"].(map[string]any)
		if delta == nil {
			continue
		}
		if delta["role"] != nil {
			opening = true
		}
		for _, f := range []string{"content", "refusal"} {
			if t, ok := delta[f].(string); ok && t != "" {
				p.texts = append(p.texts, piece{fmt.Sprintf("c%v/%s", idx, f), t, func(text string) sseEvent {
					ch := copyExcept(base)
					ch["choices"] = []any{map[string]any{"index": idx, "delta": map[string]any{f: text}, "finish_reason": nil}}
					return sseEvent{ev.name, mustString(ch)}
				}})
				delete(delta, f)
			}
		}
		for _, tc := range asSlice(delta["tool_calls"]) {
			tm, _ := tc.(map[string]any)
			fn, _ := tm["function"].(map[string]any)
			if tm["id"] != nil || fn != nil && fn["name"] != nil {
				opening = true
			}
			if a, ok := fn["arguments"].(string); ok && a != "" {
				ti := tm["index"]
				p.texts = append(p.texts, piece{fmt.Sprintf("c%v/t%v", idx, ti), a, func(text string) sseEvent {
					ch := copyExcept(base)
					ch["choices"] = []any{map[string]any{"index": idx, "delta": map[string]any{"tool_calls": []any{map[string]any{"index": ti, "function": map[string]any{"arguments": text}}}}, "finish_reason": nil}}
					return sseEvent{ev.name, mustString(ch)}
				}})
				fn["arguments"] = ""
			}
		}
	}
	rest := &sseEvent{ev.name, mustString(m)}
	switch {
	case closing:
		p.close = rest
	case opening:
		p.open = rest
	case len(p.texts) == 0:
		p.neutral = rest
	}
	return p
}

// splitAnthropic: Messages API events. Text is content_block_delta text, tool input JSON and thinking.
func (s *streamer) splitAnthropic(ev sseEvent, m map[string]any) parts {
	switch m["type"] {
	case "content_block_delta":
		d, _ := m["delta"].(map[string]any)
		dt, _ := d["type"].(string)
		if f := map[string]string{"text_delta": "text", "input_json_delta": "partial_json", "thinking_delta": "thinking"}[dt]; f != "" {
			if t, ok := d[f].(string); ok {
				idx := m["index"]
				return parts{texts: []piece{{fmt.Sprintf("b%v", idx), t, func(text string) sseEvent {
					return sseEvent{ev.name, mustString(map[string]any{"type": "content_block_delta", "index": idx, "delta": map[string]any{"type": dt, f: text}})}
				}}}}
			}
		}
		return parts{close: &ev} // signature_delta and anything new: after the text before it
	case "ping":
		return parts{neutral: &ev}
	case "message_start", "content_block_start":
		return parts{open: &ev}
	}
	return parts{close: &ev}
}

// splitGemini: streamGenerateContent?alt=sse chunks. Text is candidates[].content.parts[].text.
func (s *streamer) splitGemini(ev sseEvent, m map[string]any) parts {
	var p parts
	closing := false
	base := copyExcept(m, "candidates", "usageMetadata")
	for _, c := range asSlice(m["candidates"]) {
		cm, _ := c.(map[string]any)
		if cm == nil {
			continue
		}
		idx := cm["index"]
		if idx == nil {
			idx = 0.0
		}
		if cm["finishReason"] != nil {
			closing = true
		}
		content, _ := cm["content"].(map[string]any)
		var keep []any
		for _, part := range asSlice(content["parts"]) {
			pm, _ := part.(map[string]any)
			if t, ok := pm["text"].(string); ok && len(pm) == 1 {
				p.texts = append(p.texts, piece{fmt.Sprintf("c%v", idx), t, func(text string) sseEvent {
					ch := copyExcept(base)
					ch["candidates"] = []any{map[string]any{"content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": text}}}, "index": idx}}
					return sseEvent{ev.name, mustString(ch)}
				}})
				continue
			}
			keep = append(keep, part) // function calls, thoughts, …: inspected whole as a structural event
		}
		if content != nil {
			if len(keep) == 0 {
				delete(cm, "content")
			} else {
				content["parts"], closing = keep, true
			}
		}
	}
	rest := &sseEvent{ev.name, mustString(m)}
	switch {
	case closing:
		p.close = rest
	case len(p.texts) == 0:
		p.neutral = rest
	}
	return p
}

func asSlice(v any) []any { s, _ := v.([]any); return s }
