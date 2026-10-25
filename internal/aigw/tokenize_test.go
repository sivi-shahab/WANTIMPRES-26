package aigw

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"wantimpres26/internal/tokvault"
)

// fakeVault speaks the vault API with a reversible digit shift (the real FF1 vault is tested in tokvault): it
// knows which tokens it issued and counts detokenisations.
type fakeVault struct {
	mu      sync.Mutex
	issued  map[string]bool
	detoks  int
	down    bool
	ttlSeen int
}

func shift(s string, by int) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return '0' + (r-'0'+rune(by)+10)%10
		}
		return r
	}, s)
}

func (f *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	switch r.URL.Path {
	case "/tokenize":
		var req tokvault.TokenizeRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.ttlSeen = req.TTLSeconds
		var out []string
		for _, it := range req.Items {
			t := shift(it.Value, 3)
			f.issued[digitsOf(t)] = true
			out = append(out, t)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tokens": out})
	case "/detokenize":
		var req tokvault.DetokenizeRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		var out []*string
		for _, it := range req.Items {
			if !f.issued[digitsOf(it.Value)] {
				out = append(out, nil)
				continue
			}
			v := shift(it.Value, -3)
			out = append(out, &v)
			f.detoks++
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"values": out})
	}
}

// tokenizeRule is a bank rule: confidential data to an offshore provider is tokenized rather than redacted.
var tokenizeRule = map[string]any{"id": "bank.tokenize-offshore", "description": "test", "action": "tokenize", "reason": "TOKENIZE_OFFSHORE",
	"when": []any{map[string]any{"field": "direction", "op": "eq", "value": "request"},
		map[string]any{"field": "destination.region", "op": "neq", "value": "ID"},
		map[string]any{"field": "content.sensitivity", "op": "eq", "value": "confidential"}},
	"obligations": []any{map[string]any{"type": "tokenize", "classes": []any{"PII_ID.*", "FIN.*", "PCI.*"}}}}

func withVault(t *testing.T, e *env) *fakeVault {
	fv := &fakeVault{issued: map[string]bool{}}
	s := httptest.NewServer(fv)
	t.Cleanup(s.Close)
	e.gw.Vault = &tokvault.Client{URLs: []string{s.URL}, Token: "t", HTTP: s.Client()}
	e.gw.Apps = append(e.gw.Apps, App{ID: "cs-assistant", KeySHA256: sha("gw-key-cs-0123456789"), Providers: []string{"openai", "anthropic"},
		FailMode: FailClosed, Detokenize: true, TokenTTLMinutes: 30})
	return fv
}

// TestTokenize (ticket 24 AC): the provider sees format-preserving tokens instead of the NIK and account number;
// an app entitled to values gets them back in the answer (each detokenisation goes through the vault, which audits
// it), an app that is not entitled gets the tokens; with the vault down the values are redacted, never sent.
func TestTokenize(t *testing.T) {
	e := newEnv(t, tokenizeRule)
	fv := withVault(t, e)
	prompt := "Nasabah Budi, NIK 3171 0123 1090 0001, rekening BCA 1234567890, minta konfirmasi saldo."
	nikTok, accTok := shift("3171 0123 1090 0001", 3), shift("1234567890", 3)
	answer := func(text string) []byte {
		b, _ := json.Marshal(map[string]any{"id": "c", "object": "chat.completion", "choices": []any{map[string]any{"index": 0,
			"message": map[string]any{"role": "assistant", "content": text}, "finish_reason": "stop"}}})
		return b
	}
	// The model repeats the tokens, one reformatted to bare digits.
	e.ups["openai"].reply = answer("Konfirmasi untuk NIK " + digitsOf(nikTok) + " dan rekening " + accTok + " sudah disiapkan.")
	body := map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": prompt}}}

	r := e.do("openai", "v1/chat/completions", "gw-key-cs-0123456789", body)
	_, sent := e.ups["openai"].last(t)
	got := sent["messages"].([]any)[0].(map[string]any)["content"].(string)
	if got != strings.NewReplacer("3171 0123 1090 0001", nikTok, "1234567890", accTok).Replace(prompt) {
		t.Errorf("provider got %q", got)
	}
	text := r.body["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["content"].(string)
	if r.status != 200 || r.header.Get("X-Wantimpres26-Action") != "tokenize" || text != "Konfirmasi untuk NIK 3171012310900001 dan rekening 1234567890 sudah disiapkan." {
		t.Errorf("entitled app: %d %q", r.status, text)
	}
	if fv.detoks != 2 || fv.ttlSeen != 1800 {
		t.Errorf("vault detokenisations %d, ttl %d", fv.detoks, fv.ttlSeen)
	}
	ev := e.events.all()
	if req := ev[len(ev)-2]; req.Direction != "request" || req.Action != "tokenize" {
		t.Errorf("request event %+v", req)
	}

	r = e.do("openai", "v1/chat/completions", keyChat, body) // chat-assistant: not entitled
	text = r.body["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["content"].(string)
	if r.status != 200 || !strings.Contains(text, accTok) || strings.Contains(text, "1234567890") || fv.detoks != 2 {
		t.Errorf("unentitled app: %q (detoks %d)", text, fv.detoks)
	}

	fv.down = true
	e.do("openai", "v1/chat/completions", "gw-key-cs-0123456789", body)
	_, sent = e.ups["openai"].last(t)
	got = sent["messages"].([]any)[0].(map[string]any)["content"].(string)
	if !strings.Contains(got, "[REDACTED:PII_ID.NIK]") || strings.Contains(got, "3171") || strings.Contains(got, "1234567890") {
		t.Errorf("vault down: provider got %q", got)
	}
}

// TestTokenizeStream: a token split across stream deltas is put back whole for an entitled app.
func TestTokenizeStream(t *testing.T) {
	e := newEnv(t, tokenizeRule)
	withVault(t, e)
	tok := shift("1234567890", 3)
	e.ups["openai"].sse = sseOf(KindOpenAI, []string{strings.Repeat("Saldo siap. ", 120), "Rekening " + tok[:4], tok[4:] + " aktif."})
	status, evs := e.stream("openai", "v1/chat/completions", "gw-key-cs-0123456789",
		map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": "Cek rekening BCA 1234567890 dan NIK 3171012310900001."}}})
	if text := textOf(KindOpenAI, evs); status != 200 || !strings.HasSuffix(text, "Rekening 1234567890 aktif.") || strings.Contains(text, tok) {
		t.Errorf("%d %q", status, text[max(0, len(text)-80):])
	}
}
