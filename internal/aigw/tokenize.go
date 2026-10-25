package aigw

import (
	"context"
	"slices"
	"strings"
	"time"

	"wantimpres26/internal/inspect"
	"wantimpres26/internal/mcpgw"
	"wantimpres26/internal/tokvault"
)

// issued is an FPE token the gateway put in a request (ticket 24).
type issued struct{ class, token string }

func digitsOf(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
}

func (a *App) tokenTTL() time.Duration {
	if a.TokenTTLMinutes > 0 {
		return time.Duration(a.TokenTTLMinutes) * time.Minute
	}
	return time.Hour
}

// protect applies a redact/tokenize decision in place. A finding the decision tokenizes becomes an FPE token when
// its class is numeric and a vault is configured, even if a weaker rule also asked to redact it (FR-POL-4:
// tokenize > redact); every other finding the obligations name gets a redaction label, as does everything when the
// vault cannot be reached (redaction is the stronger control).
func (c *call) protect(ctx context.Context, d mcpgw.Decision, in *inspect.Content) {
	var red, tok []string
	for _, o := range d.Obligations {
		switch o.Type {
		case "redact":
			red = append(red, o.Classes...)
		case "tokenize":
			tok = append(tok, o.Classes...)
		}
	}
	anyOf := func(globs []string, t string) bool { return len(globs) > 0 && inspect.Wanted(globs, t) }
	all := append(slices.Clone(red), tok...)
	repl := map[[2]int]string{}
	var items []tokvault.Item
	var spans [][2]int
	for _, f := range in.Findings() {
		if !inspect.Wanted(all, f.Type) {
			continue
		}
		_, numeric := tokvault.Classes[f.Type]
		wantTok := anyOf(tok, f.Type) || len(tok) == 0 && d.Action == "tokenize"
		if numeric && wantTok && c.g.Vault != nil {
			items, spans = append(items, tokvault.Item{Class: f.Type, Value: f.Value}), append(spans, f.Span)
			continue
		}
		repl[f.Span] = inspect.Label(f.Type)
	}
	if len(items) > 0 {
		toks, err := c.g.Vault.Tokenize(ctx, items, c.app.tokenTTL())
		for i := range items {
			if err != nil {
				repl[spans[i]] = inspect.Label(items[i].Class)
				continue
			}
			repl[spans[i]] = toks[i]
			c.tokens[digitsOf(toks[i])] = issued{items[i].Class, toks[i]}
		}
		if err != nil {
			c.g.Log.Error("token vault unavailable, redacting instead", "err", err)
		}
	}
	in.Rewrite(repl)
}

// tokenSpans finds this request's tokens in text, as issued or reformatted to bare digits.
func (c *call) tokenSpans(text string) map[[2]int]issued {
	found := map[[2]int]issued{}
	for d, is := range c.tokens {
		for _, form := range []string{is.token, d} {
			for i := 0; ; {
				j := strings.Index(text[i:], form)
				if j < 0 {
					break
				}
				found[[2]int{i + j, i + j + len(form)}] = is
				i += j + len(form)
			}
		}
	}
	return found
}

// detokenizer asks the vault (which audits it) for the values of the tokens in text and returns a rewriter that
// puts them back. Tokens it does not know, or any vault failure, leave the tokens where they are.
func (c *call) detokenizer(ctx context.Context, text string) func(string) string {
	spans := c.tokenSpans(text)
	if len(spans) == 0 || c.g.Vault == nil {
		return func(s string) string { return s }
	}
	var items []tokvault.Item
	var forms []string
	for sp, is := range spans {
		form := text[sp[0]:sp[1]]
		if !slices.Contains(forms, form) {
			forms = append(forms, form)
			items = append(items, tokvault.Item{Class: is.class, Value: form})
		}
	}
	_, pid := c.principal()
	vals, err := c.g.Vault.Detokenize(ctx, tokvault.DetokenizeRequest{App: c.app.ID, Principal: pid, TraceID: c.trace, Items: items})
	if err != nil {
		c.g.Log.Error("token vault unavailable, answer keeps tokens", "err", err)
		return func(s string) string { return s }
	}
	var pairs []string
	for i, v := range vals {
		if v != nil {
			pairs = append(pairs, forms[i], *v)
		}
	}
	return strings.NewReplacer(pairs...).Replace
}
