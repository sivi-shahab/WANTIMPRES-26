package aigw

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Provider kinds: the wire format a provider speaks. Self-hosted models (vLLM, Ollama, TGI) speak openai.
const (
	KindOpenAI    = "openai"
	KindAnthropic = "anthropic"
	KindGemini    = "gemini"
)

// endpoint is one inspectable API of a kind: where the text a model reads sits in the request, and where the
// text it wrote sits in the response. Only these keys are walked, and inside them skipKeys are pruned, so roles,
// ids and base64 media never reach the detector.
type endpoint struct {
	name         string
	reqRoots     []string
	respRoots    []string // nil: nothing to inspect (embeddings are vectors)
	streamable   bool     // "stream": true is supported (ticket 14)
	alwaysStream bool     // the endpoint only streams (Gemini streamGenerateContent)
}

var endpoints = map[string][]struct {
	method string
	path   *regexp.Regexp
	ep     endpoint
}{
	KindOpenAI: {
		{"POST", regexp.MustCompile(`^v1/chat/completions$`), endpoint{"chat.completions", []string{"messages"}, []string{"choices"}, true, false}},
		{"POST", regexp.MustCompile(`^v1/responses$`), endpoint{"responses", []string{"input", "instructions"}, []string{"output"}, false, false}},
		{"POST", regexp.MustCompile(`^v1/embeddings$`), endpoint{"embeddings", []string{"input"}, nil, false, false}},
	},
	KindAnthropic: {
		{"POST", regexp.MustCompile(`^v1/messages$`), endpoint{"messages", []string{"system", "messages"}, []string{"content"}, true, false}},
	},
	KindGemini: {
		{"POST", regexp.MustCompile(`^v1(beta)?/models/[A-Za-z0-9._-]+:generateContent$`), endpoint{"generateContent", geminiRoots, []string{"candidates"}, false, false}},
		{"POST", regexp.MustCompile(`^v1(beta)?/models/[A-Za-z0-9._-]+:streamGenerateContent$`), endpoint{"streamGenerateContent", geminiRoots, []string{"candidates"}, true, true}},
	},
}

var geminiRoots = []string{"contents", "systemInstruction", "system_instruction"}

func findEndpoint(kind, method, path string) (endpoint, bool) {
	for _, e := range endpoints[kind] {
		if e.method == method && e.path.MatchString(path) {
			return e.ep, true
		}
	}
	return endpoint{}, false
}

// skipKeys hold no text a model reads: identifiers, roles, enums, and media (base64 data, URLs to images).
var skipKeys = map[string]bool{
	"role": true, "type": true, "id": true, "tool_call_id": true, "call_id": true, "tool_use_id": true, "model": true,
	"image_url": true, "url": true, "source": true, "data": true, "inline_data": true, "inlineData": true, "file_data": true, "fileData": true,
	"file_id": true, "mime_type": true, "mimeType": true, "cache_control": true, "finish_reason": true, "finishReason": true,
	"stop_reason": true, "index": true, "logprobs": true, "status": true, "signature": true, "safetyRatings": true, "audio": true,
	"encoding_format": true, "detail": true,
}

func skip(k string) bool { return skipKeys[k] }

// appKey reads the gateway key an app sent, in whichever header its provider SDK uses.
func appKey(r *http.Request) string {
	if v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return strings.TrimSpace(v)
	}
	for _, h := range []string{"x-api-key", "x-goog-api-key", "api-key"} {
		if v := r.Header.Get(h); v != "" {
			return v
		}
	}
	return r.URL.Query().Get("key") // Gemini REST also takes ?key=
}

// setAuth puts the provider key where the provider expects it.
func setAuth(h http.Header, p Provider, key string) {
	switch p.Auth {
	case "x-api-key", "x-goog-api-key", "api-key":
		h.Set(p.Auth, key)
	default:
		h.Set("Authorization", "Bearer "+key)
	}
}

func defaultAuth(kind string) string {
	switch kind {
	case KindAnthropic:
		return "x-api-key"
	case KindGemini:
		return "x-goog-api-key"
	}
	return "bearer"
}

// forwardRequestHeaders reach the provider; everything else (cookies, the app's key, tracing internals) stays.
var forwardRequestHeaders = []string{"Content-Type", "Accept", "Anthropic-Version", "Anthropic-Beta", "OpenAI-Beta"}

// forwardResponseHeader: provider headers the SDKs read (request ids for support, rate-limit state for backoff).
func forwardResponseHeader(h string) bool {
	h = strings.ToLower(h)
	return h == "content-type" || h == "retry-after" || h == "request-id" || h == "x-request-id" ||
		strings.HasPrefix(h, "x-ratelimit-") || strings.HasPrefix(h, "anthropic-ratelimit-")
}

// errorBody is a refusal in the provider's own error format, so the official SDKs raise their normal typed error
// (PermissionDeniedError, RateLimitError, …) instead of failing to parse. It carries no request content.
func errorBody(kind string, status int, code, msg string) map[string]any {
	switch kind {
	case KindAnthropic:
		t := map[int]string{400: "invalid_request_error", 401: "authentication_error", 403: "permission_error", 404: "not_found_error",
			413: "request_too_large", 429: "rate_limit_error", 503: "overloaded_error"}[status]
		if t == "" {
			t = "api_error"
		}
		return map[string]any{"type": "error", "error": map[string]any{"type": t, "message": msg}}
	case KindGemini:
		st := map[int]string{400: "INVALID_ARGUMENT", 401: "UNAUTHENTICATED", 403: "PERMISSION_DENIED", 404: "NOT_FOUND", 413: "INVALID_ARGUMENT",
			429: "RESOURCE_EXHAUSTED", 503: "UNAVAILABLE"}[status]
		if st == "" {
			st = "INTERNAL"
		}
		return map[string]any{"error": map[string]any{"code": status, "message": msg, "status": st}}
	}
	t := map[int]string{400: "invalid_request_error", 401: "invalid_request_error", 403: "wantimpres26_policy_violation", 404: "invalid_request_error",
		413: "invalid_request_error", 429: "rate_limit_exceeded", 503: "server_error"}[status]
	return map[string]any{"error": map[string]any{"message": msg, "type": t, "param": nil, "code": code}}
}

// usage is the token count the provider reported, 0 if it did not.
func usage(kind string, resp map[string]any) int64 {
	num := func(m any, keys ...string) int64 {
		var t int64
		mm, _ := m.(map[string]any)
		for _, k := range keys {
			if f, ok := mm[k].(float64); ok {
				t += int64(f)
			}
		}
		return t
	}
	switch kind {
	case KindAnthropic:
		return num(resp["usage"], "input_tokens", "output_tokens")
	case KindGemini:
		return num(resp["usageMetadata"], "totalTokenCount")
	}
	return num(resp["usage"], "total_tokens")
}

func blockMessage(what string, reasons []string, decision string) string {
	return fmt.Sprintf("%s by WANTIMPRES-26 policy %v. Decision ID: %s. Contact the security team if this is unexpected.", what, reasons, decision)
}
