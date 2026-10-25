package aigw

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Config is AIGW_CONFIG_FILE: the apps allowed to call the gateway and the providers behind it.
type Config struct {
	Apps      []App      `json:"apps"`
	Providers []Provider `json:"providers"`
}

// App is an internal application. Its gateway key is stored as a SHA-256 hash; the key itself lives only in the
// app's own secret store.
type App struct {
	ID        string   `json:"id"`
	KeySHA256 string   `json:"key_sha256"`
	Providers []string `json:"providers"` // provider names this app may use
	// FailMode when the PDP cannot decide (spec §13.3): fail_closed (default) refuses, fail_open forwards and
	// raises fail_open_total. Use fail_open only for general chat that never carries restricted data.
	FailMode string `json:"fail_mode"`
	// Canary plants a per-app secret marker in the system prompt; an answer that repeats it is a system prompt
	// leak (FR-PSEC-5). Long verbatim runs of the system prompt are caught with or without it.
	Canary bool `json:"canary"`
	// Detokenize: this app's callers may see the values behind FPE tokens in answers (ticket 24); otherwise they
	// get the tokens. TokenTTLMinutes is how long a token can be turned back (default 60).
	Detokenize      bool `json:"detokenize"`
	TokenTTLMinutes int  `json:"token_ttl_minutes"`
	// Limits (FR-PSEC-9); 0 = unlimited. Users are the X-Wantimpres26-User the app forwards.
	RPM              int64 `json:"rpm"`
	UserRPM          int64 `json:"user_rpm"`
	TokensPerDay     int64 `json:"tokens_per_day"`
	UserTokensPerDay int64 `json:"user_tokens_per_day"`
}

// Provider is an upstream LLM API.
type Provider struct {
	Name     string `json:"name"`     // route: /<name>/v1/...
	Kind     string `json:"kind"`     // openai | anthropic | gemini
	Upstream string `json:"upstream"` // base URL the API paths are appended to
	KeyFile  string `json:"key_file"` // provider key, written by the vault agent; re-read when it changes
	Auth     string `json:"auth"`     // bearer | x-api-key | x-goog-api-key | api-key; default per kind
	// Destination for the PDP. AppID is the catalog id; for an app in the catalog the PDP takes sanction and region
	// from the catalog (wantimpres26/dest), these values count only for apps it does not know (e.g. a self-hosted model).
	AppID    string `json:"app_id"`
	Sanction string `json:"sanction"`
	Region   string `json:"region"`
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ParseConfig validates the file.
func ParseConfig(raw []byte) (Config, error) {
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, err
	}
	names := map[string]bool{}
	for i, p := range c.Providers {
		switch {
		case !nameRe.MatchString(p.Name) || names[p.Name]:
			return c, fmt.Errorf("provider %q: name must be unique, lowercase letters, digits, dashes", p.Name)
		case p.Kind != KindOpenAI && p.Kind != KindAnthropic && p.Kind != KindGemini:
			return c, fmt.Errorf("provider %s: kind %q", p.Name, p.Kind)
		case !strings.HasPrefix(p.Upstream, "https://") && !strings.HasPrefix(p.Upstream, "http://"):
			return c, fmt.Errorf("provider %s: upstream must be a URL", p.Name)
		case p.KeyFile == "" || p.AppID == "" || p.Sanction == "" || p.Region == "":
			return c, fmt.Errorf("provider %s needs key_file, app_id, sanction, region", p.Name)
		}
		if p.Auth == "" {
			c.Providers[i].Auth = defaultAuth(p.Kind)
		}
		c.Providers[i].Upstream = strings.TrimSuffix(p.Upstream, "/")
		names[p.Name] = true
	}
	ids := map[string]bool{}
	for i, a := range c.Apps {
		switch {
		case !nameRe.MatchString(a.ID) || ids[a.ID]:
			return c, fmt.Errorf("app %q: id must be unique, lowercase letters, digits, dashes", a.ID)
		case len(a.KeySHA256) != 64 || strings.Trim(strings.ToLower(a.KeySHA256), "0123456789abcdef") != "":
			return c, fmt.Errorf("app %s: key_sha256 must be 64 hex characters", a.ID)
		case slices.ContainsFunc(a.Providers, func(p string) bool { return !names[p] }):
			return c, fmt.Errorf("app %s: unknown provider in %v", a.ID, a.Providers)
		case a.FailMode != "" && a.FailMode != FailOpen && a.FailMode != FailClosed:
			return c, fmt.Errorf("app %s: fail_mode %q", a.ID, a.FailMode)
		}
		if a.FailMode == "" {
			c.Apps[i].FailMode = FailClosed
		}
		c.Apps[i].KeySHA256 = strings.ToLower(a.KeySHA256)
		ids[a.ID] = true
	}
	return c, nil
}

const (
	FailOpen   = "fail_open"
	FailClosed = "fail_closed"
)

// lookup finds the app whose key hashes to the presented one, in constant time per app.
func lookup(apps []App, key string) *App {
	if key == "" {
		return nil
	}
	h := sha256.Sum256([]byte(key))
	got := hex.EncodeToString(h[:])
	var found *App
	for i := range apps {
		if subtle.ConstantTimeCompare([]byte(apps[i].KeySHA256), []byte(got)) == 1 {
			found = &apps[i]
		}
	}
	return found
}

// KeyFiles reads provider keys from files the vault agent keeps current (spec §10.1 Secrets), re-reading a file
// when its modification time changes so a rotated key is used without a restart.
type KeyFiles struct {
	mu    sync.Mutex
	cache map[string]keyFile
}

type keyFile struct {
	mod time.Time
	key string
}

func (k *KeyFiles) Key(p Provider) (string, error) {
	st, err := os.Stat(p.KeyFile)
	if err != nil {
		return "", err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if c, ok := k.cache[p.KeyFile]; ok && c.mod.Equal(st.ModTime()) {
		return c.key, nil
	}
	b, err := os.ReadFile(p.KeyFile)
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(b))
	if key == "" {
		return "", errors.New("provider key file is empty")
	}
	if k.cache == nil {
		k.cache = map[string]keyFile{}
	}
	k.cache[p.KeyFile] = keyFile{st.ModTime(), key}
	return key, nil
}
