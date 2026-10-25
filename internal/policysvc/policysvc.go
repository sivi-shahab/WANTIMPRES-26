// Package policysvc is the Policy Service: it builds and signs the OPA bundle every PEP sidecar pulls and
// serves it with ETag + long-polling (spec FR-POL-1).
package policysvc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/compile"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"

	"wantimpres26/internal/privacy"
)

const (
	// KeyID is the default key slot (KeyIDs, signer.go); Alg must match the sidecar's `keys` entries
	// (deploy/base/opa/opa.yaml).
	KeyID = "wantimpres26-policy-a"
	Alg   = "ES256"
	// ContentType tells OPA the server supports long-polling.
	ContentType = "application/vnd.openpolicyagent.bundles"
	maxWait     = 5 * time.Minute
)

// Overrides replace data documents of fsys by dotted path, e.g. "wantimpres26.rules" and "wantimpres26.exceptions" from a
// policy release (ticket 12).
type Overrides map[string]any

// source is fsys's modules and data with overrides applied, plus a content hash (the bundle revision).
type source struct {
	modules  []bundle.ModuleFile
	data     map[string]any
	revision string
}

func load(fsys fs.FS, overrides Overrides) (source, error) {
	src := source{data: map[string]any{}}
	h := sha256.New()
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		switch {
		case strings.HasSuffix(p, "_test.rego"), !strings.HasSuffix(p, ".rego") && path.Base(p) != "data.json":
			return nil
		case strings.HasSuffix(p, ".rego"):
			src.modules = append(src.modules, bundle.ModuleFile{URL: "/" + p, Path: "/" + p, Raw: raw})
		default:
			var v any
			if err := json.Unmarshal(raw, &v); err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			if _, overridden := overrides[strings.ReplaceAll(path.Dir(p), "/", ".")]; overridden {
				return nil
			}
			setPath(src.data, strings.Split(path.Dir(p), "/"), v)
		}
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00", p, raw) // hash.Hash writes never fail
		return nil
	})
	if err != nil {
		return source{}, err
	}
	for k, v := range overrides {
		setPath(src.data, strings.Split(k, "."), v)
	}
	ov, _ := json.Marshal(overrides) // map keys are sorted: stable
	forbidden := privacy.Forbidden()
	setPath(src.data, []string{"system", "log", "forbidden"}, forbidden)
	// optimized=1: a change in how the bundle is built must change the revision too, or sidecars keep the old one.
	_, _ = fmt.Fprintf(h, "overrides\x00%s\x00forbidden\x00%v\x00optimized=1", ov, forbidden)
	src.revision = hex.EncodeToString(h.Sum(nil))[:16]
	return src, nil
}

func (src source) regoOpts(query string) []func(*rego.Rego) {
	opts := []func(*rego.Rego){rego.Query(query), rego.Store(inmem.NewFromObject(src.data))}
	for _, m := range src.modules {
		opts = append(opts, rego.Module(m.Path, string(m.Raw)))
	}
	return opts
}

// Build bundles every non-test module and data.json in fsys (with overrides), injects the forbidden log fields
// for decision-log masking (data.system.log.forbidden), refuses rule sets with errors, and signs with signer. The
// revision is a content hash: replicas building the same release serve the same ETag.
func Build(ctx context.Context, fsys fs.FS, signer Signer, overrides Overrides) (tarball []byte, revision string, err error) {
	src, err := load(fsys, overrides)
	if err != nil {
		return nil, "", err
	}
	if err := Validate(ctx, src); err != nil {
		return nil, "", err
	}
	b, err := optimize(ctx, &bundle.Bundle{Data: src.data, Modules: src.modules,
		Manifest: bundle.Manifest{Roots: &[]string{"wantimpres26", "system"}}})
	if err != nil {
		return nil, "", err
	}
	b.Manifest.Revision = src.revision
	if err := signer.sign(b); err != nil {
		return nil, "", fmt.Errorf("sign bundle: %w", err)
	}
	var buf bytes.Buffer
	if err := bundle.NewWriter(&buf).Write(*b); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), src.revision, nil
}

// Entrypoint is the decision the gateways ask for on the hot path (mcpgw.OPA.Decide).
const Entrypoint = "wantimpres26/decision/checked"

// optimize partially evaluates Entrypoint against the bundle's data, as opa build -O=1 (ticket 47): the rule set
// is known when the bundle is built, so the loop over it is unrolled. About 17% of a decision on 1 vCPU. Every
// other rule (result, the MCP queries, kills) stays as written; TestOptimizedBundleDecidesAsSource holds the two
// together.
func optimize(ctx context.Context, b *bundle.Bundle) (*bundle.Bundle, error) {
	for i, m := range b.Modules {
		parsed, err := ast.ParseModuleWithOpts(m.Path, string(m.Raw), ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			return nil, err
		}
		b.Modules[i].Parsed = parsed
	}
	c := compile.New().WithTarget(compile.TargetRego).WithOptimizationLevel(1).WithEntrypoints(Entrypoint).
		WithBundle(b).WithOutput(io.Discard)
	if err := c.Build(ctx); err != nil {
		return nil, fmt.Errorf("optimize bundle: %w", err)
	}
	return c.Bundle(), nil
}

// Validate fails on any decision rule_errors or risk config_errors: a typo must never become a rule that silently
// never matches, nor weights that push a score out of 0-100.
func Validate(ctx context.Context, src source) error {
	rs, err := rego.New(src.regoOpts("data.wantimpres26.decision.rule_errors | data.wantimpres26.risk.config_errors")...).Eval(ctx)
	if err != nil {
		return fmt.Errorf("evaluate rule_errors: %w", err)
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return fmt.Errorf("rule_errors undefined: are wantimpres26/decision.rego and wantimpres26/risk/risk.rego in the bundle?")
	}
	if errs, _ := rs[0].Expressions[0].Value.([]any); len(errs) > 0 {
		return fmt.Errorf("%w: %v", ErrInvalidRules, errs)
	}
	return nil
}

// ErrInvalidRules marks a rule set the engine refuses (duplicate id, unknown op/action/mode, …).
var ErrInvalidRules = errors.New("rule set invalid")

// Evaluator runs the decision engine in-process on fsys with overrides: simulation and rule validation use the
// exact modules the sidecars run.
type Evaluator struct{ pq rego.PreparedEvalQuery }

func NewEvaluator(ctx context.Context, fsys fs.FS, overrides Overrides) (*Evaluator, error) {
	pq, err := Query(ctx, fsys, overrides, "data.wantimpres26.decision.result")
	if err != nil {
		return nil, err
	}
	return &Evaluator{pq}, nil
}

// Query prepares query over the validated policy in fsys with overrides, as the sidecars would evaluate it
// (PEP tests use it to stand in for OPA).
func Query(ctx context.Context, fsys fs.FS, overrides Overrides, query string) (rego.PreparedEvalQuery, error) {
	src, err := load(fsys, overrides)
	if err != nil {
		return rego.PreparedEvalQuery{}, err
	}
	if err := Validate(ctx, src); err != nil {
		return rego.PreparedEvalQuery{}, err
	}
	return rego.New(src.regoOpts(query)...).PrepareForEval(ctx)
}

// Decision is the part of the PDP result simulation compares.
type Decision struct {
	Action       string   `json:"action"`
	ReasonCodes  []string `json:"reason_codes"`
	MatchedRules []string `json:"matched_rules"`
	MonitorRules []string `json:"monitor_rules"`
}

// Eval decides one canonical input. Safe for concurrent use.
func (e *Evaluator) Eval(ctx context.Context, input any) (Decision, error) {
	rs, err := e.pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return Decision{}, err
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return Decision{}, errors.New("decision undefined")
	}
	raw, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return Decision{}, err
	}
	var d Decision
	return d, json.Unmarshal(raw, &d)
}

func setPath(m map[string]any, keys []string, v any) {
	for _, k := range keys[:len(keys)-1] {
		next, ok := m[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[k] = next
		}
		m = next
	}
	m[keys[len(keys)-1]] = v
}

// Server serves the current bundle. A request whose If-None-Match equals the current ETag and carries
// `Prefer: wait=N` is held until Publish or N seconds pass (OPA long-polling), then gets 304.
type Server struct {
	mu      sync.Mutex
	body    []byte
	etag    string
	changed chan struct{}
}

// Publish swaps in a new bundle and wakes every waiting poller.
func (s *Server) Publish(body []byte, revision string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body, s.etag = body, strconv.Quote(revision)
	if s.changed != nil {
		close(s.changed)
	}
	s.changed = make(chan struct{})
}

// preferWait reads N from OPA's `Prefer: modes=snapshot,delta;wait=N`; 0 when absent.
func preferWait(prefer string) time.Duration {
	for _, part := range strings.Split(prefer, ";") {
		if n, ok := strings.CutPrefix(strings.TrimSpace(part), "wait="); ok {
			secs, _ := strconv.Atoi(n)
			return time.Duration(secs) * time.Second
		}
	}
	return 0
}

func (s *Server) current() ([]byte, string, chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.body, s.etag, s.changed
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", ContentType)
	body, etag, changed := s.current()
	if body == nil {
		http.Error(w, "no bundle", http.StatusServiceUnavailable)
		return
	}
	if r.Header.Get("If-None-Match") == etag {
		timer := time.NewTimer(min(preferWait(r.Header.Get("Prefer")), maxWait))
		defer timer.Stop()
		select {
		case <-changed:
			body, etag, _ = s.current()
		case <-timer.C:
		case <-r.Context().Done():
			return
		}
	}
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(body)
}
