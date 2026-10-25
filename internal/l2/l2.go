// Package l2 calls the model-inference service (tickets 09-10: NER PII and prompt-injection classifier) for
// detection-svc, under a hard timeout: L2 is an addition to L1, never a dependency. A slow, failed or absent model
// leaves the L1 result as it is and says so (Report.Status).
//
// Rollout (spec §9.4): in shadow mode the model's findings are reported next to the result but change nothing; in
// enforce mode they are merged into it (detect.WithL2).
package l2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"wantimpres26/internal/detect"
)

const (
	Shadow  = "shadow"
	Enforce = "enforce"
)

// Client is one model-inference endpoint.
type Client struct {
	URL     string // e.g. http://model-inference
	Mode    string // shadow | enforce
	Timeout time.Duration
	HTTP    *http.Client
}

// Report is what L2 said about a text, in the scan response (and, from the PEP, in the decision event).
type Report struct {
	Model     string              `json:"model,omitempty"`
	Mode      string              `json:"mode"`
	Status    string              `json:"status"` // ok | timeout | error | skipped
	LatencyMS float64             `json:"latency_ms"`
	Entities  []detect.L2Entity   `json:"entities,omitempty"`
	Injection *detect.L2Injection `json:"injection,omitempty"`
}

type response struct {
	Model     string              `json:"model"`
	Entities  []detect.L2Entity   `json:"entities"`
	Injection *detect.L2Injection `json:"injection"`
}

// Analyze asks the model about text. trust is trusted or untrusted (FR-PSEC-2).
func (c *Client) Analyze(ctx context.Context, text, trust string) (Report, error) {
	rep := Report{Mode: c.Mode}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	views := detect.Views(text)
	if len(views) > 8 {
		views = views[:8]
	}
	body, _ := json.Marshal(map[string]any{"text": text, "views": views, "trust": trust})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/v1/analyze", bytes.NewReader(body))
	if err != nil {
		return rep, err
	}
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	resp, err := c.HTTP.Do(req)
	rep.LatencyMS = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		rep.Status = "error"
		if ctx.Err() != nil {
			rep.Status = "timeout"
		}
		return rep, err
	}
	defer func() { _ = resp.Body.Close() }()
	var r response
	if resp.StatusCode != http.StatusOK {
		rep.Status = "error"
		return rep, fmt.Errorf("model-inference: HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		rep.Status = "error"
		if ctx.Err() != nil {
			rep.Status = "timeout"
		}
		return rep, err
	}
	rep.Status, rep.Model, rep.Entities, rep.Injection = "ok", r.Model, r.Entities, r.Injection
	rep.LatencyMS = float64(time.Since(start).Microseconds()) / 1000
	return rep, nil
}

// Add runs L2 on text after L1 (and tenant tuning) produced r, unless L1 already found a certain block (a private
// key: spec §9.1 short-circuit). It never fails: without L2, r stands. In enforce mode L2 findings are merged; in
// shadow mode only reported. A nil client is L1 only.
func (c *Client) Add(ctx context.Context, r detect.Result, text, trust string) (detect.Result, *Report) {
	if c == nil {
		return r, nil
	}
	if slices.ContainsFunc(r.Classes, func(cl detect.Class) bool { return cl.Type == "SECRET.PRIVATE_KEY" }) {
		return r, &Report{Mode: c.Mode, Status: "skipped"}
	}
	rep, err := c.Analyze(ctx, text, trust)
	if err != nil || c.Mode != Enforce {
		return r, &rep
	}
	return detect.WithL2(r, text, rep.Entities, rep.Injection), &rep
}
