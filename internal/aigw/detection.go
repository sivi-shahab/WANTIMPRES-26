package aigw

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"wantimpres26/internal/events"
	"wantimpres26/internal/l2"
)

// Detection is detection-svc (POST /scan/text over mTLS), asked what the L2 model makes of each inspected text
// (ticket 49). L2 is in shadow mode (spec §9.4): it decides nothing, so the call runs after the decision, off the
// request path, and the decision event waits for it at most Timeout (spec §13.3: 150 ms). L1 in-process stays the
// result the PDP decided on; without an answer the event says why (timeout, error, unavailable).
type Detection struct {
	URL     string // e.g. https://detection-svc:8443
	HTTP    *http.Client
	Timeout time.Duration
}

// maxScan: detection-svc refuses content over 256 KB (spec §8.1).
const maxScan = 256 << 10

// Shadow returns the L2 report for text. It never fails: a missing answer is a status.
func (d *Detection) Shadow(ctx context.Context, text, direction, appID string) *events.L2 {
	if len(text) > maxScan {
		return &events.L2{Mode: l2.Shadow, Status: "skipped"}
	}
	ctx, cancel := context.WithTimeout(ctx, d.Timeout)
	defer cancel()
	trust := "trusted" // what the user sent; the model's answer is not (FR-PSEC-2)
	if direction == "response" {
		trust = "untrusted"
	}
	body, _ := json.Marshal(map[string]any{"content": text, "channel": "ai_gateway", "direction": direction,
		"context": map[string]string{"app_id": appID, "trust": trust}})
	failed := func() *events.L2 {
		if ctx.Err() != nil {
			return &events.L2{Mode: l2.Shadow, Status: "timeout"}
		}
		return &events.L2{Mode: l2.Shadow, Status: "error"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL+"/scan/text", bytes.NewReader(body))
	if err != nil {
		return failed()
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return failed()
	}
	defer func() { _ = resp.Body.Close() }()
	var r struct {
		L2 *l2.Report `json:"l2"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&r) != nil {
		return failed()
	}
	if r.L2 == nil {
		return &events.L2{Mode: l2.Shadow, Status: "unavailable"} // detection-svc runs without a model
	}
	return report(*r.L2)
}

// report keeps what the event may carry: entity types counted, the injection score; never offsets.
func report(r l2.Report) *events.L2 {
	e := &events.L2{Model: r.Model, Mode: r.Mode, Status: r.Status, LatencyMS: r.LatencyMS}
	for _, en := range r.Entities {
		if !events.ClassType(en.Type) {
			continue
		}
		i := slices.IndexFunc(e.Classes, func(c events.Class) bool { return c.Type == en.Type })
		if i < 0 {
			e.Classes = append(e.Classes, events.Class{Type: en.Type})
			i = len(e.Classes) - 1
		}
		e.Classes[i].Count++
		e.Classes[i].Confidence = max(e.Classes[i].Confidence, min(max(en.Confidence, 0), 1))
	}
	slices.SortFunc(e.Classes, func(a, b events.Class) int { return strings.Compare(a.Type, b.Type) })
	if r.Injection != nil {
		s := min(max(r.Injection.Score, 0), 1)
		e.InjectionScore = &s
	}
	return e
}
