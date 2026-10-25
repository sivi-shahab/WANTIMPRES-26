package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"wantimpres26/internal/events"
)

// Events reads decision events with ts in [from, to) from the daily indices, oldest first, at most limit.
// Policy simulation (ticket 12) replays them. Pages with search_after on (ts, event_id).
func (o *OpenSearch) Events(ctx context.Context, from, to time.Time, limit int) ([]events.Event, error) {
	var out []events.Event
	var after []any
	for len(out) < limit {
		q := map[string]any{
			"size":  min(1000, limit-len(out)),
			"query": map[string]any{"range": map[string]any{"ts": map[string]any{"gte": from.UTC().Format(time.RFC3339Nano), "lt": to.UTC().Format(time.RFC3339Nano)}}},
			"sort":  []any{map[string]any{"ts": "asc"}, map[string]any{"event_id": "asc"}},
		}
		if after != nil {
			q["search_after"] = after
		}
		body, _ := json.Marshal(q)
		code, b, err := o.do(ctx, http.MethodPost, "/"+IndexPrefix+"*/_search?ignore_unavailable=true&allow_no_indices=true", body, "application/json")
		if err != nil {
			return nil, err
		}
		if code != http.StatusOK {
			return nil, fmt.Errorf("search: HTTP %d: %s", code, b)
		}
		var res struct {
			Hits struct {
				Hits []struct {
					Source events.Event `json:"_source"`
					Sort   []any        `json:"sort"`
				} `json:"hits"`
			} `json:"hits"`
		}
		if err := json.Unmarshal(b, &res); err != nil {
			return nil, err
		}
		for _, h := range res.Hits.Hits {
			out = append(out, h.Source)
		}
		if len(res.Hits.Hits) == 0 || len(res.Hits.Hits) < q["size"].(int) {
			break
		}
		after = res.Hits.Hits[len(res.Hits.Hits)-1].Sort
	}
	return out, nil
}

// Search runs a query DSL body over the daily indices and returns the raw response (aggregations for posture).
func (o *OpenSearch) Search(ctx context.Context, body []byte) ([]byte, error) {
	code, b, err := o.do(ctx, http.MethodPost, "/"+IndexPrefix+"*/_search?ignore_unavailable=true&allow_no_indices=true", body, "application/json")
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("search: HTTP %d: %s", code, b)
	}
	return b, nil
}
