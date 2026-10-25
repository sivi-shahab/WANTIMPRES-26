package catalog

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"wantimpres26/internal/events"
)

// Handle is the events.Handler that counts decision events into APP_USAGE_DAILY.
func (s *Store) Handle(ctx context.Context, e events.Event, _ []byte) error { return s.Record(ctx, e) }

// PullFeed fetches url and url+".sig" and imports the feed if it verifies and is newer. Feeds are pull-only
// (ADR-0001); an unchanged feed is not an error.
func (s *Store) PullFeed(ctx context.Context, client *http.Client, url string, pubPEM []byte) (int64, error) {
	get := func(u string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, errors.New(u + ": " + resp.Status)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	}
	raw, err := get(url)
	if err != nil {
		return 0, err
	}
	sig, err := get(url + ".sig")
	if err != nil {
		return 0, err
	}
	v, err := s.ImportSigned(ctx, "feed-pull", raw, string(sig), pubPEM)
	if errors.Is(err, ErrStale) {
		return 0, nil
	}
	return v, err
}

// PollEvery is how often the feed URL is checked.
const PollEvery = time.Hour
