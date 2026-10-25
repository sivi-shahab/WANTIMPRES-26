package siem

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Sink delivers a batch. A *PermanentError means retrying cannot help (rejected by the SIEM): straight to DLQ.
type Sink interface {
	Name() string
	Send(ctx context.Context, recs []Record) error
}

type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Syslog sends RFC 5424 CEF messages over TCP, TLS unless TLS is nil (RFC 5425). One connection, redialled on
// failure.
// ponytail: plain syslog-over-TCP has no application acknowledgement, so a batch written just before a connection
// dies can be lost without an error. Use RELP or the HTTP sink where the SIEM must confirm receipt.
type Syslog struct {
	Addr     string
	TLS      *tls.Config
	Hostname string

	mu   sync.Mutex
	conn net.Conn
}

func (s *Syslog) Name() string { return "syslog" }

func (s *Syslog) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if s.TLS == nil {
		return d.DialContext(ctx, "tcp", s.Addr)
	}
	return (&tls.Dialer{NetDialer: d, Config: s.TLS}).DialContext(ctx, "tcp", s.Addr)
}

func (s *Syslog) Send(ctx context.Context, recs []Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var buf bytes.Buffer
	for _, r := range recs {
		buf.Write(r.Syslog(s.Hostname))
	}
	for attempt := 0; attempt < 2; attempt++ { // once more on a fresh connection if the old one went stale
		if s.conn == nil {
			c, err := s.dial(ctx)
			if err != nil {
				return err
			}
			s.conn = c
		}
		_ = s.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := s.conn.Write(buf.Bytes()); err == nil {
			return nil
		}
		_ = s.conn.Close()
		s.conn = nil
	}
	return errors.New("syslog: write failed twice")
}

// HTTP posts batches as Splunk HEC (Format "hec") or a JSON array (Format "json"). Header carries the auth
// ("Authorization: Splunk <token>", "Bearer …"). 2xx = delivered; 4xx except 408/429 = permanent.
type HTTP struct {
	URL, Format string
	Header      http.Header
	Client      *http.Client
	// Secret, if set, signs each request (the SOAR webhook): X-Wantimpres26-Timestamp (Unix seconds) and
	// X-Wantimpres26-Signature = "sha256=" + hex HMAC-SHA256(Secret, timestamp + "." + body), so the receiver can check
	// origin and freshness.
	Secret []byte
}

func (h *HTTP) Name() string { return "http-" + h.Format }

func (h *HTTP) Send(ctx context.Context, recs []Record) error {
	body, ct := JSONArray(recs), "application/json"
	if h.Format == "hec" {
		body = HEC(recs)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return &PermanentError{err}
	}
	req.Header = h.Header.Clone()
	req.Header.Set("Content-Type", ct)
	if h.Secret != nil {
		ts := fmt.Sprint(time.Now().Unix())
		mac := hmac.New(sha256.New, h.Secret)
		mac.Write([]byte(ts + "."))
		mac.Write(body)
		req.Header.Set("X-Wantimpres26-Timestamp", ts)
		req.Header.Set("X-Wantimpres26-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode/100 == 2:
		return nil
	case resp.StatusCode/100 == 4 && resp.StatusCode != 408 && resp.StatusCode != 429:
		return &PermanentError{fmt.Errorf("%s: HTTP %d", h.URL, resp.StatusCode)}
	}
	return fmt.Errorf("%s: HTTP %d", h.URL, resp.StatusCode)
}

// Filtered hands a sink only the records Keep accepts, under its own name (metrics, DLQ): the SOAR webhook takes the
// incident records of the audit stream.
type Filtered struct {
	Sink
	Label string
	Keep  func(Record) bool
}

func (f *Filtered) Name() string { return f.Label }

func (f *Filtered) Send(ctx context.Context, recs []Record) error {
	var keep []Record
	for _, r := range recs {
		if f.Keep(r) {
			keep = append(keep, r)
		}
	}
	if len(keep) == 0 {
		return nil
	}
	return f.Sink.Send(ctx, keep)
}

// SOARRecord: incident lifecycle from the audit log (open, escalate, breach timer, containment).
func SOARRecord(r Record) bool { return r.Source == "audit" && strings.HasPrefix(r.Name, "incident.") }
