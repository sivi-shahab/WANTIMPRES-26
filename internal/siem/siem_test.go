package siem

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/events"
)

var t0 = time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)

func event() events.Event {
	return events.Event{EventID: "7f9c1b0e-3d1a-4c55-9a3e-2b6f0c8d1e21", TenantID: "00000000-0000-0000-0000-000000000001",
		TS: t0.Format(time.RFC3339Nano), TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", Channel: "ai_gateway", Direction: "request",
		PrincipalID: strings.Repeat("1", 64), AppID: "chatgpt", Action: "block", ReasonCodes: []string{"PII_ID_TO_UNSANCTIONED_AI"},
		MatchedRules: []string{"tpl.pii-id-to-unsanctioned"}, PolicyVersion: "release-3", RiskScore: 92, RiskVersion: "risk-1",
		Classes: []events.Class{{Type: "PII_ID.NIK", Count: 3}}, ContentHash: strings.Repeat("a", 64), Snippet: "NIK [REDACTED:PII_ID.NIK] tolong"}
}

func TestCEFEscaping(t *testing.T) {
	r := Record{Source: "audit", Time: t0, SignatureID: "audit.x|y", Name: `a\b|c`, Severity: 7,
		Fields: []Field{{K: "msg", V: "k=v\nnext"}, {K: "suser", V: `back\slash`}}}
	want := `CEF:0|WANTIMPRES-26|AI-SPM|1.0|audit.x\|y|a\\b\|c|7|rt=` + strconv.FormatInt(t0.UnixMilli(), 10) + ` msg=k\=v\nnext suser=back\\slash`
	if got := r.CEF(); got != want {
		t.Errorf("CEF\n got %s\nwant %s", got, want)
	}
	frame := string(r.Syslog("cp-0"))
	n, rest, _ := strings.Cut(frame, " ")
	if l, _ := strconv.Atoi(n); l != len(rest) || !strings.HasPrefix(rest, "<107>1 2026-10-03T09:00:00Z cp-0 wantimpres26 - audit - CEF:0|") {
		t.Errorf("syslog frame: %q", frame) // 13*8 + 3 (error) = 107
	}
}

// Ticket AC: no raw content in any export payload, whatever the event or audit entry carried.
func TestNoRawContentLeaves(t *testing.T) {
	ev := FromEvent(event())
	au := FromAudit(audit.Entry{Seq: 42, TenantID: event().TenantID, TS: t0, Actor: "dpo1", Action: "evidence.unmask", Hash: strings.Repeat("9", 64),
		Target: map[string]any{"incident": "i-1", "justification": "cek NIK 3171234567890001 dan kartu 4111 1111 1111 1111",
			"prompt": "isi prompt asli", "nested": map[string]any{"messages": []any{"hi"}, "ok": "fine"}}})
	al := FromAlert(Alert{Status: "firing", Fingerprint: "ab12", StartsAt: t0, Labels: map[string]string{"alertname": "PolicyBundleSignatureInvalid", "severity": "critical"},
		Annotations: map[string]string{"summary": "OPA rejected a bundle"}})
	leaks := []string{"3171234567890001", "4111 1111 1111 1111", "isi prompt asli", `"hi"`, "tolong", "REDACTED:PII_ID.NIK"}
	for _, r := range []Record{ev, au, al} {
		if err := r.Check(); err != nil {
			t.Errorf("%s: %v", r.Source, err)
		}
		for _, payload := range []string{r.CEF(), string(HEC([]Record{r})), string(JSONArray([]Record{r}))} {
			for _, l := range leaks {
				if strings.Contains(payload, l) {
					t.Errorf("%s payload leaks %q: %s", r.Source, l, payload)
				}
			}
		}
	}
	if !strings.Contains(au.CEF(), "[REDACTED:DIGITS]") || !strings.Contains(au.CEF(), `"prompt":"[REDACTED]"`) {
		t.Errorf("audit target not scrubbed: %s", au.CEF())
	}
	if !strings.Contains(ev.CEF(), "cs5=PII_ID.NIK:3") || !strings.Contains(ev.CEF(), "act=block") || ev.Severity != 9 {
		t.Errorf("event record: %s", ev.CEF())
	}

	// The last gate refuses what slipped through any mapping.
	for _, bad := range []Record{
		{Fields: []Field{{K: "msg", V: "NIK 3171234567890001"}}},
		{Fields: []Field{{K: "cs1Label", V: "prompt"}, {K: "cs1", V: "x"}}},
		{Fields: []Field{id("externalId", "not an id, 3171234567890001")}},
	} {
		if !errors.Is(bad.Check(), ErrContent) {
			t.Errorf("Check passed %+v", bad.Fields)
		}
	}
}

type fakeSink struct {
	mu    sync.Mutex
	name  string
	errs  []error // returned in order, then nil
	calls int
	got   []Record
}

func (f *fakeSink) Name() string { return f.name }

func (f *fakeSink) records() []Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Record(nil), f.got...)
}

func (f *fakeSink) Send(_ context.Context, recs []Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= len(f.errs) && f.errs[f.calls-1] != nil {
		return f.errs[f.calls-1]
	}
	f.got = append(f.got, recs...)
	return nil
}

func deliverer(sinks ...Sink) (*Deliverer, *[]string) {
	var dead []string
	return &Deliverer{Sinks: sinks, MaxAttempts: 3, Backoff: time.Millisecond, Log: slog.New(slog.DiscardHandler), Metrics: NewMetrics(),
		DLQ: func(_ context.Context, sink string, r Record, reason string) error {
			dead = append(dead, sink+":"+r.ID)
			return nil
		}}, &dead
}

func TestRetryAndDeadLetter(t *testing.T) {
	ctx := context.Background()
	rec := FromEvent(event())
	flaky := &fakeSink{name: "flaky", errs: []error{errors.New("down"), errors.New("down")}}
	down := &fakeSink{name: "down", errs: []error{errors.New("x"), errors.New("x"), errors.New("x")}}
	rejecting := &fakeSink{name: "rejecting", errs: []error{&PermanentError{errors.New("HTTP 400")}}}
	d, dead := deliverer(flaky, down, rejecting)
	if err := d.Deliver(ctx, []Record{rec, {ID: "leaky", Fields: []Field{{K: "msg", V: "3171234567890001"}}}}); err != nil {
		t.Fatal(err)
	}
	if flaky.calls != 3 || len(flaky.got) != 1 {
		t.Errorf("flaky: %d calls, %d delivered", flaky.calls, len(flaky.got))
	}
	if down.calls != 3 || rejecting.calls != 1 {
		t.Errorf("attempts: down %d (want 3), rejecting %d (want 1: permanent)", down.calls, rejecting.calls)
	}
	want := "flaky:leaky down:leaky rejecting:leaky down:" + rec.ID + " rejecting:" + rec.ID
	if strings.Join(*dead, " ") != want {
		t.Errorf("dead letters %v, want %s", *dead, want)
	}
	for _, s := range []*fakeSink{flaky, down, rejecting} {
		for _, r := range s.got {
			if r.ID == "leaky" {
				t.Error("content record was sent")
			}
		}
	}
	broken, _ := deliverer(&fakeSink{name: "always-down", errs: []error{errors.New("x"), errors.New("x"), errors.New("x")}})
	broken.DLQ = func(context.Context, string, Record, string) error { return errors.New("kafka down") }
	if err := broken.Deliver(ctx, []Record{rec}); err == nil {
		t.Error("lost record: DLQ failed but Deliver reported success")
	}
	var m strings.Builder
	d.Metrics.Write(&m)
	if !strings.Contains(m.String(), `siem_records_dead_lettered_total{sink="down"}`) || !strings.Contains(m.String(), `siem_send_retries_total{sink="flaky"} 2`) {
		t.Errorf("metrics:\n%s", m.String())
	}
}

func TestHTTPSink(t *testing.T) {
	var bodies []string
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Splunk tok" {
			w.WriteHeader(401)
			return
		}
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.WriteHeader(status)
	}))
	defer srv.Close()
	h := &HTTP{URL: srv.URL, Format: "hec", Header: http.Header{"Authorization": {"Splunk tok"}}, Client: srv.Client()}
	if err := h.Send(context.Background(), []Record{FromEvent(event()), FromEvent(event())}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(bodies[0]), "\n")
	var hec struct {
		Sourcetype string         `json:"sourcetype"`
		Event      map[string]any `json:"event"`
	}
	if len(lines) != 2 || json.Unmarshal([]byte(lines[0]), &hec) != nil || hec.Sourcetype != "wantimpres26:decision" ||
		hec.Event["riskScore"] != "92" || hec.Event["destinationApp"] != "chatgpt" {
		t.Errorf("HEC body: %s", bodies[0])
	}
	var perm *PermanentError
	status = 400
	if err := h.Send(context.Background(), []Record{FromEvent(event())}); !errors.As(err, &perm) {
		t.Errorf("400 should be permanent: %v", err)
	}
	status = 503
	if err := h.Send(context.Background(), []Record{FromEvent(event())}); err == nil || errors.As(err, &perm) {
		t.Errorf("503 should be retryable: %v", err)
	}
	h.Format = "json"
	status = 200
	_ = h.Send(context.Background(), []Record{FromEvent(event())})
	if !strings.HasPrefix(bodies[len(bodies)-1], `[{`) {
		t.Errorf("json array body: %s", bodies[len(bodies)-1])
	}
}

// Ticket 26: the SOAR webhook gets only incident records from the audit stream, signed so it can check origin.
func TestSOARWebhook(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))
	var got []Record
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(r.Header.Get("X-Wantimpres26-Timestamp") + "."))
		mac.Write(b)
		ts, _ := strconv.ParseInt(r.Header.Get("X-Wantimpres26-Timestamp"), 10, 64)
		if !hmac.Equal([]byte(r.Header.Get("X-Wantimpres26-Signature")), []byte("sha256="+hex.EncodeToString(mac.Sum(nil)))) || time.Since(time.Unix(ts, 0)) > time.Minute {
			w.WriteHeader(401)
			return
		}
		var recs []Record
		_ = json.Unmarshal(b, &recs)
		got = append(got, recs...)
	}))
	defer srv.Close()
	soar := &Filtered{Label: "soar", Keep: SOARRecord, Sink: &HTTP{URL: srv.URL, Format: "json", Header: http.Header{}, Secret: secret, Client: srv.Client()}}
	at := time.Now()
	recs := []Record{
		FromEvent(event()),
		FromAudit(audit.Entry{Seq: 1, TS: at, Actor: "system", Action: "incident.breach.escalate", Target: map[string]any{"incident": "i1", "remaining_hours": 23}}),
		FromAudit(audit.Entry{Seq: 2, TS: at, Actor: "alice", Action: "policy.version.approve", Target: map[string]any{}}),
		FromAudit(audit.Entry{Seq: 3, TS: at, Actor: "soc1", Action: "incident.contain", Target: map[string]any{"action": "block_access"}}),
	}
	if err := soar.Send(context.Background(), recs); err != nil || soar.Name() != "soar" {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "incident.breach.escalate" || got[0].Severity != 9 || got[1].Name != "incident.contain" {
		t.Errorf("SOAR got %+v", got)
	}
	// Nothing for the SOAR in a batch: no request at all.
	if err := soar.Send(context.Background(), recs[:1]); err != nil || len(got) != 2 {
		t.Errorf("empty batch: %v, %d records", err, len(got))
	}
	// A wrong key is refused by the receiver (permanent: retrying with the same key cannot help).
	bad := &HTTP{URL: srv.URL, Format: "json", Header: http.Header{}, Secret: []byte("wrong"), Client: srv.Client()}
	var perm *PermanentError
	if err := bad.Send(context.Background(), recs[1:2]); !errors.As(err, &perm) {
		t.Errorf("wrong key: %v", err)
	}
}

func TestAlertmanagerWebhook(t *testing.T) {
	sink := &fakeSink{name: "s"}
	d, _ := deliverer(sink)
	sum := sha256.Sum256([]byte("am-token"))
	srv := httptest.NewServer(AlertmanagerHandler(sum[:], d))
	defer srv.Close()
	body := `{"alerts": [{"status": "firing", "fingerprint": "f1", "startsAt": "2026-10-03T09:00:00Z",
		"labels": {"alertname": "PolicyBundleSignatureInvalid", "severity": "critical", "pod": "ai-gateway-1"},
		"annotations": {"summary": "OPA in ai-gateway-1 rejected a policy bundle"}}]}`
	for token, want := range map[string]int{"wrong": 401, "am-token": 204} {
		req, _ := http.NewRequest("POST", srv.URL, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("token %s: %d, want %d", token, resp.StatusCode, want)
		}
	}
	if len(sink.got) != 1 || sink.got[0].SignatureID != "alert.PolicyBundleSignatureInvalid" || sink.got[0].Severity != 9 {
		t.Errorf("alert records: %+v", sink.got)
	}
}

// The syslog sink over TLS against a receiver that parses RFC 6587 octet-counted frames, including a reconnect
// after the receiver drops the connection.
func TestSyslogTLS(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "siem.bank.local"}, DNSNames: []string{"siem.bank.local"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	cert, _ := x509.ParseCertificate(der)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	msgs := make(chan string, 10)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				r := bufio.NewReader(c)
				for {
					n, err := r.ReadString(' ')
					if err != nil {
						return
					}
					l, _ := strconv.Atoi(strings.TrimSpace(n))
					buf := make([]byte, l)
					if _, err := io.ReadFull(r, buf); err != nil {
						return
					}
					msgs <- string(buf)
					if strings.Contains(string(buf), "drop-after") {
						return // receiver restarts: the sink must reconnect
					}
				}
			}(c)
		}
	}()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	s := &Syslog{Addr: ln.Addr().String(), Hostname: "cp-0", TLS: &tls.Config{RootCAs: pool, ServerName: "siem.bank.local"}}
	ctx := context.Background()
	first := FromEvent(event())
	first.Name = "drop-after"
	if err := s.Send(ctx, []Record{first}); err != nil {
		t.Fatal(err)
	}
	if m := <-msgs; !strings.Contains(m, "CEF:0|WANTIMPRES-26|AI-SPM|1.0|decision.block|drop-after|9|") {
		t.Errorf("received %q", m)
	}
	time.Sleep(100 * time.Millisecond)
	var got string
	for i := 0; i < 3 && got == ""; i++ { // the first write after a peer close can still succeed locally
		_ = s.Send(ctx, []Record{FromEvent(event())})
		select {
		case got = <-msgs:
		case <-time.After(time.Second):
		}
	}
	if !strings.Contains(got, "suid=1111") {
		t.Errorf("after reconnect: %q", got)
	}
	bad := &Syslog{Addr: ln.Addr().String(), Hostname: "x", TLS: &tls.Config{ServerName: "siem.bank.local"}} // untrusted CA
	if err := bad.Send(ctx, []Record{FromEvent(event())}); err == nil {
		t.Error("sent to a SIEM whose certificate is not trusted")
	}
}
