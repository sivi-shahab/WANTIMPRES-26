package ingest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// IndexPrefix + day (UTC) names the daily index; retention is per index (ism_policy.json).
// ponytail: one index pattern for every tenant (tenant_id is a field). Per-tenant indices only if a tier needs it.
const IndexPrefix = "wantimpres26-events-"

//go:embed index_template.json
var indexTemplate []byte

//go:embed ism_policy.json
var ismPolicy []byte

func IndexFor(ts time.Time) string { return IndexPrefix + ts.UTC().Format("2006.01.02") }

// Doc is one event ready for the bulk API.
type Doc struct {
	Index, ID string
	Body      []byte
	Received  time.Time // Kafka record timestamp, for the produce-to-index delay metric
}

// OpenSearch is the few REST calls ingest needs.
type OpenSearch struct {
	URL, User, Password string
	HTTP                *http.Client
}

// OpenSearchFromEnv is the client the services use (ticket 41): https with basic auth, verified against
// OPENSEARCH_CA_FILE (PEM; empty = system roots). http:// is refused unless OPENSEARCH_PLAINTEXT=true (local/CI).
// Env: OPENSEARCH_URL, OPENSEARCH_USER, OPENSEARCH_PASSWORD, OPENSEARCH_CA_FILE, OPENSEARCH_PLAINTEXT.
func OpenSearchFromEnv(getenv func(string) string, timeout time.Duration) (*OpenSearch, error) {
	o := &OpenSearch{URL: getenv("OPENSEARCH_URL"), User: getenv("OPENSEARCH_USER"), Password: getenv("OPENSEARCH_PASSWORD")}
	if getenv("OPENSEARCH_PLAINTEXT") != "true" {
		if !strings.HasPrefix(o.URL, "https://") {
			return nil, fmt.Errorf("OPENSEARCH_URL must be https:// (got %q)", o.URL)
		}
		if o.User == "" || o.Password == "" {
			return nil, errors.New("OPENSEARCH_USER and OPENSEARCH_PASSWORD are required")
		}
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if f := getenv("OPENSEARCH_CA_FILE"); f != "" {
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("OPENSEARCH_CA_FILE: %w", err)
		}
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("OPENSEARCH_CA_FILE: no certificate")
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	o.HTTP = &http.Client{Timeout: timeout, Transport: tr}
	return o, nil
}

func (o *OpenSearch) do(ctx context.Context, method, path string, body []byte, ct string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, o.URL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", ct)
	if o.User != "" {
		req.SetBasicAuth(o.User, o.Password)
	}
	resp, err := o.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}

// Setup installs the index template and the retention policy. Idempotent; an existing policy is updated in place.
func (o *OpenSearch) Setup(ctx context.Context) error {
	if code, b, err := o.do(ctx, http.MethodPut, "/_index_template/wantimpres26-events", indexTemplate, "application/json"); err != nil || code != 200 {
		return fmt.Errorf("index template: %d %s %v", code, b, err)
	}
	const path = "/_plugins/_ism/policies/wantimpres26-events"
	code, b, err := o.do(ctx, http.MethodPut, path, ismPolicy, "application/json")
	if err == nil && code == http.StatusConflict {
		var cur struct {
			SeqNo       int64 `json:"_seq_no"`
			PrimaryTerm int64 `json:"_primary_term"`
		}
		if _, gb, gerr := o.do(ctx, http.MethodGet, path, nil, "application/json"); gerr == nil && json.Unmarshal(gb, &cur) == nil {
			code, b, err = o.do(ctx, http.MethodPut, fmt.Sprintf("%s?if_seq_no=%d&if_primary_term=%d", path, cur.SeqNo, cur.PrimaryTerm), ismPolicy, "application/json")
		}
	}
	if err != nil || (code != 200 && code != 201) {
		return fmt.Errorf("ism policy: %d %s %v", code, b, err)
	}
	return nil
}

// Bulk indexes docs. It returns how many were refused for good (mapping errors: retrying cannot help) or an error
// when the whole batch must be retried (unreachable, 429, 5xx).
func (o *OpenSearch) Bulk(ctx context.Context, docs []Doc) (failed int, err error) {
	var body bytes.Buffer
	for _, d := range docs {
		meta, _ := json.Marshal(map[string]any{"index": map[string]string{"_index": d.Index, "_id": d.ID}})
		body.Write(meta)
		body.WriteByte('\n')
		body.Write(d.Body)
		body.WriteByte('\n')
	}
	code, b, err := o.do(ctx, http.MethodPost, "/_bulk", body.Bytes(), "application/x-ndjson")
	if err != nil {
		return 0, err
	}
	if code != 200 {
		return 0, fmt.Errorf("bulk: HTTP %d", code)
	}
	var res struct {
		Items []map[string]struct {
			Status int `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(b, &res); err != nil {
		return 0, err
	}
	for _, item := range res.Items {
		for _, r := range item {
			switch {
			case r.Status == 429 || r.Status >= 500:
				return 0, fmt.Errorf("bulk item: HTTP %d", r.Status)
			case r.Status >= 300:
				failed++
			}
		}
	}
	return failed, nil
}
