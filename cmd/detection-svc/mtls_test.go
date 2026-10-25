package main

import (
	"net/http"
	"strings"
	"testing"

	"wantimpres26/internal/server/mtlstest"
)

// Ticket 40 AC: detection-svc scans only for the PEP workloads in MTLS_ALLOW (deploy/base/services.yaml); any other
// pod is refused at the handshake and cannot use it as an oracle.
func TestScanOnlyForPEPs(t *testing.T) {
	ca := mtlstest.NewCA(t)
	srv := mtlstest.Serve(t, workloadRoutes(nil, nil), ca.Issue(t, "", "detection-svc"), "ai-gateway", "mcp-gateway", "connector-worker")
	scan := func(sa string) (int, error) {
		c := mtlstest.Client(t, ca.Issue(t, "", sa), "detection-svc")
		resp, err := c.Post(srv.URL+"/scan/text", "application/json", strings.NewReader(`{"content": "NIK 3201011505900001"}`))
		if err != nil {
			return 0, err
		}
		_ = resp.Body.Close()
		return resp.StatusCode, nil
	}
	if code, err := scan("ai-gateway"); err != nil || code != http.StatusOK {
		t.Errorf("PEP refused: %d %v", code, err)
	}
	for _, sa := range []string{"siem-export", "event-ingest", "tika", "default"} {
		if _, err := scan(sa); err == nil {
			t.Errorf("%s got a scan", sa)
		}
	}
}
