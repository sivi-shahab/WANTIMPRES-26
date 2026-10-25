package server_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wantimpres26/internal/server"
	"wantimpres26/internal/server/mtlstest"
)

// Ticket 40: only workloads with an allowed SPIFFE ID from the trust domain's CA get through the handshake;
// certificates rotate in place without a restart.
func TestWorkloadTLS(t *testing.T) {
	ca := mtlstest.NewCA(t)
	srvDir := ca.Issue(t, "", "detection-svc")
	srv := mtlstest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "scanned") }),
		srvDir, "ai-gateway", "mcp-gateway")
	get := func(c *http.Client) error {
		resp, err := c.Get(srv.URL)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}

	if err := get(mtlstest.Client(t, ca.Issue(t, "", "ai-gateway"), "detection-svc")); err != nil {
		t.Errorf("allowed workload refused: %v", err)
	}
	if err := get(mtlstest.Client(t, ca.Issue(t, "", "siem-export"), "detection-svc")); err == nil {
		t.Error("workload outside MTLS_ALLOW got through")
	}
	// No client certificate at all (any pod with the CA, or none).
	pool := x509.NewCertPool()
	ca2pem, _ := os.ReadFile(filepath.Join(srvDir, "ca.crt"))
	pool.AppendCertsFromPEM(ca2pem)
	anon := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
	if err := get(anon); err == nil {
		t.Error("client without a certificate got through")
	}
	// The right SPIFFE ID from another CA.
	if err := get(mtlstest.Client(t, mtlstest.NewCA(t).Issue(t, "", "ai-gateway"), "detection-svc")); err == nil {
		t.Error("certificate from a foreign CA got through")
	}
	// The client checks the server too: a server with another identity is refused.
	if err := get(mtlstest.Client(t, ca.Issue(t, "", "ai-gateway"), "model-inference")); err == nil {
		t.Error("client accepted a server with the wrong SPIFFE ID")
	}

	// Rotation: the server's certificate is replaced in place; the next handshake uses the new one.
	served := func() string {
		c := mtlstest.Client(t, ca.Issue(t, "", "mcp-gateway"), "detection-svc")
		resp, err := c.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.TLS.PeerCertificates[0].SerialNumber.String()
	}
	before := served()
	ca.Issue(t, srvDir, "detection-svc")
	if after := served(); after == before {
		t.Errorf("certificate not reloaded: serial %s", after)
	}

	if _, err := server.WorkloadTLS(srvDir, nil); err == nil {
		t.Error("empty allow list accepted")
	}
	if _, err := server.WorkloadTLS(t.TempDir(), []string{mtlstest.ID("x")}); err == nil {
		t.Error("missing certificate accepted")
	}
}

// MTLSClient refuses to fall back to plain HTTP unless development says so.
func TestMTLSClientNeedsCertificates(t *testing.T) {
	t.Setenv("MTLS_DIR", "")
	t.Setenv("MTLS_INSECURE", "")
	if _, err := server.MTLSClient(time.Second, mtlstest.ID("model-inference")); err == nil {
		t.Error("plain client without MTLS_INSECURE")
	}
	t.Setenv("MTLS_INSECURE", "true")
	if c, err := server.MTLSClient(time.Second); err != nil || c.Transport != nil {
		t.Errorf("development client: %v", err)
	}
	ca := mtlstest.NewCA(t)
	t.Setenv("MTLS_DIR", ca.Issue(t, "", "detection-svc"))
	if c, err := server.MTLSClient(time.Second, mtlstest.ID("model-inference")); err != nil || c.Transport == nil {
		t.Errorf("mTLS client: %v", err)
	}
}
