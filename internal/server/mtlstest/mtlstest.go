// Package mtlstest issues SPIFFE workload certificates for tests, laid out like cert-manager's csi-driver-spiffe
// (tls.crt, tls.key, ca.crt in one directory).
package mtlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"wantimpres26/internal/server"
)

// TrustDomain is the SPIFFE trust domain of the tests and the deployment.
const TrustDomain = "spiffe://wantimpres26.bank/ns/wantimpres26/sa/"

// ID is the SPIFFE ID of a service account in namespace wantimpres26.
func ID(sa string) string { return TrustDomain + sa }

type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

var serial atomic.Int64

func NewCA(t *testing.T) *CA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: "wantimpres26 test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &CA{cert: c, key: k, pem: pemBlock("CERTIFICATE", der)}
}

// Issue writes an SVID for service account sa into dir (a new temp dir when ""), replacing what is there, and
// returns dir.
func (ca *CA) Issue(t *testing.T, dir, sa string) string {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(ID(sa))
	n := serial.Add(1)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(n), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		URIs: []*url.URL{u}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(k)
	later := time.Now().Add(time.Duration(n) * time.Second) // a fresh mtime, as a rotation would leave
	for name, b := range map[string][]byte{"tls.crt": pemBlock("CERTIFICATE", der), "tls.key": pemBlock("EC PRIVATE KEY", kder), "ca.crt": ca.pem} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(p, later, later)
	}
	return dir
}

// Serve runs h behind server.WorkloadTLS with the certificate in dir, admitting the allowed service accounts.
func Serve(t *testing.T, h http.Handler, dir string, allow ...string) *httptest.Server {
	t.Helper()
	var ids []string
	for _, sa := range allow {
		ids = append(ids, ID(sa))
	}
	cfg, err := server.WorkloadTLS(dir, ids)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// Client calls a workload whose service account is peer, as the workload whose certificate is in dir.
func Client(t *testing.T, dir, peer string) *http.Client {
	t.Helper()
	cfg, err := server.ClientTLS(dir, []string{ID(peer)})
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}
