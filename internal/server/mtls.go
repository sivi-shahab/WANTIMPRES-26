package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Workload identity (ticket 40, threat model G1, spec §10.1 "SPIFFE/mTLS"). Every pod gets a short-lived X.509 SVID
// from cert-manager's csi-driver-spiffe: tls.crt, tls.key and ca.crt in one directory, rewritten in place before the
// certificate expires, with the URI SAN spiffe://<trust domain>/ns/<namespace>/sa/<service account>. Routes meant
// for other workloads only are served behind a TLS handshake that fails unless the client presents such a
// certificate with an allowed SPIFFE ID.

// svid is the certificate directory, re-read when tls.crt or ca.crt changes.
type svid struct {
	dir string

	mu   sync.Mutex
	mod  time.Time
	cert *tls.Certificate
	pool *x509.CertPool
}

func (s *svid) load() (*tls.Certificate, *x509.CertPool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mod := time.Time{}
	for _, f := range []string{"tls.crt", "ca.crt"} {
		st, err := os.Stat(filepath.Join(s.dir, f))
		if err != nil {
			return nil, nil, err
		}
		if st.ModTime().After(mod) {
			mod = st.ModTime()
		}
	}
	if s.cert != nil && mod.Equal(s.mod) {
		return s.cert, s.pool, nil
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(s.dir, "tls.crt"), filepath.Join(s.dir, "tls.key"))
	if err != nil {
		return nil, nil, err
	}
	ca, err := os.ReadFile(filepath.Join(s.dir, "ca.crt"))
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, nil, errors.New("ca.crt: no certificate")
	}
	s.mod, s.cert, s.pool = mod, &cert, pool
	return s.cert, s.pool, nil
}

// SPIFFEID is the certificate's spiffe:// URI SAN, or "".
func SPIFFEID(c *x509.Certificate) string {
	for _, u := range c.URIs {
		if u.Scheme == "spiffe" {
			return u.String()
		}
	}
	return ""
}

func checkPeer(certs []*x509.Certificate, allow []string) error {
	if len(certs) == 0 {
		return errors.New("no client certificate")
	}
	if id := SPIFFEID(certs[0]); !slices.Contains(allow, id) {
		return fmt.Errorf("workload %q not allowed", id)
	}
	return nil
}

// WorkloadTLS is the server side: TLS 1.3, a client certificate from the trust domain's CA required, and its SPIFFE
// ID in allow. Certificates rotate without a restart.
func WorkloadTLS(dir string, allow []string) (*tls.Config, error) {
	s := &svid{dir: dir}
	if _, _, err := s.load(); err != nil {
		return nil, fmt.Errorf("workload certificate in %s: %w", dir, err)
	}
	if len(allow) == 0 {
		return nil, errors.New("MTLS_ALLOW is empty: no workload could call")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			cert, pool, err := s.load()
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert,
				VerifyConnection: func(cs tls.ConnectionState) error { return checkPeer(cs.PeerCertificates, allow) },
			}, nil
		},
	}, nil
}

// ClientTLS is the client side for calling another workload: presents this pod's SVID and accepts only a server whose
// certificate chains to the CA and carries one of peers.
func ClientTLS(dir string, peers []string) (*tls.Config, error) {
	s := &svid{dir: dir}
	if _, _, err := s.load(); err != nil {
		return nil, fmt.Errorf("workload certificate in %s: %w", dir, err)
	}
	// nosemgrep: bypass-tls-verification -- the chain is verified in VerifyConnection against the rotating CA pool
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, _, err := s.load()
			return cert, err
		},
		// The CA pool rotates too, so the chain is verified here instead of through a fixed RootCAs.
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection below
		VerifyConnection: func(cs tls.ConnectionState) error {
			_, pool, err := s.load()
			if err != nil {
				return err
			}
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			if _, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter}); err != nil {
				return err
			}
			return checkPeer(cs.PeerCertificates, peers)
		},
	}, nil
}

// MTLSClient is an HTTP client for calling peers from this pod's MTLS_DIR; a plain client when MTLS_DIR is unset
// and MTLS_INSECURE=true (local development).
func MTLSClient(timeout time.Duration, peers ...string) (*http.Client, error) {
	dir := os.Getenv("MTLS_DIR")
	if dir == "" {
		if os.Getenv("MTLS_INSECURE") == "true" {
			return &http.Client{Timeout: timeout}, nil
		}
		return nil, errors.New("MTLS_DIR not set (MTLS_INSECURE=true only for local development)")
	}
	cfg, err := ClientTLS(dir, peers)
	if err != nil {
		return nil, err
	}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}}, nil
}

func splitList(s string) []string {
	var out []string
	for v := range strings.SplitSeq(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
