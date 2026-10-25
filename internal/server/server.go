// Package server is the shared HTTP bootstrap: health probe, privacy-safe logging, graceful shutdown.
package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"wantimpres26/internal/privacy"
)

// Run serves mux (plus GET /healthz) on $PORT (default 8080) until SIGTERM/SIGINT, then drains.
func Run(service string, mux *http.ServeMux) { RunMTLS(service, mux, nil) }

// RunMTLS is Run plus workload: routes for other workloads only (ticket 40). With MTLS_DIR set they are served on
// $MTLS_PORT (default 8443) behind WorkloadTLS with the SPIFFE IDs in MTLS_ALLOW (comma-separated); $PORT keeps mux
// and /healthz for probes and humans. Without MTLS_DIR the service refuses to start, unless MTLS_INSECURE=true
// (local development), which serves workload on $PORT.
func RunMTLS(service string, mux, workload *http.ServeMux) {
	log := privacy.NewLogger(service)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	srvs := []*http.Server{{Addr: ":" + port, Handler: mux, ReadHeaderTimeout: 5 * time.Second}}
	if workload != nil {
		switch dir := os.Getenv("MTLS_DIR"); {
		case dir != "":
			cfg, err := WorkloadTLS(dir, splitList(os.Getenv("MTLS_ALLOW")))
			if err != nil {
				log.Error("workload TLS", "err", err)
				os.Exit(1)
			}
			mport := os.Getenv("MTLS_PORT")
			if mport == "" {
				mport = "8443"
			}
			srvs = append(srvs, &http.Server{Addr: ":" + mport, Handler: workload, TLSConfig: cfg, ReadHeaderTimeout: 5 * time.Second})
		case os.Getenv("MTLS_INSECURE") == "true":
			log.Warn("MTLS_INSECURE: workload routes served without client authentication")
			srvs[0].Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, pattern := workload.Handler(r); pattern != "" {
					workload.ServeHTTP(w, r)
					return
				}
				mux.ServeHTTP(w, r)
			})
		default:
			log.Error("MTLS_DIR not set: workload routes would be open to any pod (MTLS_INSECURE=true only for local development)")
			os.Exit(1)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	errc := make(chan error, len(srvs))
	for _, srv := range srvs {
		go func() {
			if srv.TLSConfig != nil {
				errc <- srv.ListenAndServeTLS("", "")
			} else {
				errc <- srv.ListenAndServe()
			}
		}()
		log.Info("listening", "addr", srv.Addr, "mtls", srv.TLSConfig != nil)
	}

	select {
	case err := <-errc:
		log.Error("server failed", "err", err)
		os.Exit(1)
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range srvs {
		if err := srv.Shutdown(shutdown); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("shutdown failed", "err", err)
		}
	}
}
