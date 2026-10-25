package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"wantimpres26/internal/detect"
	"wantimpres26/internal/l2"
	"wantimpres26/internal/privacy"
	"wantimpres26/internal/server"
	"wantimpres26/internal/similarity"
	"wantimpres26/internal/tenantdb"
	"wantimpres26/internal/tuning"
)

// maxContent: spec §8.1 caps content at 256 KB.
const maxContent = 256 << 10

// scanText is POST /scan/text (spec §8.1) without policy evaluation yet: L1 findings less those the tenant tuning
// model judges false positives (ticket 38), registered confidential documents found (ticket 37), sensitivity, and the
// redacted snippet PEPs put in the decision event. Content is never logged or echoed back; matches carry offsets,
// not values.
func scanText(tuned *tuning.Live, similar *similarity.Live, model *l2.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Content   string `json:"content"`
			Channel   string `json:"channel"`
			Direction string `json:"direction"`
			Context   struct {
				AppID string `json:"app_id"`
				Trust string `json:"trust"` // trusted | untrusted (FR-PSEC-2)
			} `json:"context"`
		}
		err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxContent+16<<10)).Decode(&req)
		var tooBig *http.MaxBytesError
		switch {
		case errors.As(err, &tooBig) || len(req.Content) > maxContent:
			http.Error(w, "content exceeds 256 KB", http.StatusRequestEntityTooLarge)
			return
		case err != nil:
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		var res struct {
			detect.Result
			Similar []similarity.Hit `json:"similar,omitempty"`
			Tuning  *tuning.Report   `json:"tuning,omitempty"`
			L2      *l2.Report       `json:"l2,omitempty"`
			Snippet string           `json:"snippet"`
		}
		res.Result, res.Tuning = tuned.Apply(req.Content, detect.Scan(req.Content), req.Channel, req.Direction, req.Context.AppID)
		res.Result, res.L2 = model.Add(r.Context(), res.Result, req.Content, req.Context.Trust)
		res.Similar = similar.Index().Match(req.Content)
		similarity.Apply(&res.Result, res.Similar)
		res.Snippet = detect.Snippet(req.Content, res.Matches)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	}
}

// l2Client is the L2 model (tickets 09-10) from MODEL_INFERENCE_URL (unset: L1 only), L2_MODE (shadow, the
// default, or enforce: spec §9.4 rollout) and L2_TIMEOUT (Go duration, default 80ms: the 50 ms p95 budget plus
// headroom; past it the L1 result stands).
func l2Client() *l2.Client {
	url := os.Getenv("MODEL_INFERENCE_URL")
	if url == "" {
		return nil
	}
	// model-inference serves mTLS only, to detection-svc (ticket 40).
	hc, err := server.MTLSClient(0, "spiffe://wantimpres26.bank/ns/wantimpres26/sa/model-inference")
	if err != nil {
		fmt.Fprintln(os.Stderr, "detection-svc: model-inference client:", err)
		os.Exit(1)
	}
	c := &l2.Client{URL: url, Mode: l2.Shadow, Timeout: 80 * time.Millisecond, HTTP: hc}
	if os.Getenv("L2_MODE") == l2.Enforce {
		c.Mode = l2.Enforce
	}
	if d, err := time.ParseDuration(os.Getenv("L2_TIMEOUT")); err == nil && d > 0 {
		c.Timeout = d
	}
	return c
}

// Env: MTLS_DIR, MTLS_ALLOW (internal/server, ticket 40). Optional (without it only L1 runs): MODEL_INFERENCE_URL, L2_MODE, L2_TIMEOUT (l2Client); DATABASE_URL (read access to similarity.docs and tuning.models), TENANT_ID,
// TENANT_PEPPER.
func main() {
	var similar *similarity.Live
	var tuned *tuning.Live
	if url := os.Getenv("DATABASE_URL"); url != "" {
		log := privacy.NewLogger("detection-svc")
		ctx := context.Background()
		db, err := tenantdb.Pool(ctx, url, os.Getenv("TENANT_ID"))
		if err == nil {
			similar, err = similarity.Watch(ctx, db, os.Getenv("TENANT_ID"), []byte(os.Getenv("TENANT_PEPPER")), time.Minute, log)
		}
		if err == nil {
			tuned, err = tuning.Watch(ctx, db, os.Getenv("TENANT_ID"), []byte(os.Getenv("TENANT_PEPPER")), time.Minute, log)
		}
		if err != nil {
			log.Error("similarity index or tuning models", "err", err)
			os.Exit(1)
		}
	}
	// Scanning is for PEP workloads only (ticket 40): on the mTLS listener, never on the probe port.
	server.RunMTLS("detection-svc", http.NewServeMux(), workloadRoutes(tuned, similar))
}

func workloadRoutes(tuned *tuning.Live, similar *similarity.Live) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /scan/text", scanText(tuned, similar, l2Client()))
	return mux
}
