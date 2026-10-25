package posture

import (
	"encoding/json"
	"net/http"
	"time"

	"wantimpres26/internal/authz"
)

// Routes mounts GET /posture (dashboard.read: CISO, SOC, DPO, auditor, …; read-only by construction).
func Routes(rt *authz.Router, src Sources, now func() time.Time) {
	rt.Handle("GET /posture", authz.DashboardRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		rep, err := src.Compute(r.Context(), now())
		if err != nil {
			http.Error(w, "posture unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(rep)
	})
}
