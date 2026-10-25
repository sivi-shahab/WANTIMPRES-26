package remediate

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"wantimpres26/internal/authz"
	"wantimpres26/internal/connector"
)

// Routes mounts the remediation API (control-plane).
func Routes(rt *authz.Router, s *Store, now func() time.Time) {
	reply := func(w http.ResponseWriter, status int, v any, err error) {
		switch {
		case errors.Is(err, ErrNotFound):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, ErrInvalid):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, ErrSelf):
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, ErrState):
			http.Error(w, err.Error(), http.StatusConflict)
		case err != nil:
			http.Error(w, "internal error", http.StatusInternalServerError)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	type body struct {
		Action connector.Action `json:"action"`
		Note   string           `json:"note"`
	}
	decode := func(r *http.Request, v any) error {
		if json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(v) != nil {
			return ErrInvalid
		}
		return nil
	}
	rt.Handle("POST /data/assets/{id}/remediations", authz.DataRemediate, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b body
		err := decode(r, &b)
		var rem Remediation
		if err == nil {
			rem, err = s.Request(r.Context(), c.Username, r.PathValue("id"), b.Action, b.Note, now())
		}
		reply(w, http.StatusCreated, rem, err)
	})
	rt.Handle("GET /data/remediations", authz.DashboardRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		rs, err := s.List(r.Context(), r.URL.Query().Get("state"), r.URL.Query().Get("asset_id"))
		reply(w, http.StatusOK, rs, err)
	})
	rt.Handle("GET /data/remediations/{id}", authz.DashboardRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		rem, err := s.Get(r.Context(), r.PathValue("id"))
		reply(w, http.StatusOK, rem, err)
	})
	for verb, approve := range map[string]bool{"approve": true, "reject": false} {
		rt.Handle("POST /data/remediations/{id}/"+verb, authz.DataApprove, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
			var b body
			err := decode(r, &b)
			var rem Remediation
			if err == nil {
				rem, err = s.Decide(r.Context(), c.Username, r.PathValue("id"), approve, b.Note, now())
			}
			reply(w, http.StatusOK, rem, err)
		})
	}
	rt.Handle("POST /data/remediations/{id}/undo", authz.DataRemediate, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b body
		err := decode(r, &b)
		var rem Remediation
		if err == nil {
			rem, err = s.RequestUndo(r.Context(), c.Username, r.PathValue("id"), b.Note, now())
		}
		reply(w, http.StatusCreated, rem, err)
	})
}
