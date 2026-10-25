package lifecycle

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"wantimpres26/internal/authz"
)

// Routes mounts the policy lifecycle API (spec §8.3, FR-POL-5..7). Authoring needs policy.write; approving,
// rejecting, rolling back, retiring and deciding exceptions need policy.publish (sensitive: step-up + justification).
func Routes(rt *authz.Router, s *Store, sim *Simulator, now func() time.Time) {
	reply := func(w http.ResponseWriter, status int, v any, err error) {
		switch {
		case errors.Is(err, ErrNotFound):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, ErrInvalid):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, ErrState):
			http.Error(w, err.Error(), http.StatusConflict)
		case errors.Is(err, ErrFourEyes):
			http.Error(w, err.Error(), http.StatusForbidden)
		case err != nil:
			http.Error(w, "internal error", http.StatusInternalServerError)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	decode := func(r *http.Request, v any) error {
		if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(v); err != nil {
			return ErrInvalid
		}
		return nil
	}
	version := func(r *http.Request) (int, error) {
		v, err := strconv.Atoi(r.PathValue("v"))
		if err != nil {
			return 0, ErrInvalid
		}
		return v, nil
	}
	type rulesBody struct {
		Name  string `json:"name"`
		Rules []any  `json:"rules"`
	}

	rt.Handle("GET /policies", authz.PolicyRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		vs, err := s.Versions(r.Context(), "")
		reply(w, 200, vs, err)
	})
	rt.Handle("POST /policies", authz.PolicyWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b rulesBody
		if err := decode(r, &b); err != nil {
			reply(w, 0, nil, err)
			return
		}
		id, err := s.CreatePolicy(r.Context(), c.Username, b.Name, b.Rules)
		reply(w, 201, map[string]any{"id": id, "version": 1}, err)
	})
	rt.Handle("GET /policies/{id}", authz.PolicyRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		vs, err := s.Versions(r.Context(), r.PathValue("id"))
		if err == nil && len(vs) == 0 {
			err = ErrNotFound
		}
		reply(w, 200, vs, err)
	})
	rt.Handle("POST /policies/{id}/versions", authz.PolicyWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b rulesBody
		if err := decode(r, &b); err != nil {
			reply(w, 0, nil, err)
			return
		}
		v, err := s.NewVersion(r.Context(), c.Username, r.PathValue("id"), b.Rules)
		reply(w, 201, map[string]any{"version": v}, err)
	})
	rt.Handle("PUT /policies/{id}/versions/{v}", authz.PolicyWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b rulesBody
		v, err := version(r)
		if err == nil {
			err = decode(r, &b)
		}
		if err == nil {
			err = s.UpdateDraft(r.Context(), c.Username, r.PathValue("id"), v, b.Rules)
		}
		reply(w, 200, map[string]any{"version": v, "state": Draft}, err)
	})
	rt.Handle("POST /policies/{id}/simulate", authz.PolicyWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b struct {
			Version int `json:"version"`
			Window  struct {
				From time.Time `json:"from"`
				To   time.Time `json:"to"`
			} `json:"window"`
			IncludeCorpus bool `json:"include_corpus"`
		}
		if err := decode(r, &b); err != nil {
			reply(w, 0, nil, err)
			return
		}
		id, err := sim.Start(r.Context(), c.Username, r.PathValue("id"), b.Version, b.Window.From, b.Window.To, b.IncludeCorpus)
		reply(w, http.StatusAccepted, map[string]any{"simulation_id": id, "status": "/simulations/" + id}, err)
	})
	rt.Handle("GET /simulations/{id}", authz.PolicyRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		res, err := s.Simulation(r.Context(), r.PathValue("id"))
		reply(w, 200, res, err)
	})
	rt.Handle("POST /policies/{id}/versions/{v}/submit", authz.PolicyWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		v, err := version(r)
		if err == nil {
			err = s.Submit(r.Context(), c.Username, r.PathValue("id"), v)
		}
		reply(w, 200, map[string]any{"version": v, "state": PendingApproval}, err)
	})
	rt.Handle("POST /policies/{id}/versions/{v}/approve", authz.PolicyPublish, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		v, err := version(r)
		var n int64
		if err == nil {
			n, err = s.Approve(r.Context(), c.Username, r.PathValue("id"), v)
		}
		reply(w, 200, map[string]any{"version": v, "state": Active, "release": n}, err)
	})
	rt.Handle("POST /policies/{id}/versions/{v}/reject", authz.PolicyPublish, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		v, err := version(r)
		if err == nil {
			err = s.Reject(r.Context(), c.Username, r.PathValue("id"), v, authz.Justification(r))
		}
		reply(w, 200, map[string]any{"version": v, "state": Draft}, err)
	})
	rt.Handle("POST /policies/{id}/versions/{v}/retire", authz.PolicyPublish, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		v, err := version(r)
		var n int64
		if err == nil {
			n, err = s.Retire(r.Context(), c.Username, r.PathValue("id"), v)
		}
		reply(w, 200, map[string]any{"version": v, "state": Retired, "release": n}, err)
	})
	rt.Handle("POST /policies/{id}/rollback", authz.PolicyPublish, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		n, err := s.Rollback(r.Context(), c.Username, r.PathValue("id"))
		reply(w, 200, map[string]any{"release": n}, err)
	})
	rt.Handle("GET /policy-releases", authz.PolicyRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		rs, err := s.Releases(r.Context(), 100)
		reply(w, 200, rs, err)
	})

	rt.Handle("GET /exceptions", authz.PolicyRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		es, err := s.Exceptions(r.Context())
		reply(w, 200, es, err)
	})
	rt.Handle("POST /exceptions", authz.PolicyWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var e Exception
		if err := decode(r, &e); err != nil {
			reply(w, 0, nil, err)
			return
		}
		id, err := s.RequestException(r.Context(), c.Username, e, now())
		reply(w, 201, map[string]any{"id": id, "state": "pending"}, err)
	})
	rt.Handle("POST /exceptions/{id}/approve", authz.PolicyPublish, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		n, err := s.ApproveException(r.Context(), c.Username, r.PathValue("id"), now())
		reply(w, 200, map[string]any{"state": "active", "release": n}, err)
	})
	rt.Handle("POST /exceptions/{id}/revoke", authz.PolicyPublish, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		n, err := s.RevokeException(r.Context(), c.Username, r.PathValue("id"))
		reply(w, 200, map[string]any{"state": "revoked", "release": n}, err)
	})
}
