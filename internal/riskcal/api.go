package riskcal

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"wantimpres26/internal/authz"
)

// Routes mounts the risk weight API. Proposing, editing and simulating need policy.write; approving and rejecting
// need policy.publish (sensitive: step-up + justification), like policy versions.
func Routes(rt *authz.Router, s *Store, now func() time.Time) {
	reply := func(w http.ResponseWriter, status int, v any, err error) {
		switch {
		case errors.Is(err, ErrNotFound):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, ErrInvalid), errors.Is(err, ErrTooFew):
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
	version := func(r *http.Request) (int, error) {
		v, err := strconv.Atoi(r.PathValue("v"))
		if err != nil {
			return 0, ErrInvalid
		}
		return v, nil
	}
	rt.Handle("GET /risk/versions", authz.PolicyRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		vs, err := s.Versions(r.Context())
		reply(w, http.StatusOK, map[string]any{"items": vs}, err)
	})
	// {"propose": true} fits the weights to last quarter's verdicts; {"config": {...}} stores a hand-made one.
	rt.Handle("POST /risk/versions", authz.PolicyWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var body struct {
			Propose bool           `json:"propose"`
			Config  map[string]any `json:"config"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body) != nil || body.Propose == (body.Config != nil) {
			reply(w, 0, nil, ErrInvalid)
			return
		}
		var v Version
		var err error
		if body.Propose {
			v, err = s.Propose(r.Context(), c.Username, now())
		} else {
			v, err = s.Create(r.Context(), c.Username, body.Config)
		}
		reply(w, http.StatusCreated, v, err)
	})
	act := func(perm, path string, f func(r *http.Request, c authz.Caller, v int) (any, error)) {
		rt.Handle("POST /risk/versions/{v}/"+path, perm, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
			v, err := version(r)
			var out any
			if err == nil {
				out, err = f(r, c, v)
			}
			reply(w, http.StatusOK, out, err)
		})
	}
	act(authz.PolicyWrite, "simulate", func(r *http.Request, c authz.Caller, v int) (any, error) {
		return s.Simulate(r.Context(), c.Username, v, now())
	})
	act(authz.PolicyWrite, "submit", func(r *http.Request, c authz.Caller, v int) (any, error) {
		return map[string]any{"state": "pending_approval"}, s.Submit(r.Context(), c.Username, v)
	})
	act(authz.PolicyPublish, "approve", func(r *http.Request, c authz.Caller, v int) (any, error) {
		n, err := s.Approve(r.Context(), c.Username, v)
		return map[string]any{"state": "active", "release": n}, err
	})
	act(authz.PolicyPublish, "reject", func(r *http.Request, c authz.Caller, v int) (any, error) {
		var body struct {
			Note string `json:"note"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<16)).Decode(&body)
		return map[string]any{"state": "draft"}, s.Reject(r.Context(), c.Username, v, body.Note)
	})
}
