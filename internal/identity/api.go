package identity

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"wantimpres26/internal/authz"
)

// Routes mounts role-binding management and /me on the admin router.
func Routes(rt *authz.Router, s *Store) {
	reply := func(w http.ResponseWriter, v any, err error) {
		switch {
		case errors.Is(err, ErrNotFound):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, ErrInvalid):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case err != nil:
			http.Error(w, "internal error", http.StatusInternalServerError)
		case v == nil:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	rt.Handle("GET /me", authz.Authenticated, func(w http.ResponseWriter, _ *http.Request, c authz.Caller) {
		reply(w, map[string]any{"user": c.Username, "permissions": c.Perms(time.Now()), "break_glass": c.BreakGlass}, nil)
	})
	rt.Handle("GET /identity/role-bindings", authz.IdentityRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		bs, err := s.ListBindings(r.Context())
		reply(w, bs, err)
	})
	rt.Handle("POST /identity/role-bindings", authz.IdentityAdmin, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b RoleBinding
		if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<10)).Decode(&b); err != nil {
			reply(w, nil, ErrInvalid)
			return
		}
		b, err := s.Bind(r.Context(), c.Username, b)
		reply(w, b, err)
	})
	rt.Handle("DELETE /identity/role-bindings/{id}", authz.IdentityAdmin, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		reply(w, nil, s.Unbind(r.Context(), c.Username, r.PathValue("id")))
	})
}
