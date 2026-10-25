package agents

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"wantimpres26/internal/authz"
)

var errScope = errors.New("outside your business unit")

// Routes mounts the registry API. Reads need agent.read; writes need agent.write *for the agent's business unit*
// (ABAC: an agent owner bound to unit "retail" cannot change a "treasury" agent, or move one there).
func Routes(rt *authz.Router, s *Store, now func() time.Time) {
	reply := func(w http.ResponseWriter, status int, v any, err error) {
		switch {
		case errors.Is(err, ErrNotFound):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, ErrInvalid):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, errScope), errors.Is(err, errSelf):
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, ErrExpired):
			http.Error(w, err.Error(), http.StatusGone)
		case errors.Is(err, ErrConflict):
			http.Error(w, err.Error(), http.StatusConflict)
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
	inUnit := func(c authz.Caller, units ...string) error {
		for _, u := range units {
			if !c.Can(authz.AgentWrite, authz.Resource{BusinessUnit: u}, now()) {
				return errScope
			}
		}
		return nil
	}

	rt.Handle("GET /agents", authz.AgentRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		as, err := s.List(r.Context(), r.URL.Query().Get("status"))
		reply(w, 200, as, err)
	})
	rt.Handle("GET /agents/summary", authz.DashboardRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		sum, err := s.Summarize(r.Context())
		reply(w, 200, sum, err)
	})
	rt.Handle("GET /agents/discovered", authz.AgentRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		ds, err := s.Discovered(r.Context(), r.URL.Query().Get("state"))
		reply(w, 200, ds, err)
	})
	rt.Handle("POST /agents/discovered/{id}/dismiss", authz.AgentWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b struct {
			Note string `json:"note"`
		}
		if err := decode(r, &b); err != nil {
			reply(w, 0, nil, err)
			return
		}
		reply(w, 200, map[string]any{"agent_id": r.PathValue("id"), "state": "dismissed"}, s.Dismiss(r.Context(), c.Username, r.PathValue("id"), b.Note))
	})
	rt.Handle("GET /agents/{id}", authz.AgentRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		a, err := s.Get(r.Context(), r.PathValue("id"))
		reply(w, 200, a, err)
	})
	rt.Handle("POST /agents", authz.AgentWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var a Agent
		if err := decode(r, &a); err != nil {
			reply(w, 0, nil, err)
			return
		}
		if err := inUnit(c, a.BusinessUnit); err != nil {
			reply(w, 0, nil, err)
			return
		}
		a, err := s.Register(r.Context(), c.Username, a)
		reply(w, 201, a, err)
	})
	rt.Handle("PUT /agents/{id}", authz.AgentWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var a Agent
		if err := decode(r, &a); err != nil {
			reply(w, 0, nil, err)
			return
		}
		a.ID = r.PathValue("id")
		cur, err := s.Get(r.Context(), a.ID)
		if err == nil {
			err = inUnit(c, cur.BusinessUnit, a.BusinessUnit)
		}
		if err == nil {
			a, err = s.Update(r.Context(), c.Username, a)
		}
		reply(w, 200, a, err)
	})
	rt.Handle("POST /agents/{id}/status", authz.AgentWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			reply(w, 0, nil, err)
			return
		}
		cur, err := s.Get(r.Context(), r.PathValue("id"))
		if err == nil {
			err = inUnit(c, cur.BusinessUnit)
		}
		var a Agent
		if err == nil {
			a, err = s.SetStatus(r.Context(), c.Username, cur.ID, b.Status, b.Reason)
		}
		reply(w, 200, a, err)
	})

	// MCP tool definitions (ticket 29): the risk report and the review queue are visible to agent readers;
	// approving or rejecting a definition is a security configuration decision.
	rt.Handle("GET /mcp/tools", authz.AgentRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		ts, err := s.Tools(r.Context(), r.URL.Query().Get("server"), r.URL.Query().Get("status"))
		reply(w, 200, ts, err)
	})
	rt.Handle("GET /mcp/tools/report", authz.AgentRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		rep, err := s.ToolReport(r.Context())
		reply(w, 200, rep, err)
	})
	rt.Handle("POST /mcp/tools/{server}/{name}/approve", authz.ConfigWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b struct {
			Hash string `json:"hash"`
			Note string `json:"note"`
		}
		if err := decode(r, &b); err != nil {
			reply(w, 0, nil, err)
			return
		}
		t, err := s.ApproveTool(r.Context(), c.Username, r.PathValue("server"), r.PathValue("name"), b.Hash, b.Note)
		reply(w, 200, t, err)
	})
	rt.Handle("POST /mcp/tools/{server}/{name}/reject", authz.ConfigWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b struct {
			Note string `json:"note"`
		}
		if err := decode(r, &b); err != nil {
			reply(w, 0, nil, err)
			return
		}
		t, err := s.RejectTool(r.Context(), c.Username, r.PathValue("server"), r.PathValue("name"), b.Note)
		reply(w, 200, t, err)
	})

	// HITL approvals (ticket 30). Approvers act within the units of their binding, never on agents they own.
	rt.Handle("GET /approvals", authz.AgentRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		as, err := s.Approvals(r.Context(), r.URL.Query().Get("state"), now())
		reply(w, 200, as, err)
	})
	rt.Handle("GET /approvals/{id}", authz.AgentRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		a, err := s.GetApproval(r.Context(), r.PathValue("id"))
		reply(w, 200, a, err)
	})
	for verb, approve := range map[string]bool{"approve": true, "reject": false} {
		rt.Handle("POST /approvals/{id}/"+verb, authz.AgentApprove, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
			var b struct {
				Note string `json:"note"`
			}
			if err := decode(r, &b); err != nil {
				reply(w, 0, nil, err)
				return
			}
			a, err := s.DecideApproval(r.Context(), c.Username, r.PathValue("id"), approve, b.Note, now(), func(ag Agent) error {
				if !c.Can(authz.AgentApprove, authz.Resource{BusinessUnit: ag.BusinessUnit}, now()) {
					return errScope
				}
				return nil
			})
			reply(w, 200, a, err)
		})
	}

	// Kill switches (ticket 30): an owner kills their own agent; SOC kills any agent, tool or app; global needs
	// agent.kill.global (sensitive: fresh login and justification).
	rt.Handle("GET /kills", authz.AgentRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		ks, err := s.Kills(r.Context(), r.URL.Query().Get("all") != "true")
		reply(w, 200, ks, err)
	})
	type killBody struct {
		Scope  string `json:"scope"`
		Target string `json:"target"`
		Reason string `json:"reason"`
	}
	rt.Handle("POST /agents/{id}/kill", authz.AgentWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b killBody
		if err := decode(r, &b); err != nil {
			reply(w, 0, nil, err)
			return
		}
		cur, err := s.Get(r.Context(), r.PathValue("id"))
		if err == nil {
			err = inUnit(c, cur.BusinessUnit)
		}
		var k Kill
		if err == nil {
			k, err = s.SetKill(r.Context(), c.Username, "agent", cur.ID, b.Reason)
		}
		reply(w, 201, k, err)
	})
	rt.Handle("POST /kills", authz.IncidentWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b killBody
		err := decode(r, &b)
		if err == nil && b.Scope == "global" {
			err = errScope // POST /kills/global
		}
		var k Kill
		if err == nil {
			k, err = s.SetKill(r.Context(), c.Username, b.Scope, b.Target, b.Reason)
		}
		reply(w, 201, k, err)
	})
	rt.Handle("POST /kills/global", authz.AgentKillGlobal, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b killBody
		err := decode(r, &b)
		var k Kill
		if err == nil {
			k, err = s.SetKill(r.Context(), c.Username, "global", "", b.Reason)
		}
		reply(w, 201, k, err)
	})
	lift := func(global bool) func(http.ResponseWriter, *http.Request, authz.Caller) {
		return func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
			id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
			if err != nil {
				reply(w, 0, nil, ErrNotFound)
				return
			}
			k, err := s.LiftKill(r.Context(), c.Username, id, global)
			reply(w, 200, k, err)
		}
	}
	rt.Handle("POST /kills/{id}/lift", authz.IncidentWrite, lift(false))
	rt.Handle("POST /kills/global/{id}/lift", authz.AgentKillGlobal, lift(true))
}
