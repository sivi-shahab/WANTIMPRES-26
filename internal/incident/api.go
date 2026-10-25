package incident

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"wantimpres26/internal/authz"
)

// Routes mounts the §8.5 incident API. Raw evidence has its own route (…/raw) because it needs a different,
// sensitive permission than the metadata; the router enforces step-up re-auth and justification for it.
func Routes(rt *authz.Router, s *Store, now func() time.Time) {
	reply := func(w http.ResponseWriter, v any, err error) {
		switch {
		case errors.Is(err, ErrNotFound):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, ErrForbidden):
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, ErrInvalidTransition):
			http.Error(w, err.Error(), http.StatusConflict)
		case errors.Is(err, ErrInvalid):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case err != nil:
			http.Error(w, "internal error", http.StatusInternalServerError)
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	decode := func(r *http.Request, v any) error {
		if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<10)).Decode(v); err != nil {
			return ErrInvalidTransition
		}
		return nil
	}

	rt.Handle("GET /incidents", authz.IncidentRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		v, err := s.List(r.Context(), r.URL.Query().Get("severity"), r.URL.Query().Get("state"), 500)
		reply(w, v, err)
	})
	rt.Handle("GET /incidents/{id}", authz.IncidentRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		id := r.PathValue("id")
		inc, err := s.Get(r.Context(), id)
		if err != nil {
			reply(w, nil, err)
			return
		}
		evs, err := s.Events(r.Context(), id)
		if err != nil {
			reply(w, nil, err)
			return
		}
		ev, err := s.Evidence(r.Context(), id)
		if err != nil {
			reply(w, nil, err)
			return
		}
		acts, err := s.ActionsOf(r.Context(), id)
		if err != nil {
			reply(w, nil, err)
			return
		}
		blocks, err := s.BlocksOf(r.Context(), id)
		if err != nil {
			reply(w, nil, err)
			return
		}
		ticket, err := s.TicketOf(r.Context(), id)
		if err != nil {
			reply(w, nil, err)
			return
		}
		reqs, err := s.UnmaskRequests(r.Context(), id)
		reply(w, map[string]any{"incident": inc, "events": evs, "evidence": ev, "actions": acts, "blocks": blocks, "ticket": ticket,
			"unmask_requests": reqs}, err)
	})
	rt.Handle("POST /incidents/{id}/transition", authz.IncidentWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var body struct {
			To   State  `json:"to"`
			Note string `json:"note"`
		}
		if err := decode(r, &body); err != nil {
			reply(w, nil, err)
			return
		}
		v, err := s.Transition(r.Context(), r.PathValue("id"), body.To, body.Note, c.Username, now())
		reply(w, v, err)
	})
	rt.Handle("POST /incidents/{id}/severity", authz.IncidentWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var body struct {
			Severity string `json:"severity"`
			Note     string `json:"note"`
		}
		if err := decode(r, &body); err != nil {
			reply(w, nil, err)
			return
		}
		v, err := s.RaiseSeverity(r.Context(), r.PathValue("id"), body.Severity, body.Note, c.Username, now())
		reply(w, v, err)
	})
	rt.Handle("GET /incidents/{id}/evidence/{eid}", authz.IncidentRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		metas, err := s.Evidence(r.Context(), r.PathValue("id"))
		for _, m := range metas {
			if m.ID == r.PathValue("eid") {
				reply(w, m, err)
				return
			}
		}
		if err == nil {
			err = ErrNotFound
		}
		reply(w, nil, err)
	})
	// Ticket 45 four-eyes for restricted evidence: request, then a second analyst approves one use (1 h).
	rt.Handle("POST /incidents/{id}/evidence/{eid}/unmask-requests", authz.EvidenceUnmask, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		v, err := s.RequestUnmask(r.Context(), c, r.PathValue("id"), r.PathValue("eid"), authz.Justification(r), now())
		reply(w, v, err)
	})
	rt.Handle("POST /incidents/{id}/unmask-requests/{rid}/approve", authz.EvidenceUnmask, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		v, err := s.ApproveUnmask(r.Context(), c, r.PathValue("id"), r.PathValue("rid"), authz.Justification(r), now())
		reply(w, v, err)
	})
	rt.Handle("GET /incidents/{id}/evidence/{eid}/raw", authz.EvidenceUnmask, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		raw, err := s.Unmask(r.Context(), c, r.PathValue("id"), r.PathValue("eid"), authz.Justification(r), now())
		if err != nil {
			reply(w, nil, err)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(raw)
	})

	// FR-INC-5: {"action": "block_access"|"open_ticket"|…, "params": {…}}. Also the SOAR playbook entry point (a
	// service account with incident.write).
	rt.Handle("POST /incidents/{id}/actions", authz.IncidentWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var body struct {
			Action string            `json:"action"`
			Params map[string]string `json:"params"`
		}
		if err := decode(r, &body); err != nil {
			reply(w, nil, ErrInvalid)
			return
		}
		v, err := s.Contain(r.Context(), c, r.PathValue("id"), body.Action, body.Params, now())
		reply(w, v, err)
	})
	rt.Handle("POST /incidents/{id}/blocks/{bid}/lift", authz.IncidentWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		bid, err := strconv.ParseInt(r.PathValue("bid"), 10, 64)
		if err != nil {
			reply(w, nil, ErrNotFound)
			return
		}
		n, err := s.LiftBlock(r.Context(), r.PathValue("id"), bid, c.Username, now())
		reply(w, map[string]any{"release": n}, err)
	})

	// FR-INC-6 breach workflow. The SOC declares; the DPO closes the timer (notified or dismissed).
	rt.Handle("POST /incidents/{id}/breach/declare", authz.IncidentWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var body struct {
			Note string `json:"note"`
		}
		if err := decode(r, &body); err != nil {
			reply(w, nil, ErrInvalid)
			return
		}
		v, err := s.DeclareBreach(r.Context(), r.PathValue("id"), body.Note, c.Username, now())
		reply(w, v, err)
	})
	rt.Handle("POST /incidents/{id}/breach/close", authz.ComplianceWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var body struct {
			Outcome string `json:"outcome"`
			Note    string `json:"note"`
		}
		if err := decode(r, &body); err != nil {
			reply(w, nil, ErrInvalid)
			return
		}
		v, err := s.CloseBreach(r.Context(), r.PathValue("id"), body.Outcome, body.Note, c.Username, now())
		reply(w, v, err)
	})
	// The draft report: JSON, or ?format=md for the DPO.
	rt.Handle("GET /incidents/{id}/breach/report", authz.IncidentRead, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		rep, err := s.DraftBreachReport(r.Context(), r.PathValue("id"), c.Username, now())
		if err == nil && r.URL.Query().Get("format") == "md" {
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			_, _ = w.Write([]byte(rep.Markdown()))
			return
		}
		reply(w, rep, err)
	})
}
