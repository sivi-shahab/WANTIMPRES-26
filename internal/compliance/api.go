package compliance

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"wantimpres26/internal/authz"
)

// Routes mounts the compliance API: readers (compliance.read: CISO, DPO, auditor) see the library, statuses,
// reports and the register; writers (compliance.write: DPO) sign off mappings, attach evidence and collect.
func Routes(rt *authz.Router, s *Store, src Sources, reg RegisterSources, now func() time.Time) {
	reply := func(w http.ResponseWriter, v any, err error) {
		switch {
		case errors.Is(err, ErrNotFound):
			http.Error(w, err.Error(), http.StatusNotFound)
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
		if json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(v) != nil {
			return ErrInvalid
		}
		return nil
	}
	period := func(r *http.Request) (time.Time, time.Time, error) {
		from, err1 := time.Parse(time.RFC3339, r.URL.Query().Get("from"))
		to, err2 := time.Parse(time.RFC3339, r.URL.Query().Get("to"))
		if err1 != nil || err2 != nil {
			return time.Time{}, time.Time{}, ErrInvalid
		}
		return from, to, nil
	}
	csvReply := func(w http.ResponseWriter, name string, b []byte, err error) {
		if err != nil {
			reply(w, nil, err)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		// nosemgrep: no-direct-write-to-responsewriter -- text/csv download
		_, _ = w.Write(b)
	}

	rt.Handle("GET /compliance/frameworks", authz.ComplianceRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		fs, err := s.Frameworks(r.Context())
		reply(w, fs, err)
	})
	rt.Handle("GET /compliance/mappings", authz.ComplianceRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		ms, err := s.Mappings(r.Context(), r.URL.Query().Get("framework"), r.URL.Query().Get("version"), now())
		reply(w, ms, err)
	})
	rt.Handle("POST /compliance/mappings/verify", authz.ComplianceWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b struct {
			Mapping
			Status string `json:"status"`
			Source string `json:"source"`
			Note   string `json:"note"`
		}
		err := decode(r, &b)
		if err == nil {
			err = s.Verify(r.Context(), c.Username, b.Mapping, b.Status, b.Source, b.Note, now())
		}
		reply(w, map[string]string{"status": b.Status}, err)
	})
	rt.Handle("GET /compliance/controls", authz.ComplianceRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		st, err := s.Current(r.Context())
		reply(w, st, err)
	})
	rt.Handle("GET /compliance/controls/{id}/history", authz.ComplianceRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		from, to, err := period(r)
		var h []Transition
		if err == nil {
			h, err = s.History(r.Context(), r.PathValue("id"), from, to)
		}
		reply(w, h, err)
	})
	rt.Handle("POST /compliance/collect", authz.ComplianceWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		st, err := s.Collect(r.Context(), src, c.Username, now())
		reply(w, st, err)
	})
	rt.Handle("POST /compliance/evidence", authz.ComplianceWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b struct {
			Control string `json:"control_id"`
			Status  string `json:"status"`
			SHA256  string `json:"sha256"`
			Note    string `json:"note"`
		}
		err := decode(r, &b)
		var id int64
		if err == nil {
			id, err = s.Attach(r.Context(), c.Username, b.Control, b.Status, b.SHA256, b.Note, now())
		}
		reply(w, map[string]int64{"evidence_id": id}, err)
	})
	rt.Handle("GET /compliance/report", authz.ComplianceRead, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		from, to, err := period(r)
		var rep Report
		if err == nil {
			rep, err = s.Export(r.Context(), c.Username, from, to, now())
		}
		if r.URL.Query().Get("format") == "csv" {
			var b []byte
			if err == nil {
				b, err = rep.CSV()
			}
			csvReply(w, "compliance-"+from.Format("20060102")+"-"+to.Format("20060102")+".csv", b, err)
			return
		}
		reply(w, rep, err)
	})
	rt.Handle("GET /compliance/ai-register", authz.ComplianceRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		es, err := s.Register(r.Context(), reg, now())
		if r.URL.Query().Get("format") == "csv" {
			var b []byte
			if err == nil {
				b, err = RegisterCSV(es)
			}
			csvReply(w, "ai-register.csv", b, err)
			return
		}
		reply(w, es, err)
	})
}
