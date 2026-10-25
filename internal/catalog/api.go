package catalog

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"wantimpres26/internal/authz"
)

// Routes mounts the app inventory (§8.4). Reading is posture information (dashboard.read: CISO, SOC, auditor…);
// changing status, adding local apps and importing feeds is configuration (config.write).
func Routes(rt *authz.Router, s *Store, feedPubPEM []byte, now func() time.Time) {
	reply := func(w http.ResponseWriter, status int, v any, err error) {
		switch {
		case errors.Is(err, ErrNotFound):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, ErrInvalid), errors.Is(err, ErrSignature):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, ErrStale):
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
		if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4<<20)).Decode(v); err != nil {
			return ErrInvalid
		}
		return nil
	}

	rt.Handle("GET /apps", authz.DashboardRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		q := r.URL.Query()
		o := ListOptions{Sanction: q.Get("sanction"), Flag: q.Get("flag"), Sort: q.Get("sort"), Limit: 50}
		if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
			o.Limit = min(l, 500)
		}
		if c := q.Get("cursor"); c != "" {
			raw, err := base64.RawURLEncoding.DecodeString(c)
			if o.Offset, _ = strconv.Atoi(string(raw)); err != nil || o.Offset < 0 {
				reply(w, 0, nil, ErrInvalid)
				return
			}
		}
		items, total, err := s.List(r.Context(), o, now())
		res := map[string]any{"items": items, "total": total}
		if next := o.Offset + len(items); next < total {
			res["next_cursor"] = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(next)))
		}
		reply(w, 200, res, err)
	})
	rt.Handle("GET /apps/report/residency", authz.DashboardRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		items, total, err := s.List(r.Context(), ListOptions{Flag: FlagOffshoreNoOJK, Sort: "-sensitive_events"}, now())
		reply(w, 200, map[string]any{"flag": FlagOffshoreNoOJK, "items": items, "total": total,
			"note": "Processing outside Indonesia (or of unknown location) without an OJK approval reference (ADR-0001, POJK 11)."}, err)
	})
	rt.Handle("GET /apps/{id}", authz.DashboardRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		items, _, err := s.List(r.Context(), ListOptions{}, now())
		for _, v := range items {
			if v.ID == r.PathValue("id") {
				reply(w, 200, v, err)
				return
			}
		}
		if err == nil {
			err = ErrNotFound
		}
		reply(w, 0, nil, err)
	})
	rt.Handle("PATCH /apps/{id}", authz.ConfigWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var p Patch
		if err := decode(r, &p); err != nil {
			reply(w, 0, nil, err)
			return
		}
		v, err := s.Update(r.Context(), c.Username, r.PathValue("id"), p)
		reply(w, 200, v, err)
	})
	rt.Handle("POST /apps", authz.ConfigWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var a App
		if err := decode(r, &a); err != nil {
			reply(w, 0, nil, err)
			return
		}
		reply(w, 201, map[string]any{"id": a.ID, "sanction": DefaultSanction}, s.AddLocal(r.Context(), c.Username, a))
	})
	rt.Handle("POST /catalog/feed", authz.ConfigWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b struct {
			Feed      string `json:"feed"`      // the feed JSON exactly as signed
			Signature string `json:"signature"` // base64 ECDSA over SHA-256 of Feed
		}
		if err := decode(r, &b); err != nil {
			reply(w, 0, nil, err)
			return
		}
		v, err := s.ImportSigned(r.Context(), c.Username, []byte(b.Feed), b.Signature, feedPubPEM)
		reply(w, 200, map[string]any{"version": v}, err)
	})

	// Ticket 43: the provider domains the network team allows only from the AI gateway's egress IPs. JSON, or
	// ?format=txt for a firewall/SWG FQDN object (one domain per line; each covers its subdomains).
	rt.Handle("GET /catalog/egress", authz.ConfigRead, func(w http.ResponseWriter, r *http.Request, _ authz.Caller) {
		apps, err := s.Apps(r.Context())
		entries := ProviderDomains(apps)
		if err == nil && r.URL.Query().Get("format") == "txt" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			for _, e := range entries {
				_, _ = fmt.Fprintln(w, e.Domain)
			}
			return
		}
		reply(w, 200, map[string]any{"items": entries}, err)
	})
	// Findings from shadow-baseline -servers (the gateway_bypass list of its JSON report).
	rt.Handle("POST /catalog/gateway-bypass", authz.ConfigWrite, func(w http.ResponseWriter, r *http.Request, c authz.Caller) {
		var b struct {
			GatewayBypass []Bypass `json:"gateway_bypass"`
		}
		if err := decode(r, &b); err != nil {
			reply(w, 0, nil, err)
			return
		}
		n, err := s.ReportBypass(r.Context(), c.Username, b.GatewayBypass)
		reply(w, 200, map[string]any{"received": len(b.GatewayBypass), "new": n}, err)
	})
}
