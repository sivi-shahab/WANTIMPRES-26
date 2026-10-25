package catalog

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"wantimpres26/internal/audit"
)

// Ticket 43 (threat model G4): LLM traffic must go through the AI gateway. The network team allows the provider
// domains below only from the gateway's egress IPs; anything else reaching them from a server subnet is a bypass.

// EgressEntry is one domain of an AI provider with an API (an app whose fingerprint has API endpoints).
type EgressEntry struct {
	Domain        string `json:"domain"`
	AppID         string `json:"app_id"`
	Vendor        string `json:"vendor"`
	HostingRegion string `json:"hosting_region"`
}

// ProviderDomains lists every domain of the apps that expose an API, sorted by domain. The provider's web domains
// are in too: a server has no business reaching chatgpt.com either, and a domain left out is a way around.
// A domain matches its subdomains (the same rule as the fingerprint matcher).
func ProviderDomains(apps []App) []EgressEntry {
	var out []EgressEntry
	seen := map[string]bool{}
	for _, a := range apps {
		if len(a.APIEndpoints) == 0 {
			continue
		}
		for _, d := range a.Domains {
			d = strings.ToLower(strings.TrimSuffix(d, "."))
			if d == "" || seen[d] {
				continue
			}
			seen[d] = true
			out = append(out, EgressEntry{Domain: d, AppID: a.ID, Vendor: a.Vendor, HostingRegion: a.HostingRegion})
		}
	}
	// A domain already covered by a parent in the list (www.perplexity.ai under perplexity.ai) is left out.
	all := slices.Clone(out)
	out = slices.DeleteFunc(out, func(e EgressEntry) bool {
		return slices.ContainsFunc(all, func(p EgressEntry) bool { return p.Domain != e.Domain && domainMatches(e.Domain, p.Domain) })
	})
	slices.SortFunc(out, func(a, b EgressEntry) int { return strings.Compare(a.Domain, b.Domain) })
	return out
}

// ProviderFor returns the entry a host falls under, if any.
func ProviderFor(entries []EgressEntry, host string) (EgressEntry, bool) {
	for _, e := range entries {
		if domainMatches(host, e.Domain) {
			return e, true
		}
	}
	return EgressEntry{}, false
}

// Bypass is a server seen reaching a provider domain without the gateway (from SWG/DNS logs, shadow-baseline).
// Server is an address inside a declared server subnet: infrastructure, not a person.
type Bypass struct {
	Server     string    `json:"server"`
	Domain     string    `json:"domain"`
	AppID      string    `json:"app_id"`
	Requests   int       `json:"requests"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	ReportedBy string    `json:"reported_by,omitempty"`
}

// ReportBypass stores findings (merged per server and domain) and audits each pair seen for the first time, so the
// SIEM gets an event for every new bypass.
func (s *Store) ReportBypass(ctx context.Context, actor string, bs []Bypass) (newPairs int, err error) {
	for _, b := range bs {
		if _, err := netip.ParseAddr(b.Server); err != nil || b.Domain == "" || b.Requests < 1 || b.LastSeen.Before(b.FirstSeen) {
			return 0, fmt.Errorf("%w: bypass needs a server IP, a domain, requests >= 1 and first_seen <= last_seen", ErrInvalid)
		}
	}
	err = pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		newPairs = 0
		for _, b := range bs {
			var inserted bool
			err := tx.QueryRow(ctx, `INSERT INTO catalog.gateway_bypass (server, domain, app_id, requests, first_seen, last_seen, reported_by)
				VALUES ($1, $2, $3, $4, $5, $6, $7)
				ON CONFLICT (server, domain) DO UPDATE SET requests = catalog.gateway_bypass.requests + excluded.requests,
				  first_seen = least(catalog.gateway_bypass.first_seen, excluded.first_seen),
				  last_seen = greatest(catalog.gateway_bypass.last_seen, excluded.last_seen), reported_by = excluded.reported_by
				RETURNING xmax = 0`, b.Server, strings.ToLower(b.Domain), b.AppID, b.Requests, b.FirstSeen, b.LastSeen, actor).Scan(&inserted)
			if err != nil {
				return err
			}
			if !inserted {
				continue
			}
			newPairs++
			if _, err := audit.AppendTx(ctx, tx, s.tenant, actor, "catalog.gateway_bypass", map[string]any{"server": b.Server, "domain": b.Domain,
				"app": b.AppID, "requests": b.Requests, "first_seen": b.FirstSeen}); err != nil {
				return err
			}
		}
		return nil
	})
	return newPairs, err
}

// Bypasses lists findings with traffic since `since`, most recent first.
func (s *Store) Bypasses(ctx context.Context, since time.Time) ([]Bypass, error) {
	rows, err := s.db.Query(ctx, `SELECT server, domain, app_id, requests, first_seen, last_seen, reported_by FROM catalog.gateway_bypass
		WHERE last_seen >= $1 ORDER BY last_seen DESC, server, domain`, since)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Bypass])
}
