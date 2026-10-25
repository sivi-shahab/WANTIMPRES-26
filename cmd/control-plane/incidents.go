package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"wantimpres26/internal/agents"
	"wantimpres26/internal/authz"
	"wantimpres26/internal/connector"
	"wantimpres26/internal/incident"
	"wantimpres26/internal/remediate"
)

// wireIncidents adds what ticket 26 needs from outside the incident module: the ITSM, the containment actions
// other modules own, and the breach timer sweep.
//
// Env: ITSM_KIND (servicenow|jira-sm; empty = none), ITSM_URL, ITSM_AUTH_FILE (Authorization header value),
// JIRA_SERVICEDESK_ID and JIRA_REQUEST_TYPE_ID (jira-sm).
func wireIncidents(ctx context.Context, s *incident.Store, registry *agents.Store, rem *remediate.Store, log *slog.Logger) error {
	if kind := os.Getenv("ITSM_KIND"); kind != "" {
		raw, err := os.ReadFile(os.Getenv("ITSM_AUTH_FILE"))
		if err != nil {
			return fmt.Errorf("ITSM_AUTH_FILE: %w", err)
		}
		auth, url, client := strings.TrimSpace(string(raw)), os.Getenv("ITSM_URL"), &http.Client{Timeout: 30 * time.Second}
		switch kind {
		case "servicenow":
			s.ITSM = &incident.ServiceNow{URL: url, Auth: auth, Client: client}
		case "jira-sm":
			s.ITSM = &incident.JiraSM{URL: url, Auth: auth, ServiceDeskID: os.Getenv("JIRA_SERVICEDESK_ID"),
				RequestTypeID: os.Getenv("JIRA_REQUEST_TYPE_ID"), Client: client}
		default:
			return fmt.Errorf("ITSM_KIND %q: servicenow or jira-sm", kind)
		}
	}

	// Kill switch for an agent, tool or app (the agent's token is useless while it is killed: every PDP blocks it
	// and the MCP gateways cut its sessions). Same permission as POST /kills; global stays on POST /kills/global.
	s.Actions["kill_switch"] = incident.Action{Run: func(ctx context.Context, actor string, inc incident.Incident, p map[string]string, _ time.Time) (map[string]any, error) {
		if p["scope"] == "global" {
			return nil, fmt.Errorf("%w: a global kill switch goes through POST /kills/global", incident.ErrInvalid)
		}
		k, err := registry.SetKill(ctx, actor, p["scope"], p["target"], fmt.Sprintf("incident %s: %s", inc.ID, p["reason"]))
		return map[string]any{"kill_id": k.ID, "scope": k.Scope, "target": k.Target}, invalid(err, agents.ErrInvalid, agents.ErrNotFound)
	}}
	// Revoke anonymous share links on a data asset: a remediation request, approved by a second person (FR-DATA-6).
	s.Actions["revoke_share_link"] = incident.Action{Perm: authz.DataRemediate, Run: func(ctx context.Context, actor string, inc incident.Incident, p map[string]string, now time.Time) (map[string]any, error) {
		r, err := rem.Request(ctx, actor, p["asset_id"], connector.Action{Kind: connector.RevokeAnyoneLinks}, "incident "+inc.ID+": "+p["note"], now)
		return map[string]any{"remediation": r.ID, "state": r.State}, invalid(err, remediate.ErrInvalid, remediate.ErrNotFound)
	}}

	go func() {
		for t := time.NewTicker(time.Minute); ctx.Err() == nil; <-t.C {
			if n, err := s.SweepBreaches(ctx, time.Now()); err != nil {
				log.Error("breach timer sweep", "err", err)
			} else if n > 0 {
				log.Warn("breach timers escalated: less than 24 h to notify", "count", n)
			}
		}
	}()
	return nil
}

// invalid turns another module's bad-request errors into the incident API's 400.
func invalid(err error, bad ...error) error {
	for _, b := range bad {
		if errors.Is(err, b) {
			return fmt.Errorf("%w: %v", incident.ErrInvalid, err)
		}
	}
	return err
}
