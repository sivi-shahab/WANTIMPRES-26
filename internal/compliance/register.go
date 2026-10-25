package compliance

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	"wantimpres26/internal/agents"
	"wantimpres26/internal/catalog"
)

// Entry is one AI system in the register (ISO/IEC 42001 A.4/A.6 inventory, OJK AI governance): what it is, who
// owns it, what it is for, its risk and status, and where data goes.
type Entry struct {
	Kind    string    `json:"kind"` // ai_app | agent | mcp_tool | enterprise_ai
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Vendor  string    `json:"vendor,omitempty"`
	Owner   string    `json:"owner,omitempty"`
	Unit    string    `json:"business_unit,omitempty"`
	Purpose string    `json:"purpose,omitempty"`
	Risk    string    `json:"risk,omitempty"`
	Status  string    `json:"status"`
	Region  string    `json:"hosting_region,omitempty"`
	OJKRef  string    `json:"ojk_approval_ref,omitempty"`
	Trains  *bool     `json:"trains_on_customer_data,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	AsOf    time.Time `json:"as_of"`
}

// RegisterSources are the inventories the register joins.
type RegisterSources struct {
	Apps   func(ctx context.Context) ([]catalog.View, error)
	Agents func(ctx context.Context) ([]agents.Agent, error)
}

// Register lists every AI system the platform knows of, now.
func (s *Store) Register(ctx context.Context, src RegisterSources, now time.Time) ([]Entry, error) {
	var out []Entry
	apps, err := src.Apps(ctx)
	if err != nil {
		return nil, fmt.Errorf("app catalog: %w", err)
	}
	for _, a := range apps {
		e := Entry{Kind: "ai_app", ID: a.ID, Name: a.Name, Vendor: a.Vendor, Status: a.Sanction, Region: a.HostingRegion, Trains: a.TrainsOnCustomerData,
			Purpose: a.Category, Detail: strings.Join(a.Flags, ","), AsOf: now}
		if a.Owner != nil {
			e.Owner = *a.Owner
		}
		if a.OJKApprovalRef != nil {
			e.OJKRef = *a.OJKApprovalRef
		}
		out = append(out, e)
	}
	as, err := src.Agents(ctx)
	if err != nil {
		return nil, fmt.Errorf("agent registry: %w", err)
	}
	for _, a := range as {
		e := Entry{Kind: "agent", ID: a.ID, Name: a.Name, Unit: a.BusinessUnit, Purpose: a.Purpose, Risk: a.RiskTier, Status: a.Status, AsOf: now,
			Detail: fmt.Sprintf("%d tool(s), identity %s", len(a.Tools), a.Identity.Type)}
		if a.Owner != nil {
			e.Owner = *a.Owner
		}
		if a.Model != nil {
			e.Vendor = *a.Model
		}
		out = append(out, e)
	}
	rows, err := s.DB.Query(ctx, "SELECT server, name, risk, status FROM agents.mcp_tools ORDER BY server, name")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var server, name, risk, status string
		if err := rows.Scan(&server, &name, &risk, &status); err != nil {
			return nil, err
		}
		out = append(out, Entry{Kind: "mcp_tool", ID: server + "/" + name, Name: name, Risk: risk, Status: status, Detail: "MCP server " + server, AsOf: now})
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	// Enterprise AI services the bank's data reaches, read through their compliance APIs (ticket 32).
	rows, err = s.DB.Query(ctx, "SELECT container_id, name, kind, last_scan FROM data.containers WHERE kind IN ('claude_enterprise', 'chatgpt_enterprise') ORDER BY 1")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, name, kind string
		var last *time.Time
		if err := rows.Scan(&id, &name, &kind, &last); err != nil {
			return nil, err
		}
		e := Entry{Kind: "enterprise_ai", ID: id, Name: name, Status: "monitored", AsOf: now, Detail: kind}
		if last != nil {
			e.Detail += ", last read " + last.Format(time.RFC3339)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RegisterCSV renders the register.
func RegisterCSV(es []Entry) ([]byte, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"kind", "id", "name", "vendor_or_model", "owner", "business_unit", "purpose", "risk", "status", "hosting_region", "ojk_approval_ref",
		"trains_on_customer_data", "detail", "as_of"})
	for _, e := range es {
		trains := ""
		if e.Trains != nil {
			trains = fmt.Sprint(*e.Trains)
		}
		_ = w.Write([]string{e.Kind, e.ID, e.Name, e.Vendor, e.Owner, e.Unit, e.Purpose, e.Risk, e.Status, e.Region, e.OJKRef, trains, e.Detail,
			e.AsOf.Format(time.RFC3339)})
	}
	w.Flush()
	return b.Bytes(), w.Error()
}
