package agents

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"wantimpres26/internal/audit"
	"wantimpres26/internal/mcptools"
)

// --- MCP tool definitions: pin, scan, re-approve on change (FR-AGT-3, ticket 29) ---------------------------

// MCPTool is one tool of one MCP server as last seen in tools/list, with its scan and approval.
type MCPTool struct {
	Server       string         `json:"server"`
	Name         string         `json:"name"`
	Hash         string         `json:"hash"`
	Definition   map[string]any `json:"definition"`
	Risk         string         `json:"risk"`
	Score        float64        `json:"score"`
	Signals      []string       `json:"signals"`
	Status       string         `json:"status"` // approved | under_review | rejected
	ApprovedHash *string        `json:"approved_hash"`
	FirstSeen    time.Time      `json:"first_seen"`
	LastSeen     time.Time      `json:"last_seen"`
	DecidedBy    *string        `json:"decided_by,omitempty"`
	DecidedAt    *time.Time     `json:"decided_at,omitempty"`
	Note         *string        `json:"note,omitempty"`
}

// Callable: approved, and what the server now serves is what was approved.
func (t MCPTool) Callable() bool {
	return t.Status == "approved" && t.ApprovedHash != nil && *t.ApprovedHash == t.Hash
}

// ToolState is what the gateway learns back from an observation.
type ToolState struct {
	Status   string `json:"status"`
	Callable bool   `json:"callable"`
}

const toolCols = `server, name, hash, definition, risk, score, signals, status, approved_hash, first_seen, last_seen, decided_by, decided_at, note`

func listTools(ctx context.Context, q querier, where string, args ...any) ([]MCPTool, error) {
	where, lock := strings.CutSuffix(where, " FOR UPDATE")
	sql := "SELECT " + toolCols + " FROM agents.mcp_tools " + where + " ORDER BY server, name"
	if lock {
		sql += " FOR UPDATE"
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[MCPTool])
}

// Observe records the definitions a server's tools/list returned. A new tool is scanned: clean ones are pinned
// and approved, flagged ones wait for review. A changed definition (rug pull or honest update alike) goes back to
// under_review until someone approves the new version. Changes are audited and released to the PDP.
func (s *Store) Observe(ctx context.Context, server string, defs []map[string]any, now time.Time) (map[string]ToolState, error) {
	if server == "" || len(server) > 128 {
		return nil, fmt.Errorf("%w: server name", ErrInvalid)
	}
	out := map[string]ToolState{}
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		// One server's observations at a time: two gateway replicas seeing the same change record it once.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext('mcp_tools:' || $1))", server); err != nil {
			return err
		}
		known, err := listTools(ctx, tx, "WHERE server = $1", server)
		if err != nil {
			return err
		}
		byName := map[string]MCPTool{}
		for _, t := range known {
			byName[t.Name] = t
		}
		changed := 0
		for _, def := range defs {
			name := mcptools.Name(def)
			if name == "" || len(name) > 256 {
				continue
			}
			hash := mcptools.Hash(def)
			old, seen := byName[name]
			if seen && old.Hash == hash {
				if _, err := tx.Exec(ctx, "UPDATE agents.mcp_tools SET last_seen = greatest(last_seen, $3) WHERE server = $1 AND name = $2", server, name, now); err != nil {
					return err
				}
				out[name] = ToolState{old.Status, old.Callable()}
				continue
			}
			f := mcptools.Scan(def)
			t := MCPTool{Server: server, Name: name, Hash: hash, Definition: def, Risk: f.Risk, Score: f.Score, Signals: f.Signals,
				Status: "under_review", FirstSeen: now, LastSeen: now}
			action := "mcp.tool.changed"
			if seen {
				t.FirstSeen, t.ApprovedHash = old.FirstSeen, old.ApprovedHash
			} else {
				action = "mcp.tool.registered"
				if f.Risk == "low" {
					t.Status, t.ApprovedHash = "approved", &hash
				}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO agents.mcp_tools (`+toolCols+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULL, NULL, NULL)
				ON CONFLICT (server, name) DO UPDATE SET hash = $3, definition = $4, risk = $5, score = $6, signals = $7, status = $8,
				approved_hash = $9, last_seen = $11, decided_by = NULL, decided_at = NULL, note = NULL`,
				t.Server, t.Name, t.Hash, t.Definition, t.Risk, t.Score, t.Signals, t.Status, t.ApprovedHash, t.FirstSeen, t.LastSeen); err != nil {
				return err
			}
			target := map[string]any{"server": server, "tool": name, "hash": hash, "status": t.Status, "risk": f.Risk, "signals": f.Signals}
			if seen {
				target["previous_hash"] = old.Hash
			}
			if _, err := audit.AppendTx(ctx, tx, s.tenant, "mcp-gateway", action, target); err != nil {
				return err
			}
			out[name] = ToolState{t.Status, t.Callable()}
			changed++
		}
		if changed > 0 {
			_, err = s.policies.CutRelease(ctx, tx, "mcp-gateway", fmt.Sprintf("mcp tools of %s: %d new or changed", server, changed))
		}
		return err
	})
	return out, err
}

// ApproveTool pins the definition the reviewer saw (hash): if the server has changed it since, nothing is
// approved. A flagged definition needs a note saying why it is acceptable.
func (s *Store) ApproveTool(ctx context.Context, actor, server, name, hash, note string) (MCPTool, error) {
	return s.decideTool(ctx, actor, "mcp.tool.approve", server, name, "approved", note, func(t MCPTool) error {
		if hash != t.Hash {
			return fmt.Errorf("%w: the definition changed since %s; review the current one", ErrInvalid, hash)
		}
		if t.Risk != "low" && strings.TrimSpace(note) == "" {
			return fmt.Errorf("%w: a flagged tool (%s) needs a note", ErrInvalid, strings.Join(t.Signals, ", "))
		}
		return nil
	})
}

// RejectTool keeps a tool uncallable until a new definition is approved.
func (s *Store) RejectTool(ctx context.Context, actor, server, name, note string) (MCPTool, error) {
	return s.decideTool(ctx, actor, "mcp.tool.reject", server, name, "rejected", note, func(MCPTool) error {
		if strings.TrimSpace(note) == "" {
			return fmt.Errorf("%w: a rejection needs a note", ErrInvalid)
		}
		return nil
	})
}

func (s *Store) decideTool(ctx context.Context, actor, action, server, name, status, note string, check func(MCPTool) error) (MCPTool, error) {
	err := s.change(ctx, actor, action, func(tx pgx.Tx) (map[string]any, error) {
		ts, err := listTools(ctx, tx, "WHERE server = $1 AND name = $2 FOR UPDATE", server, name)
		if err != nil {
			return nil, err
		}
		if len(ts) == 0 {
			return nil, ErrNotFound
		}
		t := ts[0]
		if err := check(t); err != nil {
			return nil, err
		}
		pin := t.ApprovedHash
		if status == "approved" {
			pin = &t.Hash
		}
		if _, err := tx.Exec(ctx, `UPDATE agents.mcp_tools SET status = $3, approved_hash = $4, decided_by = $5, decided_at = now(), note = $6
			WHERE server = $1 AND name = $2`, server, name, status, pin, actor, note); err != nil {
			return nil, err
		}
		n, err := s.policies.CutRelease(ctx, tx, actor, fmt.Sprintf("mcp tool %s/%s %s", server, name, status))
		return map[string]any{"server": server, "tool": name, "hash": t.Hash, "status": status, "risk": t.Risk, "note": note, "release": n}, err
	})
	if err != nil {
		return MCPTool{}, err
	}
	ts, err := listTools(ctx, s.db, "WHERE server = $1 AND name = $2", server, name)
	if err != nil || len(ts) == 0 {
		return MCPTool{}, err
	}
	return ts[0], nil
}

// Tools lists tool definitions, optionally of one server and/or status.
func (s *Store) Tools(ctx context.Context, server, status string) ([]MCPTool, error) {
	return listTools(ctx, s.db, "WHERE ($1 = '' OR server = $1) AND ($2 = '' OR status = $2)", server, status)
}

// ServerReport is the per-server risk report.
type ServerReport struct {
	Server      string `json:"server"`
	Tools       int    `json:"tools"`
	Callable    int    `json:"callable"`
	UnderReview int    `json:"under_review"`
	Rejected    int    `json:"rejected"`
	Changed     int    `json:"changed"` // served definition differs from the approved pin (rug pull or update)
	High        int    `json:"high_risk"`
	Medium      int    `json:"medium_risk"`
}

func (s *Store) ToolReport(ctx context.Context) ([]ServerReport, error) {
	ts, err := s.Tools(ctx, "", "")
	if err != nil {
		return nil, err
	}
	out := []ServerReport{}
	for _, t := range ts {
		if len(out) == 0 || out[len(out)-1].Server != t.Server {
			out = append(out, ServerReport{Server: t.Server})
		}
		r := &out[len(out)-1]
		r.Tools++
		r.Callable += b2i(t.Callable())
		r.UnderReview += b2i(t.Status == "under_review")
		r.Rejected += b2i(t.Status == "rejected")
		r.Changed += b2i(t.ApprovedHash != nil && *t.ApprovedHash != t.Hash)
		r.High += b2i(t.Risk == "high")
		r.Medium += b2i(t.Risk == "medium")
	}
	return out, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// toolsDoc is data.wantimpres26.mcp_tools: per "server/tool", its status and pinned hash (wantimpres26/agent).
func toolsDoc(ctx context.Context, tx pgx.Tx) (map[string]any, error) {
	ts, err := listTools(ctx, tx, "")
	if err != nil {
		return nil, err
	}
	items := map[string]any{}
	for _, t := range ts {
		pin := ""
		if t.ApprovedHash != nil {
			pin = *t.ApprovedHash
		}
		items[t.Server+"/"+t.Name] = map[string]any{"status": t.Status, "hash": pin}
	}
	return map[string]any{"version": len(ts), "items": items}, nil
}

// GatewayHandler serves the MCP gateway, authenticated by its own bearer token (stored as SHA-256, like SCIM):
//
//	POST /mcp/tools/observed    {"server", "tools": [definitions]} → {"tools": {name: {status, callable}}}
//	POST /mcp/approvals/request {agent_id, server, tool, args_digest, preview, reason_codes, trace_id} → Approval
//	POST /mcp/approvals/claim   {agent_id, server, tool, args_digest} → {"approval_id"} or 404
func (s *Store) GatewayHandler(tokenSHA256 []byte, now func() time.Time) http.Handler {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, v any, err error) {
		switch {
		case errors.Is(err, ErrInvalid):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, ErrNotFound):
			http.Error(w, "not found", http.StatusNotFound)
		case err != nil:
			http.Error(w, "internal error", http.StatusInternalServerError)
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	decode := func(w http.ResponseWriter, r *http.Request, v any) bool {
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(v) != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return false
		}
		return true
	}
	mux.HandleFunc("POST /mcp/tools/observed", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Server string           `json:"server"`
			Tools  []map[string]any `json:"tools"`
		}
		if decode(w, r, &body) {
			states, err := s.Observe(r.Context(), body.Server, body.Tools, now())
			reply(w, map[string]any{"tools": states}, err)
		}
	})
	mux.HandleFunc("POST /mcp/approvals/request", func(w http.ResponseWriter, r *http.Request) {
		var a Approval
		if decode(w, r, &a) {
			a, err := s.RequestApproval(r.Context(), a, now())
			reply(w, a, err)
		}
	})
	mux.HandleFunc("POST /mcp/approvals/claim", func(w http.ResponseWriter, r *http.Request) {
		var a Approval
		if !decode(w, r, &a) {
			return
		}
		id, ok, err := s.ClaimApproval(r.Context(), a.AgentID, a.Server, a.Tool, a.ArgsDigest, now())
		if err == nil && !ok {
			err = ErrNotFound
		}
		reply(w, map[string]any{"approval_id": id}, err)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		got := sha256.Sum256([]byte(raw))
		if !ok || subtle.ConstantTimeCompare(got[:], tokenSHA256) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
