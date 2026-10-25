package m365

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"wantimpres26/internal/connector"
)

// QuarantineFolder is created at the root of a library or OneDrive; restrict its permissions to the security
// team when deploying (Graph cannot set a folder to "no inheritance").
const QuarantineFolder = "WANTIMPRES-26 Quarantine"

type perm struct {
	ID    string   `json:"id"`
	Roles []string `json:"roles"`
	Link  *struct {
		Scope string `json:"scope"`
	} `json:"link"`
	To struct {
		User      *identity `json:"user"`
		Group     *identity `json:"group"`
		SiteGroup *identity `json:"siteGroup"`
	} `json:"grantedToV2"`
	Inherited *struct {
		Path string `json:"path"`
	} `json:"inheritedFrom"`
}

func (p perm) role() string {
	for _, r := range []string{"owner", "write"} {
		if slices.Contains(p.Roles, r) {
			return r
		}
	}
	return "read"
}

// who names the grantee as Grant.Ref does; kind is user, group or link.
func (p perm) who() (kind, ref string) {
	switch {
	case p.Link != nil:
		return "link", p.Link.Scope
	case p.To.User != nil:
		return "user", userRef(p.To.User)
	case p.To.Group != nil:
		return "group", p.To.Group.DisplayName
	case p.To.SiteGroup != nil:
		return "group", p.To.SiteGroup.DisplayName
	}
	return "", ""
}

// undoData restores what can be restored: users re-invited, the previous label, the original folder.
type undoData struct {
	Invites []invite `json:"invites,omitempty"`
	Label   string   `json:"label,omitempty"`
	Parent  string   `json:"parent,omitempty"`
}

type invite struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

func (g *Graph) permissions(ctx context.Context, it connector.Item) ([]perm, error) {
	var out []perm
	err := g.pages(ctx, g.item(it)+"/permissions", func(raw json.RawMessage) error {
		var p perm
		if err := json.Unmarshal(raw, &p); err != nil {
			return err
		}
		out = append(out, p)
		return nil
	})
	return out, err
}

// write sends a change with the remediation credentials (read-write Graph permissions), never the scan ones.
func (g *Graph) write(ctx context.Context, method, path string, body any) error {
	if g.WriteHTTP == nil {
		return fmt.Errorf("%w: no remediation credentials for M365", connector.ErrNotSupported)
	}
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	resp, err := g.Backoff.Do(ctx, g.WriteHTTP, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, method, g.BaseURL+path, strings.NewReader(string(payload)))
		if err == nil && body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return req, err
	}, nil)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

type step struct {
	text string
	do   func(ctx context.Context) error
}

// Remediate plans a and, unless dryRun, carries it out.
func (g *Graph) Remediate(ctx context.Context, it connector.Item, a connector.Action, dryRun bool) (connector.Change, error) {
	if g.WriteHTTP == nil {
		return connector.Change{}, fmt.Errorf("%w: no remediation credentials for M365", connector.ErrNotSupported)
	}
	perms, err := g.permissions(ctx, it)
	if err != nil {
		return connector.Change{}, err
	}
	var steps []step
	var undo undoData
	del := func(p perm, restorable bool) {
		kind, ref := p.who()
		text := fmt.Sprintf("delete permission %s (%s %s, %s)", p.ID, kind, ref, p.role())
		if !restorable {
			text += " — not restorable"
		}
		steps = append(steps, step{text, func(ctx context.Context) error {
			return g.write(ctx, http.MethodDelete, g.item(it)+"/permissions/"+url.PathEscape(p.ID), nil)
		}})
	}
	// Explicit grants matching want; an inherited match cannot be removed here.
	match := func(want func(perm) bool) error {
		for _, p := range perms {
			if !want(p) {
				continue
			}
			if p.Inherited != nil {
				return fmt.Errorf("permission %s is inherited from %s: remediate that folder", p.ID, p.Inherited.Path)
			}
			kind, ref := p.who()
			restorable := kind == "user" && strings.Contains(ref, "@")
			if restorable {
				undo.Invites = append(undo.Invites, invite{ref, p.role()})
			}
			del(p, restorable)
		}
		return nil
	}
	switch a.Kind {
	case connector.RevokeAnyoneLinks:
		err = match(func(p perm) bool { return p.Link != nil && p.Link.Scope == "anonymous" })
	case connector.RemoveGrants:
		want := map[string]bool{}
		for _, r := range a.Grants {
			want[strings.ToLower(r)] = true
		}
		err = match(func(p perm) bool { _, ref := p.who(); return p.Link == nil && want[strings.ToLower(ref)] })
	case connector.ApplyLabel:
		if a.Label == "" {
			return connector.Change{}, fmt.Errorf("apply_label needs a label id")
		}
		cur, err := g.Labels(ctx, it)
		if err != nil {
			return connector.Change{}, err
		}
		prev := ""
		if len(cur) > 0 {
			prev = cur[0]
		}
		if prev == a.Label {
			break
		}
		undo.Label = prev
		was := prev
		if was == "" {
			was = "none"
		}
		steps = append(steps, step{fmt.Sprintf("assign sensitivity label %s (was %s)", a.Label, was), func(ctx context.Context) error {
			return g.write(ctx, http.MethodPost, g.item(it)+"/assignSensitivityLabel",
				map[string]any{"sensitivityLabelId": a.Label, "assignmentMethod": "standard", "justificationText": "WANTIMPRES-26 remediation"})
		}})
	case connector.Quarantine:
		var cur struct {
			Parent struct {
				ID string `json:"id"`
			} `json:"parentReference"`
		}
		if err := g.getJSON(ctx, g.item(it)+"?$select=id,parentReference", nil, &cur); err != nil {
			return connector.Change{}, err
		}
		qid, qerr := g.quarantineFolder(ctx, it.ContainerID, dryRun)
		if qerr != nil {
			return connector.Change{}, qerr
		}
		if cur.Parent.ID == qid && qid != "" {
			break
		}
		undo.Parent = cur.Parent.ID
		steps = append(steps, step{"move to /" + QuarantineFolder, func(ctx context.Context) error {
			folder, err := g.quarantineFolder(ctx, it.ContainerID, false)
			if err != nil {
				return err
			}
			return g.write(ctx, http.MethodPatch, g.item(it), map[string]any{"parentReference": map[string]any{"id": folder}})
		}})
		// Strip sharing: every explicit grant but owners.
		err = match(func(p perm) bool { return p.Inherited == nil && p.role() != "owner" })
	default:
		return connector.Change{}, fmt.Errorf("unknown remediation %q", a.Kind)
	}
	if err != nil {
		return connector.Change{}, err
	}
	return run(ctx, steps, undo, dryRun)
}

func run(ctx context.Context, steps []step, undo undoData, dryRun bool) (connector.Change, error) {
	if len(steps) == 0 {
		return connector.Change{}, connector.ErrNothingToDo
	}
	ch := connector.Change{}
	for _, s := range steps {
		ch.Steps = append(ch.Steps, s.text)
	}
	if len(undo.Invites) > 0 || undo.Label != "" || undo.Parent != "" {
		ch.Undo, _ = json.Marshal(undo)
	}
	if dryRun {
		return ch, nil
	}
	for i, s := range steps {
		if err := s.do(ctx); err != nil {
			return ch, fmt.Errorf("step %d (%s): %w", i+1, s.text, err)
		}
	}
	return ch, nil
}

// quarantineFolder finds (or, unless dryRun, creates) the quarantine folder; "" in a dry run when missing.
func (g *Graph) quarantineFolder(ctx context.Context, drive string, dryRun bool) (string, error) {
	var f struct {
		ID string `json:"id"`
	}
	err := g.getJSON(ctx, "/drives/"+url.PathEscape(drive)+"/root:/"+url.PathEscape(QuarantineFolder), nil, &f)
	switch {
	case err == nil:
		return f.ID, nil
	case !refused(err):
		return "", err
	case dryRun:
		return "", nil // created when executed
	}
	resp, err := g.Backoff.Do(ctx, g.WriteHTTP, func() (*http.Request, error) {
		b, _ := json.Marshal(map[string]any{"name": QuarantineFolder, "folder": map[string]any{}, "@microsoft.graph.conflictBehavior": "fail"})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.BaseURL+"/drives/"+url.PathEscape(drive)+"/root/children", strings.NewReader(string(b)))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return req, err
	}, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	return f.ID, json.NewDecoder(resp.Body).Decode(&f)
}

// Undo moves an item back, re-invites the users a remediation removed and restores the previous label. Removed
// links and group grants are not restorable (and were not promised).
func (g *Graph) Undo(ctx context.Context, it connector.Item, raw json.RawMessage, dryRun bool) (connector.Change, error) {
	if g.WriteHTTP == nil {
		return connector.Change{}, fmt.Errorf("%w: no remediation credentials for M365", connector.ErrNotSupported)
	}
	var u undoData
	if err := json.Unmarshal(raw, &u); err != nil {
		return connector.Change{}, fmt.Errorf("undo data: %w", err)
	}
	var steps []step
	if u.Parent != "" {
		steps = append(steps, step{"move back to folder " + u.Parent, func(ctx context.Context) error {
			return g.write(ctx, http.MethodPatch, g.item(it), map[string]any{"parentReference": map[string]any{"id": u.Parent}})
		}})
	}
	for _, in := range u.Invites {
		steps = append(steps, step{fmt.Sprintf("re-grant %s as %s", in.Email, in.Role), func(ctx context.Context) error {
			return g.write(ctx, http.MethodPost, g.item(it)+"/invite", map[string]any{"recipients": []any{map[string]any{"email": in.Email}},
				"roles": []string{in.Role}, "requireSignIn": true, "sendInvitation": false})
		}})
	}
	if u.Label != "" {
		steps = append(steps, step{"restore sensitivity label " + u.Label, func(ctx context.Context) error {
			return g.write(ctx, http.MethodPost, g.item(it)+"/assignSensitivityLabel",
				map[string]any{"sensitivityLabelId": u.Label, "assignmentMethod": "standard", "justificationText": "WANTIMPRES-26 remediation undone"})
		}})
	}
	ch, err := run(ctx, steps, undoData{}, dryRun)
	ch.Undo = nil
	return ch, err
}
