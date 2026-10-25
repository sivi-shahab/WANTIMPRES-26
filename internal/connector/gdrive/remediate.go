package gdrive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"wantimpres26/internal/connector"
)

// QuarantineFolder is created at the root of the user's My Drive or the shared drive.
const QuarantineFolder = "WANTIMPRES-26 Quarantine"

type drivePerm struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Role      string `json:"role"`
	Email     string `json:"emailAddress,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Discovery bool   `json:"allowFileDiscovery,omitempty"`
	Inherited bool   `json:"-"`
	Details   []struct {
		Inherited bool `json:"inherited"`
	} `json:"permissionDetails,omitempty"`
}

func (p drivePerm) ref() string {
	if p.Domain != "" {
		return strings.ToLower(p.Domain)
	}
	return strings.ToLower(p.Email)
}

// restore is a permission as it is re-created on undo (Drive restores access exactly: the file URL is unchanged).
type restore struct {
	Type      string `json:"type"`
	Role      string `json:"role"`
	Email     string `json:"emailAddress,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Discovery bool   `json:"allowFileDiscovery,omitempty"`
}

type undoData struct {
	Perms  []restore `json:"perms,omitempty"`
	Parent string    `json:"parent,omitempty"`
}

func (d *Drive) writeClient(subject string) (*http.Client, error) {
	if d.WriteClient == nil {
		return nil, fmt.Errorf("%w: no remediation credentials for Google Drive", connector.ErrNotSupported)
	}
	return d.WriteClient(subject), nil
}

func (d *Drive) write(ctx context.Context, subject, method, path string, q url.Values, body any, out any) error {
	c, err := d.writeClient(subject)
	if err != nil {
		return err
	}
	if q == nil {
		q = url.Values{}
	}
	q.Set("supportsAllDrives", "true")
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	resp, err := d.Backoff.Do(ctx, c, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, method, d.BaseURL+path+"?"+q.Encode(), strings.NewReader(string(payload)))
		if err == nil && body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return req, err
	}, throttled)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
	}
	return nil
}

func (d *Drive) permissions(ctx context.Context, subject, id string) ([]drivePerm, error) {
	var r struct {
		Permissions []drivePerm `json:"permissions"`
	}
	q := url.Values{"supportsAllDrives": {"true"}, "fields": {"permissions(id,type,role,emailAddress,domain,allowFileDiscovery,permissionDetails(inherited))"}}
	if err := d.getJSON(ctx, subject, "/drive/v3/files/"+url.PathEscape(id)+"/permissions", q, &r); err != nil {
		return nil, err
	}
	for i := range r.Permissions {
		for _, det := range r.Permissions[i].Details {
			r.Permissions[i].Inherited = r.Permissions[i].Inherited || det.Inherited
		}
	}
	return r.Permissions, nil
}

type step struct {
	text string
	do   func(ctx context.Context) error
}

func run(ctx context.Context, steps []step, undo undoData, dryRun bool) (connector.Change, error) {
	if len(steps) == 0 {
		return connector.Change{}, connector.ErrNothingToDo
	}
	var ch connector.Change
	for _, s := range steps {
		ch.Steps = append(ch.Steps, s.text)
	}
	if len(undo.Perms) > 0 || undo.Parent != "" {
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

// Remediate: revoke_anyone_links, remove_grants and quarantine. Drive labels are not supported.
func (d *Drive) Remediate(ctx context.Context, it connector.Item, a connector.Action, dryRun bool) (connector.Change, error) {
	subject, driveID := d.subject(it.ContainerID)
	if _, err := d.writeClient(subject); err != nil {
		return connector.Change{}, err
	}
	perms, err := d.permissions(ctx, subject, it.ID)
	if err != nil {
		return connector.Change{}, err
	}
	var steps []step
	var undo undoData
	remove := func(want func(drivePerm) bool) error {
		for _, p := range perms {
			if !want(p) {
				continue
			}
			if p.Inherited {
				return fmt.Errorf("permission %s (%s %s) is inherited from a folder or the shared drive: remediate there", p.ID, p.Type, p.ref())
			}
			undo.Perms = append(undo.Perms, restore{p.Type, p.Role, p.Email, p.Domain, p.Discovery})
			steps = append(steps, step{fmt.Sprintf("delete permission %s (%s %s, %s)", p.ID, p.Type, p.ref(), p.Role), func(ctx context.Context) error {
				return d.write(ctx, subject, http.MethodDelete, "/drive/v3/files/"+url.PathEscape(it.ID)+"/permissions/"+url.PathEscape(p.ID), nil, nil, nil)
			}})
		}
		return nil
	}
	switch a.Kind {
	case connector.RevokeAnyoneLinks:
		err = remove(func(p drivePerm) bool { return p.Type == "anyone" })
	case connector.RemoveGrants:
		want := map[string]bool{}
		for _, r := range a.Grants {
			want[strings.ToLower(r)] = true
		}
		err = remove(func(p drivePerm) bool { return p.Type != "anyone" && want[p.ref()] })
	case connector.Quarantine:
		var f struct {
			Parents []string `json:"parents"`
		}
		if err := d.getJSON(ctx, subject, "/drive/v3/files/"+url.PathEscape(it.ID), url.Values{"supportsAllDrives": {"true"}, "fields": {"parents"}}, &f); err != nil {
			return connector.Change{}, err
		}
		folder, ferr := d.quarantineFolder(ctx, subject, driveID, true)
		if ferr != nil {
			return connector.Change{}, ferr
		}
		parent := strings.Join(f.Parents, ",")
		if folder != "" && parent == folder {
			break
		}
		undo.Parent = parent
		steps = append(steps, step{"move to /" + QuarantineFolder, func(ctx context.Context) error {
			folder, err := d.quarantineFolder(ctx, subject, driveID, false)
			if err != nil {
				return err
			}
			return d.write(ctx, subject, http.MethodPatch, "/drive/v3/files/"+url.PathEscape(it.ID),
				url.Values{"addParents": {folder}, "removeParents": {parent}}, map[string]any{}, nil)
		}})
		err = remove(func(p drivePerm) bool { return p.Role != "owner" && p.Role != "organizer" && !p.Inherited })
	case connector.ApplyLabel:
		return connector.Change{}, fmt.Errorf("%w: Drive labels", connector.ErrNotSupported)
	default:
		return connector.Change{}, fmt.Errorf("unknown remediation %q", a.Kind)
	}
	if err != nil {
		return connector.Change{}, err
	}
	return run(ctx, steps, undo, dryRun)
}

// quarantineFolder finds (or, unless dryRun, creates) the quarantine folder at the root of the drive.
func (d *Drive) quarantineFolder(ctx context.Context, subject, driveID string, dryRun bool) (string, error) {
	root := "root"
	q := url.Values{"supportsAllDrives": {"true"}, "fields": {"files(id)"}}
	if driveID != "" {
		root = driveID
		q.Set("corpora", "drive")
		q.Set("driveId", driveID)
		q.Set("includeItemsFromAllDrives", "true")
	}
	q.Set("q", fmt.Sprintf("name = '%s' and mimeType = '%s' and '%s' in parents and trashed = false", QuarantineFolder, folderMime, root))
	var r struct {
		Files []struct {
			ID string `json:"id"`
		} `json:"files"`
	}
	if err := d.getJSON(ctx, subject, "/drive/v3/files", q, &r); err != nil {
		return "", err
	}
	if len(r.Files) > 0 {
		return r.Files[0].ID, nil
	}
	if dryRun {
		return "", nil
	}
	var f struct {
		ID string `json:"id"`
	}
	err := d.write(ctx, subject, http.MethodPost, "/drive/v3/files", nil, map[string]any{"name": QuarantineFolder, "mimeType": folderMime, "parents": []string{root}}, &f)
	return f.ID, err
}

// Undo re-creates removed permissions and moves a quarantined file back.
func (d *Drive) Undo(ctx context.Context, it connector.Item, raw json.RawMessage, dryRun bool) (connector.Change, error) {
	subject, driveID := d.subject(it.ContainerID)
	if _, err := d.writeClient(subject); err != nil {
		return connector.Change{}, err
	}
	var u undoData
	if err := json.Unmarshal(raw, &u); err != nil {
		return connector.Change{}, fmt.Errorf("undo data: %w", err)
	}
	var steps []step
	if u.Parent != "" {
		steps = append(steps, step{"move back to folder " + u.Parent, func(ctx context.Context) error {
			folder, err := d.quarantineFolder(ctx, subject, driveID, true)
			if err != nil {
				return err
			}
			return d.write(ctx, subject, http.MethodPatch, "/drive/v3/files/"+url.PathEscape(it.ID),
				url.Values{"addParents": {u.Parent}, "removeParents": {folder}}, map[string]any{}, nil)
		}})
	}
	for _, p := range u.Perms {
		who := p.Email + p.Domain
		if p.Type == "anyone" {
			who = "anyone"
		}
		steps = append(steps, step{fmt.Sprintf("re-create permission %s %s (%s)", p.Type, who, p.Role), func(ctx context.Context) error {
			return d.write(ctx, subject, http.MethodPost, "/drive/v3/files/"+url.PathEscape(it.ID)+"/permissions",
				url.Values{"sendNotificationEmail": {"false"}}, p, nil)
		}})
	}
	ch, err := run(ctx, steps, undoData{}, dryRun)
	ch.Undo = nil
	return ch, err
}
