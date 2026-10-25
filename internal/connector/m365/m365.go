// Package m365 is the Microsoft 365 connector (SharePoint, OneDrive and Teams files) over Microsoft Graph: delta
// queries for incremental scans, permissions for oversharing, Purview sensitivity labels. Read-only application
// permissions: Sites.Read.All, Files.Read.All, User.Read.All.
package m365

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2/clientcredentials"

	"wantimpres26/internal/connector"
)

// Graph is the connector. Fields are exported so tests can point it at a fake Graph.
type Graph struct {
	BaseURL string       // https://graph.microsoft.com/v1.0
	HTTP    *http.Client // carries the app's OAuth token (client credentials)
	Domains []string     // the tenant's own e-mail domains: anything else is external
	// Backoff handles Graph throttling (429/503/504): Retry-After honored, otherwise exponential.
	Backoff connector.Backoff
	// WriteHTTP carries a separate app registration with write permissions (Files.ReadWrite.All,
	// Sites.ReadWrite.All, InformationProtectionPolicy for labels) used only by remediation; nil = none.
	WriteHTTP *http.Client
}

// Writer sets the remediation app registration.
func (g *Graph) Writer(tenant, clientID, secret string) {
	cc := clientcredentials.Config{ClientID: clientID, ClientSecret: secret,
		TokenURL: "https://login.microsoftonline.com/" + url.PathEscape(tenant) + "/oauth2/v2.0/token",
		Scopes:   []string{"https://graph.microsoft.com/.default"}}
	g.WriteHTTP = cc.Client(context.Background())
}

// New connects with an Entra ID app registration (client credentials).
func New(tenant, clientID, secret string, domains []string) *Graph {
	cc := clientcredentials.Config{ClientID: clientID, ClientSecret: secret,
		TokenURL: "https://login.microsoftonline.com/" + url.PathEscape(tenant) + "/oauth2/v2.0/token",
		Scopes:   []string{"https://graph.microsoft.com/.default"}}
	return &Graph{BaseURL: "https://graph.microsoft.com/v1.0", HTTP: cc.Client(context.Background()), Domains: domains,
		Backoff: connector.DefaultBackoff}
}

// refused: a definite non-throttling Graph error (missing OneDrive, unsupported file type, …).
func refused(err error) bool {
	var se *connector.StatusError
	return errors.As(err, &se) && !se.Throttled
}

// do sends one Graph request, waiting out throttling. Absolute URLs (nextLink, deltaLink) are used as given;
// they must stay on the Graph host, so a tampered link cannot carry the token elsewhere.
func (g *Graph) do(ctx context.Context, method, ref string, body any, header map[string]string) (*http.Response, error) {
	u := ref
	if !strings.HasPrefix(ref, "https://") && !strings.HasPrefix(ref, "http://") {
		u = g.BaseURL + ref
	} else if base, _ := url.Parse(g.BaseURL); base == nil || !strings.HasPrefix(ref, base.Scheme+"://"+base.Host+"/") {
		return nil, fmt.Errorf("graph link outside %s", g.BaseURL)
	}
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	return g.Backoff.Do(ctx, g.HTTP, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range header {
			req.Header.Set(k, v)
		}
		return req, nil
	}, nil)
}

func (g *Graph) getJSON(ctx context.Context, ref string, header map[string]string, out any) error {
	resp, err := g.do(ctx, http.MethodGet, ref, nil, header)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out)
}

// pages follows @odata.nextLink.
func (g *Graph) pages(ctx context.Context, ref string, each func(json.RawMessage) error) error {
	for ref != "" {
		var p struct {
			Value []json.RawMessage `json:"value"`
			Next  string            `json:"@odata.nextLink"`
		}
		if err := g.getJSON(ctx, ref, nil, &p); err != nil {
			return err
		}
		for _, v := range p.Value {
			if err := each(v); err != nil {
				return err
			}
		}
		ref = p.Next
	}
	return nil
}

// Containers: every document library of every site (SharePoint and Teams) and every user's OneDrive.
func (g *Graph) Containers(ctx context.Context) ([]connector.Container, error) {
	var out []connector.Container
	seen := map[string]bool{}
	add := func(raw json.RawMessage) error {
		var d struct {
			ID, Name, DriveType string
		}
		if err := json.Unmarshal(raw, &d); err != nil || d.ID == "" || seen[d.ID] {
			return err
		}
		seen[d.ID] = true
		kind := "sharepoint"
		if d.DriveType == "personal" || d.DriveType == "business" {
			kind = "onedrive"
		}
		out = append(out, connector.Container{ID: d.ID, Name: d.Name, Kind: kind})
		return nil
	}
	err := g.pages(ctx, "/sites/getAllSites?$select=id", func(raw json.RawMessage) error {
		var s struct{ ID string }
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
		return g.pages(ctx, "/sites/"+url.PathEscape(s.ID)+"/drives?$select=id,name,driveType", add)
	})
	if err != nil {
		return nil, err
	}
	err = g.pages(ctx, "/users?$select=id", func(raw json.RawMessage) error {
		var u struct{ ID string }
		if err := json.Unmarshal(raw, &u); err != nil {
			return err
		}
		var d json.RawMessage
		if err := g.getJSON(ctx, "/users/"+url.PathEscape(u.ID)+"/drive?$select=id,name,driveType", nil, &d); err != nil {
			if refused(err) {
				return nil // no OneDrive provisioned
			}
			return err
		}
		return add(d)
	})
	return out, err
}

// deltaSelect: what the scanner needs from each driveItem; cTag changes with content only.
const deltaSelect = "id,name,parentReference,file,folder,size,cTag,lastModifiedDateTime,deleted"

// Items reads one page of the drive's delta feed. Sharing changes are included (Prefer: deltashowsharingchanges):
// an item whose permissions changed comes back with the same cTag, so only its ACL is read again.
func (g *Graph) Items(ctx context.Context, c connector.Container, cursor string) (connector.Page, error) {
	ref := cursor
	if ref == "" {
		ref = "/drives/" + url.PathEscape(c.ID) + "/root/delta?$select=" + deltaSelect
	}
	var p struct {
		Value []struct {
			ID     string    `json:"id"`
			Name   string    `json:"name"`
			CTag   string    `json:"cTag"`
			Size   int64     `json:"size"`
			Mod    time.Time `json:"lastModifiedDateTime"`
			Folder *struct{} `json:"folder"`
			Del    *struct{} `json:"deleted"`
			Parent struct {
				Path string `json:"path"`
			} `json:"parentReference"`
		} `json:"value"`
		Next  string `json:"@odata.nextLink"`
		Delta string `json:"@odata.deltaLink"`
	}
	if err := g.getJSON(ctx, ref, map[string]string{"Prefer": "deltashowsharingchanges, hierarchicalsharing"}, &p); err != nil {
		return connector.Page{}, err
	}
	page := connector.Page{Next: p.Next}
	if p.Next == "" {
		page.Next, page.Done = p.Delta, true
	}
	for _, v := range p.Value {
		page.Items = append(page.Items, connector.Item{ID: v.ID, ContainerID: c.ID, Name: v.Name, Path: v.Parent.Path + "/" + v.Name,
			ContentTag: v.CTag, Size: v.Size, Modified: v.Mod, Folder: v.Folder != nil, Deleted: v.Del != nil})
	}
	return page, nil
}

func (g *Graph) item(it connector.Item) string {
	return "/drives/" + url.PathEscape(it.ContainerID) + "/items/" + url.PathEscape(it.ID)
}

// Get downloads the content (Graph redirects to a pre-authenticated URL; the client drops the token on that hop).
func (g *Graph) Get(ctx context.Context, it connector.Item, maxBytes int64) ([]byte, error) {
	if it.Size > maxBytes {
		return nil, fmt.Errorf("item is %d bytes, limit %d", it.Size, maxBytes)
	}
	resp, err := g.do(ctx, http.MethodGet, g.item(it)+"/content", nil, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err == nil && int64(len(b)) > maxBytes {
		err = fmt.Errorf("item content exceeds %d bytes", maxBytes)
	}
	return b, err
}

type identity struct {
	Email       string `json:"email"`
	UPN         string `json:"userPrincipalName"`
	DisplayName string `json:"displayName"`
	ID          string `json:"id"`
}

// ACL maps Graph permissions to grants: sharing links by scope, users (external by e-mail domain), groups.
func (g *Graph) ACL(ctx context.Context, it connector.Item) ([]connector.Grant, error) {
	var out []connector.Grant
	err := g.pages(ctx, g.item(it)+"/permissions", func(raw json.RawMessage) error {
		var p struct {
			Roles []string `json:"roles"`
			Link  *struct {
				Scope string `json:"scope"`
			} `json:"link"`
			To struct {
				User      *identity `json:"user"`
				Group     *identity `json:"group"`
				SiteGroup *identity `json:"siteGroup"`
			} `json:"grantedToV2"`
			Identities []struct {
				User *identity `json:"user"`
			} `json:"grantedToIdentitiesV2"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return err
		}
		role := "read"
		for _, r := range []string{"write", "owner"} {
			if slices.Contains(p.Roles, r) {
				role = r
			}
		}
		if p.Link != nil {
			kind := map[string]string{"anonymous": "anyone_link", "organization": "org_link"}[p.Link.Scope]
			if kind == "" {
				kind = "specific_link"
			}
			ext := false
			for _, id := range p.Identities {
				if id.User != nil {
					ext = ext || g.external(id.User)
					out = append(out, connector.Grant{Kind: "user", Ref: userRef(id.User), Role: role, External: g.external(id.User)})
				}
			}
			out = append(out, connector.Grant{Kind: kind, Role: role, External: ext || kind == "anyone_link"})
			return nil
		}
		switch {
		case p.To.User != nil:
			out = append(out, connector.Grant{Kind: "user", Ref: userRef(p.To.User), Role: role, External: g.external(p.To.User)})
		case p.To.Group != nil:
			out = append(out, connector.Grant{Kind: "group", Ref: p.To.Group.DisplayName, Role: role})
		case p.To.SiteGroup != nil:
			out = append(out, connector.Grant{Kind: "group", Ref: p.To.SiteGroup.DisplayName, Role: role})
		}
		return nil
	})
	return out, err
}

func userRef(u *identity) string {
	if u.UPN != "" {
		return strings.ToLower(u.UPN)
	}
	return strings.ToLower(u.Email)
}

// external: guest accounts (#EXT# UPNs) and addresses outside the tenant's domains.
func (g *Graph) external(u *identity) bool {
	ref := userRef(u)
	if strings.Contains(ref, "#ext#") {
		return true
	}
	at := strings.LastIndexByte(ref, '@')
	return at >= 0 && !slices.Contains(g.Domains, ref[at+1:])
}

// Labels reads Purview sensitivity labels. Files Graph cannot label (some types) have none.
func (g *Graph) Labels(ctx context.Context, it connector.Item) ([]string, error) {
	resp, err := g.do(ctx, http.MethodPost, g.item(it)+"/extractSensitivityLabels", nil, nil)
	if refused(err) {
		return nil, nil // a file type Graph cannot label
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Labels []struct {
			ID string `json:"sensitivityLabelId"`
		} `json:"labels"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	var ids []string
	for _, l := range out.Labels {
		ids = append(ids, l.ID)
	}
	return ids, nil
}
