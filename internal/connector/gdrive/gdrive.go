// Package gdrive is the Google Drive connector (shared drives and every user's My Drive) over the Drive v3 API:
// the changes feed for incremental scans, permissions for oversharing, text export of Google-native documents.
// It authenticates as a service account with domain-wide delegation (read-only scopes), impersonating each
// user for their My Drive and the scanning admin for shared drives.
package gdrive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2/jwt"

	"wantimpres26/internal/connector"
)

// Scopes the delegation grants (Admin console → Security → API controls → Domain-wide delegation).
var Scopes = []string{
	"https://www.googleapis.com/auth/drive.readonly",
	"https://www.googleapis.com/auth/admin.directory.user.readonly",
	"https://www.googleapis.com/auth/admin.reports.audit.readonly",
}

// Drive is the connector.
type Drive struct {
	BaseURL string // https://www.googleapis.com
	Admin   string // super admin (or delegated admin) to impersonate for the directory, reports and shared drives
	Domains []string
	// Client returns an HTTP client acting as subject (domain-wide delegation).
	Client func(subject string) *http.Client
	// WriteClient is the same with the full drive scope, used only by remediation; nil = none.
	WriteClient func(subject string) *http.Client
	Backoff     connector.Backoff
}

// New builds the connector from a service account key (JSON) with domain-wide delegation; remediate also asks
// for the full drive scope, used only to remediate.
func New(keyJSON []byte, admin string, domains []string, remediate bool) (*Drive, error) {
	var k struct {
		Email      string `json:"client_email"`
		PrivateKey string `json:"private_key"`
		TokenURI   string `json:"token_uri"`
	}
	if err := json.Unmarshal(keyJSON, &k); err != nil || k.Email == "" || k.PrivateKey == "" {
		return nil, errors.New("service account key: client_email and private_key required")
	}
	if k.TokenURI == "" {
		k.TokenURI = "https://oauth2.googleapis.com/token"
	}
	clients := func(scopes []string) func(string) *http.Client {
		var mu sync.Mutex
		cache := map[string]*http.Client{}
		return func(subject string) *http.Client {
			mu.Lock()
			defer mu.Unlock()
			if c, ok := cache[subject]; ok {
				return c
			}
			c := (&jwt.Config{Email: k.Email, PrivateKey: []byte(k.PrivateKey), TokenURL: k.TokenURI, Scopes: scopes, Subject: subject}).Client(context.Background())
			cache[subject] = c
			return c
		}
	}
	d := &Drive{BaseURL: "https://www.googleapis.com", Admin: admin, Domains: domains, Backoff: connector.DefaultBackoff, Client: clients(Scopes)}
	if remediate {
		// The delegation must then also grant https://www.googleapis.com/auth/drive.
		d.WriteClient = clients([]string{"https://www.googleapis.com/auth/drive"})
	}
	return d, nil
}

// throttled: Google signals quota as 429 or as 403 with reason rateLimitExceeded / userRateLimitExceeded.
func throttled(r *http.Response) bool {
	if connector.Throttled(r) || r.StatusCode == http.StatusInternalServerError {
		return true
	}
	if r.StatusCode != http.StatusForbidden {
		return false
	}
	b, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	_ = r.Body.Close()
	r.Body = io.NopCloser(strings.NewReader(string(b)))
	return strings.Contains(string(b), "ateLimitExceeded")
}

func (d *Drive) get(ctx context.Context, subject, path string, q url.Values) (*http.Response, error) {
	return d.Backoff.Do(ctx, d.Client(subject), func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, d.BaseURL+path+"?"+q.Encode(), nil)
	}, throttled)
}

func (d *Drive) getJSON(ctx context.Context, subject, path string, q url.Values, out any) error {
	resp, err := d.get(ctx, subject, path, q)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out)
}

// A container id says whose drive: "user:<email>" (My Drive, impersonating that user) or "drive:<id>" (shared
// drive, impersonating the admin).
func (d *Drive) subject(container string) (subject, driveID string) {
	if email, ok := strings.CutPrefix(container, "user:"); ok {
		return email, ""
	}
	return d.Admin, strings.TrimPrefix(container, "drive:")
}

func (d *Drive) Containers(ctx context.Context) ([]connector.Container, error) {
	var out []connector.Container
	for page := ""; ; {
		var r struct {
			Drives []struct{ ID, Name string } `json:"drives"`
			Next   string                      `json:"nextPageToken"`
		}
		q := url.Values{"pageSize": {"100"}, "useDomainAdminAccess": {"true"}}
		if page != "" {
			q.Set("pageToken", page)
		}
		if err := d.getJSON(ctx, d.Admin, "/drive/v3/drives", q, &r); err != nil {
			return nil, fmt.Errorf("shared drives: %w", err)
		}
		for _, s := range r.Drives {
			out = append(out, connector.Container{ID: "drive:" + s.ID, Name: s.Name, Kind: "gdrive_shared"})
		}
		if page = r.Next; page == "" {
			break
		}
	}
	for page := ""; ; {
		var r struct {
			Users []struct {
				Email     string `json:"primaryEmail"`
				Suspended bool   `json:"suspended"`
			} `json:"users"`
			Next string `json:"nextPageToken"`
		}
		q := url.Values{"customer": {"my_customer"}, "maxResults": {"500"}, "projection": {"basic"}}
		if page != "" {
			q.Set("pageToken", page)
		}
		if err := d.getJSON(ctx, d.Admin, "/admin/directory/v1/users", q, &r); err != nil {
			return nil, fmt.Errorf("users: %w", err)
		}
		for _, u := range r.Users {
			if !u.Suspended {
				out = append(out, connector.Container{ID: "user:" + u.Email, Name: u.Email, Kind: "gdrive_mydrive"})
			}
		}
		if page = r.Next; page == "" {
			break
		}
	}
	return out, nil
}

type file struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	MimeType  string    `json:"mimeType"`
	MD5       string    `json:"md5Checksum"`
	Size      string    `json:"size"`
	Modified  time.Time `json:"modifiedTime"`
	Trashed   bool      `json:"trashed"`
	OwnedByMe *bool     `json:"ownedByMe"`
	DriveID   string    `json:"driveId"`
}

const fileFields = "id,name,mimeType,md5Checksum,size,modifiedTime,trashed,ownedByMe,driveId"

const folderMime = "application/vnd.google-apps.folder"

func (d *Drive) item(container string, f file, removed bool) connector.Item {
	var size int64
	_, _ = fmt.Sscan(f.Size, &size)
	// Binary files have an MD5. Google-native documents do not: their modifiedTime moves with edits, not with
	// sharing changes, so it serves as the content tag.
	tag := f.MD5
	if tag == "" && !f.Modified.IsZero() {
		tag = "m" + f.Modified.UTC().Format(time.RFC3339Nano)
	}
	return connector.Item{ID: f.ID, ContainerID: container, Name: f.Name, Path: f.Name, ContentTag: tag, Size: size, MimeType: f.MimeType,
		Modified: f.Modified, Folder: f.MimeType == folderMime, Deleted: removed || f.Trashed}
}

// Items: cursor "" takes the changes start token first (nothing changing during the listing is lost), then lists
// the drive ("list:<start>:<page>"); afterwards the feed is the changes API ("changes:<token>").
func (d *Drive) Items(ctx context.Context, c connector.Container, cursor string) (connector.Page, error) {
	subject, driveID := d.subject(c.ID)
	scope := url.Values{"supportsAllDrives": {"true"}}
	if driveID != "" {
		scope.Set("driveId", driveID)
	}
	switch {
	case cursor == "":
		var r struct {
			Token string `json:"startPageToken"`
		}
		if err := d.getJSON(ctx, subject, "/drive/v3/changes/startPageToken", scope, &r); err != nil {
			return connector.Page{}, err
		}
		return d.list(ctx, c, subject, driveID, r.Token, "")
	case strings.HasPrefix(cursor, "list:"):
		start, page, _ := strings.Cut(strings.TrimPrefix(cursor, "list:"), ":")
		return d.list(ctx, c, subject, driveID, start, page)
	case strings.HasPrefix(cursor, "changes:"):
		q := url.Values{"pageToken": {strings.TrimPrefix(cursor, "changes:")}, "pageSize": {"1000"}, "includeItemsFromAllDrives": {"true"},
			"fields": {"nextPageToken,newStartPageToken,changes(fileId,removed,file(" + fileFields + "))"}}
		for k, v := range scope {
			q[k] = v
		}
		if driveID == "" {
			q.Set("restrictToMyDrive", "true")
		}
		var r struct {
			Changes []struct {
				FileID  string `json:"fileId"`
				Removed bool   `json:"removed"`
				File    *file  `json:"file"`
			} `json:"changes"`
			Next     string `json:"nextPageToken"`
			NewStart string `json:"newStartPageToken"`
		}
		if err := d.getJSON(ctx, subject, "/drive/v3/changes", q, &r); err != nil {
			return connector.Page{}, err
		}
		p := connector.Page{Next: "changes:" + r.Next}
		if r.Next == "" {
			p.Next, p.Done = "changes:"+r.NewStart, true
		}
		for _, ch := range r.Changes {
			switch {
			case ch.File == nil:
				p.Items = append(p.Items, connector.Item{ID: ch.FileID, ContainerID: c.ID, Deleted: true})
			case driveID == "" && ch.File.OwnedByMe != nil && !*ch.File.OwnedByMe:
				// Shared with this user, owned elsewhere: its owner's drive reports it.
			default:
				p.Items = append(p.Items, d.item(c.ID, *ch.File, ch.Removed))
			}
		}
		return p, nil
	}
	return connector.Page{}, fmt.Errorf("bad cursor %q", cursor)
}

func (d *Drive) list(ctx context.Context, c connector.Container, subject, driveID, start, page string) (connector.Page, error) {
	q := url.Values{"pageSize": {"1000"}, "fields": {"nextPageToken,files(" + fileFields + ")"}, "supportsAllDrives": {"true"}}
	if driveID != "" {
		q.Set("corpora", "drive")
		q.Set("driveId", driveID)
		q.Set("includeItemsFromAllDrives", "true")
		q.Set("q", "trashed = false")
	} else {
		q.Set("q", "'me' in owners and trashed = false")
	}
	if page != "" {
		q.Set("pageToken", page)
	}
	var r struct {
		Files []file `json:"files"`
		Next  string `json:"nextPageToken"`
	}
	if err := d.getJSON(ctx, subject, "/drive/v3/files", q, &r); err != nil {
		return connector.Page{}, err
	}
	p := connector.Page{Next: "list:" + start + ":" + r.Next}
	if r.Next == "" {
		p.Next, p.Done = "changes:"+start, true
	}
	for _, f := range r.Files {
		p.Items = append(p.Items, d.item(c.ID, f, false))
	}
	return p, nil
}

// exports: Google-native types and the text format they are read as.
var exports = map[string]string{
	"application/vnd.google-apps.document":     "text/plain",
	"application/vnd.google-apps.spreadsheet":  "text/csv",
	"application/vnd.google-apps.presentation": "text/plain",
}

func (d *Drive) Get(ctx context.Context, it connector.Item, maxBytes int64) ([]byte, error) {
	if it.Size > maxBytes {
		return nil, fmt.Errorf("file is %d bytes, limit %d", it.Size, maxBytes)
	}
	subject, _ := d.subject(it.ContainerID)
	path, q := "/drive/v3/files/"+url.PathEscape(it.ID), url.Values{"supportsAllDrives": {"true"}}
	if mt, ok := exports[it.MimeType]; ok {
		path += "/export"
		q.Set("mimeType", mt)
	} else if strings.HasPrefix(it.MimeType, "application/vnd.google-apps.") {
		return nil, fmt.Errorf("google type %s has no text export", it.MimeType)
	} else {
		q.Set("alt", "media")
	}
	resp, err := d.get(ctx, subject, path, q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err == nil && int64(len(b)) > maxBytes {
		err = fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	return b, err
}

// ACL: anyone (with or without the link) is an anonymous share; a domain permission is the organization when it
// is the bank's own domain, else external; users and groups are external by domain.
func (d *Drive) ACL(ctx context.Context, it connector.Item) ([]connector.Grant, error) {
	subject, _ := d.subject(it.ContainerID)
	var r struct {
		Permissions []struct {
			Type   string `json:"type"`
			Role   string `json:"role"`
			Email  string `json:"emailAddress"`
			Domain string `json:"domain"`
		} `json:"permissions"`
	}
	q := url.Values{"supportsAllDrives": {"true"}, "fields": {"permissions(type,role,emailAddress,domain)"}}
	if err := d.getJSON(ctx, subject, "/drive/v3/files/"+url.PathEscape(it.ID)+"/permissions", q, &r); err != nil {
		return nil, err
	}
	role := func(r string) string {
		switch r {
		case "owner", "organizer", "fileOrganizer":
			return "owner"
		case "writer":
			return "write"
		}
		return "read"
	}
	var out []connector.Grant
	for _, p := range r.Permissions {
		switch p.Type {
		case "anyone":
			out = append(out, connector.Grant{Kind: "anyone_link", Role: role(p.Role), External: true})
		case "domain":
			own := slices.Contains(d.Domains, strings.ToLower(p.Domain))
			kind := "org_link"
			if !own {
				kind = "specific_link"
			}
			out = append(out, connector.Grant{Kind: kind, Ref: strings.ToLower(p.Domain), Role: role(p.Role), External: !own})
		case "user", "group":
			email := strings.ToLower(p.Email)
			at := strings.LastIndexByte(email, '@')
			out = append(out, connector.Grant{Kind: p.Type, Ref: email, Role: role(p.Role), External: at >= 0 && !slices.Contains(d.Domains, email[at+1:])})
		}
	}
	return out, nil
}

// Labels: Drive labels need their ids configured per tenant; not read yet.
func (d *Drive) Labels(context.Context, connector.Item) ([]string, error) { return nil, nil }

// OAuthGrants reads token authorizations (Admin SDK Reports, application "token", event "authorize") since a
// time: which third-party apps users let into their Google data, with what scopes.
func (d *Drive) OAuthGrants(ctx context.Context, since time.Time) ([]connector.OAuthGrant, error) {
	var out []connector.OAuthGrant
	for page := ""; ; {
		q := url.Values{"eventName": {"authorize"}, "startTime": {since.UTC().Format(time.RFC3339)}, "maxResults": {"1000"}}
		if page != "" {
			q.Set("pageToken", page)
		}
		var r struct {
			Items []struct {
				ID struct {
					Time time.Time `json:"time"`
				} `json:"id"`
				Actor struct {
					Email string `json:"email"`
				} `json:"actor"`
				Events []struct {
					Name       string `json:"name"`
					Parameters []struct {
						Name       string   `json:"name"`
						Value      string   `json:"value"`
						MultiValue []string `json:"multiValue"`
					} `json:"parameters"`
				} `json:"events"`
			} `json:"items"`
			Next string `json:"nextPageToken"`
		}
		if err := d.getJSON(ctx, d.Admin, "/admin/reports/v1/activity/users/all/applications/token", q, &r); err != nil {
			return nil, fmt.Errorf("token audit: %w", err)
		}
		for _, it := range r.Items {
			for _, ev := range it.Events {
				if ev.Name != "authorize" {
					continue
				}
				g := connector.OAuthGrant{User: strings.ToLower(it.Actor.Email), At: it.ID.Time}
				for _, p := range ev.Parameters {
					switch p.Name {
					case "client_id":
						g.ClientID = p.Value
					case "app_name":
						g.AppName = p.Value
					case "scope":
						g.Scopes = p.MultiValue
					}
				}
				if g.ClientID != "" {
					out = append(out, g)
				}
			}
		}
		if page = r.Next; page == "" {
			return out, nil
		}
	}
}
