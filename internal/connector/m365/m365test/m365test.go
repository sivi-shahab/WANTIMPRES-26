// Package m365test is a fake Microsoft Graph for connector and scanner tests: sites, drives, delta queries with
// paging and versioned delta links, sharing changes, permissions, sensitivity labels, throttling, and counters of
// what was fetched.
package m365test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type Item struct {
	Name, Path string
	Content    []byte
	Perms      []map[string]any // Graph permission objects
	Labels     []string
	Folder     bool
	Parent     string // parent item id; "" = root
	deleted    bool
	cTag       int // bumps on content change
	version    int // feed version of the last change of any kind
}

type Drive struct {
	ID, Name, Type string
	Items          map[string]*Item
}

type Graph struct {
	*httptest.Server
	mu       sync.Mutex
	Drives   []*Drive
	version  int
	PageSize int
	// Throttle: requests whose path contains the key get that many 429/503 answers first (Retry-After value,
	// "" = none).
	Throttle map[string]*Throttle
	Fetches  map[string]int // "content:<id>", "perms:<id>", "labels:<id>"
	Writes   []string       // every write call, "<METHOD> <path>"
	permSeq  int
}

type Throttle struct {
	Times      int
	Status     int
	RetryAfter string
}

func New() *Graph {
	g := &Graph{PageSize: 2, Throttle: map[string]*Throttle{}, Fetches: map[string]int{}}
	g.Server = httptest.NewServer(http.HandlerFunc(g.serve))
	return g
}

// URL is the Graph base (…/v1.0).
func (g *Graph) URL() string { return g.Server.URL + "/v1.0" }

func (g *Graph) drive(id string) *Drive {
	for _, d := range g.Drives {
		if d.ID == id {
			return d
		}
	}
	return nil
}

// Put adds or changes an item: new content bumps its cTag; every call is a change in the feed.
func (g *Graph) Put(drive, id string, it Item) {
	g.mu.Lock()
	defer g.mu.Unlock()
	d := g.drive(drive)
	g.version++
	old := d.Items[id]
	it.version, it.cTag = g.version, 1
	it.Perms = g.ids(it.Perms)
	if old != nil {
		it.cTag = old.cTag
		if string(old.Content) != string(it.Content) {
			it.cTag++
		}
	}
	d.Items[id] = &it
}

// Share replaces an item's permissions: a sharing change, content (cTag) untouched.
func (g *Graph) Share(drive, id string, perms []map[string]any) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.version++
	it := g.drive(drive).Items[id]
	it.Perms, it.version = g.ids(perms), g.version
}

// ids gives permissions without one an id, as Graph does.
func (g *Graph) ids(perms []map[string]any) []map[string]any {
	for _, p := range perms {
		if p["id"] == nil {
			g.permSeq++
			p["id"] = fmt.Sprintf("perm-%d", g.permSeq)
		}
	}
	return perms
}

// Item returns a copy of an item's current state.
func (g *Graph) Item(drive, id string) Item {
	g.mu.Lock()
	defer g.mu.Unlock()
	return *g.drive(drive).Items[id]
}

func (g *Graph) Delete(drive, id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.version++
	it := g.drive(drive).Items[id]
	it.deleted, it.version = true, g.version
}

func (g *Graph) Count(key string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.Fetches[key]
}

func (g *Graph) json(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (g *Graph) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/v1.0")
	for key, t := range g.Throttle {
		if strings.Contains(p, key) && t.Times > 0 {
			t.Times--
			if t.RetryAfter != "" {
				w.Header().Set("Retry-After", t.RetryAfter)
			}
			w.WriteHeader(t.Status)
			return
		}
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	switch {
	case p == "/sites/getAllSites":
		g.json(w, map[string]any{"value": []any{map[string]any{"id": "site-1"}}})
	case len(parts) == 3 && parts[0] == "sites" && parts[2] == "drives":
		var v []any
		for _, d := range g.Drives {
			if d.Type == "documentLibrary" {
				v = append(v, map[string]any{"id": d.ID, "name": d.Name, "driveType": d.Type})
			}
		}
		g.json(w, map[string]any{"value": v})
	case p == "/users":
		g.json(w, map[string]any{"value": []any{map[string]any{"id": "u-1"}, map[string]any{"id": "u-2"}}})
	case len(parts) == 3 && parts[0] == "users" && parts[2] == "drive":
		for _, d := range g.Drives {
			if d.Type == "business" && parts[1] == "u-1" {
				g.json(w, map[string]any{"id": d.ID, "name": d.Name, "driveType": d.Type})
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	case len(parts) == 4 && parts[0] == "drives" && parts[3] == "delta":
		g.delta(w, r, g.drive(parts[1]))
	case len(parts) >= 4 && parts[0] == "drives" && parts[2] == "root:" && r.Method == http.MethodGet:
		// /drives/{d}/root:/{name}: an item at the root by name
		name := strings.TrimSuffix(strings.Join(parts[3:], "/"), ":")
		for id, it := range g.drive(parts[1]).Items {
			if it.Name == name && it.Parent == "" && !it.deleted {
				g.json(w, map[string]any{"id": id, "name": it.Name})
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	case len(parts) == 4 && parts[0] == "drives" && parts[2] == "root" && parts[3] == "children" && r.Method == http.MethodPost:
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		g.Writes = append(g.Writes, "POST create folder "+body.Name)
		g.version++
		id := "folder-" + strings.ReplaceAll(strings.ToLower(body.Name), " ", "-")
		g.drive(parts[1]).Items[id] = &Item{Name: body.Name, Folder: true, version: g.version}
		w.WriteHeader(http.StatusCreated)
		g.json(w, map[string]any{"id": id, "name": body.Name})
	case len(parts) >= 4 && parts[0] == "drives" && parts[2] == "items":
		it := g.drive(parts[1]).Items[parts[3]]
		if it == nil || it.deleted {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet && !strings.HasSuffix(r.URL.Path, "/extractSensitivityLabels") { // a read, despite POST
			g.Writes = append(g.Writes, r.Method+" "+strings.Join(parts[4:], "/"))
		}
		switch {
		case len(parts) == 4 && r.Method == http.MethodGet:
			g.json(w, map[string]any{"id": parts[3], "name": it.Name, "parentReference": map[string]any{"id": it.Parent}})
		case len(parts) == 4 && r.Method == http.MethodPatch:
			var body struct {
				Parent struct {
					ID string `json:"id"`
				} `json:"parentReference"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			g.version++
			it.Parent, it.version = body.Parent.ID, g.version
			g.json(w, map[string]any{"id": parts[3]})
		case len(parts) == 6 && parts[4] == "permissions" && r.Method == http.MethodDelete:
			n := len(it.Perms)
			it.Perms = slices.DeleteFunc(it.Perms, func(p map[string]any) bool { return p["id"] == parts[5] && p["inheritedFrom"] == nil })
			if len(it.Perms) == n {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			g.version++
			it.version = g.version
			w.WriteHeader(http.StatusNoContent)
		case len(parts) == 5 && parts[4] == "invite" && r.Method == http.MethodPost:
			var body struct {
				Recipients []struct {
					Email string `json:"email"`
				} `json:"recipients"`
				Roles []string `json:"roles"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			for _, rc := range body.Recipients {
				it.Perms = g.ids(append(it.Perms, UserPerm(rc.Email, body.Roles[0])))
			}
			g.version++
			it.version = g.version
			g.json(w, map[string]any{"value": []any{}})
		case len(parts) == 5 && parts[4] == "assignSensitivityLabel" && r.Method == http.MethodPost:
			var body struct {
				ID string `json:"sensitivityLabelId"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			it.Labels = []string{body.ID}
			g.version++
			it.version, it.cTag = g.version, it.cTag+1 // the label is written into the file
			w.WriteHeader(http.StatusAccepted)
		case len(parts) == 5 && parts[4] == "content":
			g.Fetches["content:"+parts[3]]++
			// nosemgrep: no-direct-write-to-responsewriter -- fake Graph API for tests
			_, _ = w.Write(it.Content)
		case len(parts) == 5 && parts[4] == "permissions" && r.Method == http.MethodGet:
			g.Fetches["perms:"+parts[3]]++
			g.json(w, map[string]any{"value": it.Perms})
		case len(parts) == 5 && parts[4] == "extractSensitivityLabels" && r.Method == http.MethodPost:
			g.Fetches["labels:"+parts[3]]++
			var ls []any
			for _, l := range it.Labels {
				ls = append(ls, map[string]any{"sensitivityLabelId": l, "assignmentMethod": "standard"})
			}
			g.json(w, map[string]any{"labels": ls})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// delta: no token = everything; token=v = changes after feed version v. Paged by PageSize via skip.
func (g *Graph) delta(w http.ResponseWriter, r *http.Request, d *Drive) {
	since, _ := strconv.Atoi(r.URL.Query().Get("token"))
	skip, _ := strconv.Atoi(r.URL.Query().Get("skip"))
	ids := make([]string, 0, len(d.Items))
	for id, it := range d.Items {
		if it.version > since && (since > 0 || !it.deleted) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	end := min(skip+g.PageSize, len(ids))
	var v []any
	for _, id := range ids[min(skip, len(ids)):end] {
		it := d.Items[id]
		m := map[string]any{"id": id, "name": it.Name, "parentReference": map[string]any{"path": it.Path}}
		switch {
		case it.deleted:
			m["deleted"] = map[string]any{"state": "deleted"}
		case it.Folder:
			m["folder"] = map[string]any{}
		default:
			m["file"] = map[string]any{}
			m["size"] = len(it.Content)
			m["cTag"] = fmt.Sprintf("c:%s,%d", id, it.cTag)
		}
		v = append(v, m)
	}
	base := g.URL() + "/drives/" + d.ID + "/root/delta"
	out := map[string]any{"value": v}
	if end < len(ids) {
		out["@odata.nextLink"] = fmt.Sprintf("%s?token=%d&skip=%d", base, since, end)
	} else {
		out["@odata.deltaLink"] = fmt.Sprintf("%s?token=%d", base, g.version)
	}
	g.json(w, out)
}

// Perm builders.
func UserPerm(upn, role string) map[string]any {
	return map[string]any{"roles": []string{role}, "grantedToV2": map[string]any{"user": map[string]any{"userPrincipalName": upn}}}
}

func GroupPerm(name string) map[string]any {
	return map[string]any{"roles": []string{"read"}, "grantedToV2": map[string]any{"siteGroup": map[string]any{"displayName": name}}}
}

func LinkPerm(scope string, upns ...string) map[string]any {
	ids := []any{}
	for _, u := range upns {
		ids = append(ids, map[string]any{"user": map[string]any{"email": u}})
	}
	return map[string]any{"roles": []string{"read"}, "link": map[string]any{"scope": scope, "type": "view"}, "grantedToIdentitiesV2": ids}
}
