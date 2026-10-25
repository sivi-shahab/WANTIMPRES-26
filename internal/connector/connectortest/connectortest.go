// Package connectortest is the Connector SDK contract test (ticket 32 AC): every connector, whatever its source,
// must behave the same way for the scanner (internal/datascan). A connector test supplies a Harness that can
// change the backing store (a fake, an emulator or the real service) and calls Run.
package connectortest

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"wantimpres26/internal/connector"
)

// Harness drives one connector over one empty container.
type Harness struct {
	Conn      connector.Connector
	Container string // id of an existing, empty container
	// Put creates or replaces a file and returns the item id the connector will report for it.
	Put func(t *testing.T, name string, content []byte) string
	// Delete removes a file; nil for append-only sources (audit logs), which are then checked for new files
	// appearing instead of changes and deletions (AppendOnly).
	Delete     func(t *testing.T, id string)
	AppendOnly bool
	// Derived: Get returns a rendering that contains what Put stored (a chat transcript), not the bytes themselves.
	Derived bool
	// Share makes the file readable by anyone (anonymous link, public bucket, …); nil when the source has no
	// per-file sharing to change. SharingInFeed: a sharing change appears in the incremental feed.
	Share         func(t *testing.T, id string)
	SharingInFeed bool
	// Settle runs after changes, before the feed is read (deliver pending events, wait for consistency); may be nil.
	Settle func(t *testing.T)
}

// walk reads the feed from cursor to the end of the pass, returning the non-folder items and the cursor to
// resume from.
func walk(t *testing.T, h Harness, c connector.Container, cursor string) ([]connector.Item, string) {
	t.Helper()
	var out []connector.Item
	for range 10000 {
		p, err := h.Conn.Items(context.Background(), c, cursor)
		if err != nil {
			t.Fatalf("Items(%q): %v", cursor, err)
		}
		for _, it := range p.Items {
			if !it.Folder {
				out = append(out, it)
			}
		}
		if p.Next == "" {
			t.Fatalf("Items(%q): empty cursor (Done=%v); the scanner could not resume", cursor, p.Done)
		}
		cursor = p.Next
		if p.Done {
			return out, cursor
		}
	}
	t.Fatal("feed never finished")
	return nil, ""
}

func settle(t *testing.T, h Harness) {
	if h.Settle != nil {
		h.Settle(t)
	}
}

func byID(items []connector.Item) map[string]connector.Item {
	m := map[string]connector.Item{}
	for _, it := range items {
		m[it.ID] = it // the latest report of an id wins, as in the scanner
	}
	return m
}

// Run checks the contract.
func Run(t *testing.T, h Harness) {
	ctx := context.Background()
	cs, err := h.Conn.Containers(ctx)
	if err != nil {
		t.Fatalf("Containers: %v", err)
	}
	i := slices.IndexFunc(cs, func(c connector.Container) bool { return c.ID == h.Container })
	if i < 0 {
		t.Fatalf("Containers %+v lack %s", cs, h.Container)
	}
	c := cs[i]
	if c.Kind == "" {
		t.Errorf("container %s has no kind", c.ID)
	}

	contents := map[string][]byte{}
	put := func(name string, b []byte) string {
		id := h.Put(t, name, b)
		contents[id] = b
		return id
	}
	a := put("a.txt", []byte("NIK 3201011505900001"))
	b := put("b.txt", []byte("versi satu"))
	cid := put("c.csv", []byte("kolom,isi\n1,dua\n"))
	settle(t, h)

	t.Run("bootstrap lists everything with content tags", func(t *testing.T) {
		got := byID(mustWalk(t, h, c, ""))
		for _, id := range []string{a, b, cid} {
			it, ok := got[id]
			// Size 0 = the source does not say (chats, logs); a size given must be right.
			if !ok || it.Deleted || it.ContentTag == "" || it.ContainerID != c.ID || it.Name == "" || (it.Size != 0 && it.Size != int64(len(contents[id]))) {
				t.Errorf("item %s: %+v (present %v)", id, it, ok)
			}
		}
	})
	_, cursor := walk(t, h, c, "")

	t.Run("get returns content within limits", func(t *testing.T) {
		got, err := h.Conn.Get(ctx, connector.Item{ID: a, ContainerID: c.ID, Size: int64(len(contents[a]))}, 1<<20)
		same := string(got) == string(contents[a]) || h.Derived && strings.Contains(string(got), string(contents[a]))
		if err != nil || !same {
			t.Errorf("Get: %q %v", got, err)
		}
		if _, err := h.Conn.Get(ctx, connector.Item{ID: a, ContainerID: c.ID, Size: int64(len(contents[a]))}, 4); err == nil {
			t.Error("Get past maxBytes succeeded")
		}
	})

	t.Run("no change, no items", func(t *testing.T) {
		settle(t, h)
		var items []connector.Item
		items, cursor = walk(t, h, c, cursor)
		for _, it := range items {
			if it.ID == a || it.ID == b || it.ID == cid {
				t.Errorf("unchanged item %s reported again", it.ID)
			}
		}
	})

	var tagB string
	for _, it := range mustWalk(t, h, c, "") {
		if it.ID == b {
			tagB = it.ContentTag
		}
	}
	if h.AppendOnly {
		t.Run("new files are in the feed, nothing else", func(t *testing.T) {
			d := put("d.txt", []byte("berkas baru"))
			settle(t, h)
			var items []connector.Item
			items, cursor = walk(t, h, c, cursor)
			got := byID(items)
			if it, ok := got[d]; !ok || it.Deleted || it.ContentTag == "" {
				t.Errorf("new item: %+v (present %v)", it, ok)
			}
			for _, id := range []string{a, b, cid} {
				if _, ok := got[id]; ok {
					t.Errorf("old item %s reported again", id)
				}
			}
		})
	}
	t.Run("content change and deletion are in the feed, nothing else", func(t *testing.T) {
		if h.AppendOnly {
			t.Skip("append-only source")
		}
		put("b.txt", []byte("versi dua, lebih panjang"))
		h.Delete(t, cid)
		settle(t, h)
		var items []connector.Item
		items, cursor = walk(t, h, c, cursor)
		got := byID(items)
		if it, ok := got[b]; !ok || it.Deleted || it.ContentTag == tagB {
			t.Errorf("changed item: %+v (present %v, old tag %s)", it, ok, tagB)
		}
		if it, ok := got[cid]; !ok || !it.Deleted {
			t.Errorf("deleted item: %+v (present %v)", it, ok)
		}
		if _, ok := got[a]; ok {
			t.Error("unchanged item reported")
		}
	})

	t.Run("acl, labels, remediation", func(t *testing.T) {
		acl, err := h.Conn.ACL(ctx, connector.Item{ID: a, ContainerID: c.ID})
		if err != nil {
			t.Fatalf("ACL: %v", err)
		}
		if slices.ContainsFunc(acl, func(g connector.Grant) bool { return g.Kind == "anyone_link" }) {
			t.Errorf("fresh item already public: %+v", acl)
		}
		if _, err := h.Conn.Labels(ctx, connector.Item{ID: a, ContainerID: c.ID}); err != nil {
			t.Errorf("Labels: %v", err)
		}
		item := connector.Item{ID: a, ContainerID: c.ID}
		revoke := connector.Action{Kind: connector.RevokeAnyoneLinks}
		if _, err := h.Conn.Remediate(ctx, item, revoke, true); err != nil && !errors.Is(err, connector.ErrNotSupported) && !errors.Is(err, connector.ErrNothingToDo) {
			t.Errorf("Remediate on a private item: %v", err)
		}
		if h.Share == nil {
			return
		}
		h.Share(t, a)
		settle(t, h)
		acl, err = h.Conn.ACL(ctx, connector.Item{ID: a, ContainerID: c.ID})
		if err != nil || !slices.ContainsFunc(acl, func(g connector.Grant) bool { return g.Kind == "anyone_link" && g.External }) {
			t.Errorf("after sharing with anyone: %+v %v", acl, err)
		}
		if h.SharingInFeed {
			items, _ := walk(t, h, c, cursor)
			if it, ok := byID(items)[a]; !ok || it.ContentTag == "" {
				t.Error("sharing change missing from the feed")
			}
		}
		public := func() bool {
			acl, err := h.Conn.ACL(ctx, item)
			if err != nil {
				t.Fatalf("ACL: %v", err)
			}
			return slices.ContainsFunc(acl, func(g connector.Grant) bool { return g.Kind == "anyone_link" })
		}

		// FR-DATA-6 (ticket 33): a dry run changes nothing and says what would happen; executing does exactly
		// that; undo, when offered, restores it.
		plan, err := h.Conn.Remediate(ctx, item, revoke, true)
		if errors.Is(err, connector.ErrNotSupported) {
			return
		}
		if err != nil || len(plan.Steps) == 0 || !public() {
			t.Fatalf("dry run: %+v %v (still public: %v)", plan, err, public())
		}
		if again, _ := h.Conn.Remediate(ctx, item, revoke, true); !slices.Equal(again.Steps, plan.Steps) {
			t.Errorf("same state, different plan: %v vs %v", again.Steps, plan.Steps)
		}
		done, err := h.Conn.Remediate(ctx, item, revoke, false)
		if err != nil || !slices.Equal(done.Steps, plan.Steps) || public() {
			t.Fatalf("execute: %+v %v (still public: %v; planned %v)", done, err, public(), plan.Steps)
		}
		if _, err := h.Conn.Remediate(ctx, item, revoke, true); !errors.Is(err, connector.ErrNothingToDo) {
			t.Errorf("after execution: %v", err)
		}
		if done.Undo == nil {
			return
		}
		undoPlan, err := h.Conn.Undo(ctx, item, done.Undo, true)
		if err != nil || len(undoPlan.Steps) == 0 || public() {
			t.Fatalf("undo dry run: %+v %v", undoPlan, err)
		}
		if _, err := h.Conn.Undo(ctx, item, done.Undo, false); err != nil || !public() {
			t.Errorf("undo: %v (public again: %v)", err, public())
		}
	})
}

func mustWalk(t *testing.T, h Harness, c connector.Container, cursor string) []connector.Item {
	items, _ := walk(t, h, c, cursor)
	return items
}
