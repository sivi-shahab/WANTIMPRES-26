package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"wantimpres26/internal/connector"
	"wantimpres26/internal/connector/connectortest"
)

// fakeClaude follows the documented Compliance API: chats ordered by updated_at with updated_at.gt and
// after_id paging, deleted chats with deleted_at, messages with content and files, file content.
type fakeClaude struct {
	mu       sync.Mutex
	clock    time.Time
	chats    map[string]*chat
	files    map[string][]byte
	throttle []int // statuses to answer first (429/529), with retry-after 3
	pageSize int
}

type chat struct {
	text    string
	file    string
	updated time.Time
	deleted bool
}

func (f *fakeClaude) put(id, text, file string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clock = f.clock.Add(time.Second + 100*time.Millisecond) // whole and fractional seconds: ordering by time, not text
	f.chats[id] = &chat{text: text, file: file, updated: f.clock}
}

func (f *fakeClaude) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("x-api-key") != "sk-ant-api01-test" || r.Header.Get("anthropic-version") != "2023-06-01" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if len(f.throttle) > 0 {
		w.Header().Set("retry-after", "3")
		w.WriteHeader(f.throttle[0])
		f.throttle = f.throttle[1:]
		return
	}
	js := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	p := strings.TrimPrefix(r.URL.Path, "/v1/compliance")
	q := r.URL.Query()
	switch {
	case p == "/apps/chats":
		if q.Get("order_by") != "updated_at" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		since, _ := time.Parse(time.RFC3339Nano, q.Get("updated_at.gt"))
		var ids []string
		for id, c := range f.chats {
			if c.updated.After(since) {
				ids = append(ids, id)
			}
		}
		sort.Slice(ids, func(i, j int) bool { return f.chats[ids[i]].updated.Before(f.chats[ids[j]].updated) })
		if a := q.Get("after_id"); a != "" {
			ids = ids[slices.Index(ids, a)+1:]
		}
		more := len(ids) > f.pageSize
		ids = ids[:min(len(ids), f.pageSize)]
		var data []any
		for _, id := range ids {
			c := f.chats[id]
			m := map[string]any{"id": id, "name": "Chat " + id, "updated_at": c.updated, "user": map[string]any{"id": "u1", "email_address": "ani@bankmega.com"}}
			if c.deleted {
				m["deleted_at"], m["name"] = c.updated, ""
			}
			data = append(data, m)
		}
		last := ""
		if len(ids) > 0 {
			last = ids[len(ids)-1]
		}
		js(map[string]any{"data": data, "has_more": more, "last_id": last})
	case strings.HasPrefix(p, "/apps/chats/files/") && strings.HasSuffix(p, "/content"):
		_, _ = w.Write(f.files[strings.TrimSuffix(strings.TrimPrefix(p, "/apps/chats/files/"), "/content")])
	case strings.HasPrefix(p, "/apps/chats/") && strings.HasSuffix(p, "/messages"):
		c := f.chats[strings.TrimSuffix(strings.TrimPrefix(p, "/apps/chats/"), "/messages")]
		msg := map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": c.text}}, "files": nil}
		if c.file != "" {
			msg["files"] = []any{map[string]any{"id": c.file, "filename": c.file + ".txt", "mime_type": "text/plain", "size_bytes": len(f.files[c.file])}}
		}
		js(map[string]any{"chat_messages": []any{msg, map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "text", "text": "Baik."}}}}})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func claude(t *testing.T) (*fakeClaude, *Claude, *[]time.Duration) {
	f := &fakeClaude{clock: time.Date(2026, 10, 4, 8, 0, 0, 0, time.UTC), chats: map[string]*chat{}, files: map[string][]byte{}, pageSize: 2}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	var waits []time.Duration
	return f, &Claude{BaseURL: srv.URL, Key: "sk-ant-api01-test", HTTP: srv.Client(),
		Backoff: connector.Backoff{Retries: 3, Base: time.Second, Max: time.Minute, Sleep: func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }}}, &waits
}

// AC (ticket 32): the Claude Enterprise connector against the SDK contract.
func TestClaudeContract(t *testing.T) {
	f, c, _ := claude(t)
	connectortest.Run(t, connectortest.Harness{
		Conn: c, Container: "claude", Derived: true,
		Put: func(_ *testing.T, name string, b []byte) string {
			id := "chat-" + strings.TrimSuffix(name, ".txt")
			f.put(id, string(b), "")
			return id
		},
		Delete: func(_ *testing.T, id string) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.clock = f.clock.Add(time.Second)
			f.chats[id].deleted, f.chats[id].updated = true, f.clock
		},
	})
}

func TestClaudeTranscriptAndThrottling(t *testing.T) {
	f, c, waits := claude(t)
	f.files["file-1"] = []byte("lampiran: kartu 4111 1111 1111 1111")
	f.put("chat-a", "Tolong ringkas data nasabah NIK 3201011505900001", "file-1")
	f.throttle = []int{429, 529}
	p, err := c.Items(context.Background(), connector.Container{ID: "claude"}, "")
	if err != nil || len(p.Items) != 1 || !p.Done {
		t.Fatalf("items %+v %v", p, err)
	}
	if !slices.Equal(*waits, []time.Duration{3 * time.Second, 3 * time.Second}) {
		t.Errorf("retry-after waits %v", *waits)
	}
	b, err := c.Get(context.Background(), p.Items[0], 1<<20)
	want := "user: Tolong ringkas data nasabah NIK 3201011505900001\n[file file-1.txt]\nlampiran: kartu 4111 1111 1111 1111\nassistant: Baik.\n"
	if err != nil || string(b) != want {
		t.Errorf("transcript:\n%q\n%v", b, err)
	}
	if _, err := c.Get(context.Background(), p.Items[0], 20); err == nil {
		t.Error("transcript past the limit")
	}
}

// fakeChatGPT serves Compliance Logs: log files of conversation_message events, listed after a time, with
// last_end_time to continue from.
type fakeChatGPT struct {
	mu   sync.Mutex
	logs []struct {
		id   string
		end  time.Time
		body []byte
	}
	clock time.Time
}

func (f *fakeChatGPT) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer cg-key" || !strings.HasPrefix(r.URL.Path, "/v1/compliance/workspaces/ws-1/logs") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if id := strings.TrimPrefix(r.URL.Path, "/v1/compliance/workspaces/ws-1/logs/"); id != r.URL.Path {
		for _, l := range f.logs {
			if l.id == id {
				_, _ = w.Write(l.body)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}
	after, _ := time.Parse(time.RFC3339Nano, r.URL.Query().Get("after"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if r.URL.Query().Get("event_type") != "conversation_message" || limit == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var data []any
	last := ""
	more := false
	for _, l := range f.logs {
		if l.end.After(after) {
			if len(data) == 2 {
				more = true
				break
			}
			data = append(data, map[string]any{"id": l.id})
			last = l.end.Format(time.RFC3339Nano)
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "has_more": more, "last_end_time": last})
}

func TestChatGPTContract(t *testing.T) {
	f := &fakeChatGPT{clock: time.Date(2026, 10, 4, 8, 0, 0, 0, time.UTC)}
	srv := httptest.NewServer(f)
	defer srv.Close()
	n := 0
	connectortest.Run(t, connectortest.Harness{
		Conn:      &ChatGPT{BaseURL: srv.URL, Key: "cg-key", Workspace: "ws-1", HTTP: srv.Client(), Backoff: connector.DefaultBackoff},
		Container: "chatgpt:ws-1", AppendOnly: true,
		Put: func(_ *testing.T, _ string, b []byte) string {
			f.mu.Lock()
			defer f.mu.Unlock()
			n++
			f.clock = f.clock.Add(time.Minute)
			id := fmt.Sprintf("log-%d", n)
			f.logs = append(f.logs, struct {
				id   string
				end  time.Time
				body []byte
			}{id, f.clock, b})
			return id
		},
	})
}
