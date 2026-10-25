// Package compliance holds connectors for AI vendors' compliance APIs, which let the bank classify what its
// people put into enterprise AI services (spec §11; residency: inbound pull only, ADR-0001):
//
//   - Claude: Anthropic's Compliance API for Claude Enterprise (chats and their messages, uploaded files),
//     https://platform.claude.com/docs/en/manage-claude/compliance-api
//   - ChatGPT: OpenAI's Compliance Logs for ChatGPT Enterprise (conversation_message log files). Only the logs
//     endpoint is built: the rest of OpenAI's Compliance API reference was not available to verify.
package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"wantimpres26/internal/connector"
)

// --- Claude Enterprise ---

// Claude reads chats through a Compliance Access Key (scope read:compliance_user_data).
type Claude struct {
	BaseURL string // https://api.anthropic.com
	Key     string
	HTTP    *http.Client
	Backoff connector.Backoff // 600 requests/min per parent org; 429 carries retry-after
}

func (c *Claude) get(ctx context.Context, path string, q url.Values) (*http.Response, error) {
	return c.Backoff.Do(ctx, c.HTTP, func() (*http.Request, error) {
		u := c.BaseURL + "/v1/compliance" + path
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err == nil {
			req.Header.Set("x-api-key", c.Key)
			req.Header.Set("anthropic-version", "2023-06-01")
		}
		return req, err
	}, nil)
}

func (c *Claude) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	resp, err := c.get(ctx, path, q)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out)
}

// The whole organization is one container (the key's parent org covers every linked org).
func (c *Claude) Containers(context.Context) ([]connector.Container, error) {
	return []connector.Container{{ID: "claude", Name: "Claude Enterprise", Kind: "claude_enterprise"}}, nil
}

type claudeChat struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at"`
	User      struct {
		Email string `json:"email_address"`
	} `json:"user"`
}

const epoch = "1970-01-01T00:00:00Z"

// Items pages chats by updated_at (oldest first). Cursor "since=<t>;after=<id>": this pass lists chats updated
// after t, continuing after id; at its end the next pass starts after the newest updated_at seen. A deleted chat
// comes back with deleted_at set.
func (c *Claude) Items(ctx context.Context, ct connector.Container, cursor string) (connector.Page, error) {
	since, after, newest := epoch, "", ""
	for _, part := range strings.Split(cursor, ";") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "since":
			since = v
		case "after":
			after = v
		case "newest": // the newest updated_at seen so far in this pass
			newest = v
		}
	}
	if newest == "" {
		newest = since
	}
	newestT, err := time.Parse(time.RFC3339Nano, newest)
	if err != nil {
		return connector.Page{}, fmt.Errorf("bad cursor %q", cursor)
	}
	q := url.Values{"order_by": {"updated_at"}, "updated_at.gt": {since}, "limit": {"1000"}}
	if after != "" {
		q.Set("after_id", after)
	}
	var r struct {
		Data    []claudeChat `json:"data"`
		HasMore bool         `json:"has_more"`
		LastID  string       `json:"last_id"`
	}
	if err := c.getJSON(ctx, "/apps/chats", q, &r); err != nil {
		return connector.Page{}, err
	}
	var p connector.Page
	for _, ch := range r.Data {
		name := ch.Name
		if name == "" {
			name = "chat " + ch.ID
		}
		ts := ch.UpdatedAt.UTC().Format(time.RFC3339Nano)
		if ch.UpdatedAt.After(newestT) { // compare times, not strings: "…:00Z" sorts after "…:00.1Z"
			newestT = ch.UpdatedAt
		}
		p.Items = append(p.Items, connector.Item{ID: ch.ID, ContainerID: ct.ID, Name: name + ".txt", Path: "chat/" + ch.ID,
			ContentTag: ts, Modified: ch.UpdatedAt, MimeType: "text/plain", Deleted: ch.DeletedAt != nil})
	}
	newest = newestT.UTC().Format(time.RFC3339Nano)
	if r.HasMore {
		p.Next = fmt.Sprintf("since=%s;after=%s;newest=%s", since, r.LastID, newest)
	} else {
		p.Next, p.Done = "since="+newest, true
	}
	return p, nil
}

// Get assembles the chat as text: each message's text, then the text of uploaded files (some uploads are kept
// by the service as extracted text). Binary uploads are named but not read here.
func (c *Claude) Get(ctx context.Context, it connector.Item, maxBytes int64) ([]byte, error) {
	var r struct {
		Messages []struct {
			Role    string `json:"role"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			Files []struct {
				ID       string `json:"id"`
				Filename string `json:"filename"`
				MimeType string `json:"mime_type"`
				Size     int64  `json:"size_bytes"`
			} `json:"files"`
		} `json:"chat_messages"`
	}
	if err := c.getJSON(ctx, "/apps/chats/"+url.PathEscape(it.ID)+"/messages", nil, &r); err != nil {
		return nil, err
	}
	var b strings.Builder
	over := func() bool { return int64(b.Len()) > maxBytes }
	for _, m := range r.Messages {
		for _, part := range m.Content {
			if part.Type == "text" {
				b.WriteString(m.Role + ": " + part.Text + "\n")
			}
		}
		for _, f := range m.Files {
			if f.Size > maxBytes-int64(b.Len()) {
				fmt.Fprintf(&b, "[file %s: %d bytes, over the limit]\n", f.Filename, f.Size)
				continue
			}
			resp, err := c.get(ctx, "/apps/chats/files/"+url.PathEscape(f.ID)+"/content", nil)
			if err != nil {
				return nil, fmt.Errorf("file %s: %w", f.ID, err)
			}
			data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
			_ = resp.Body.Close()
			if err != nil {
				return nil, err
			}
			if utf8.Valid(data) {
				fmt.Fprintf(&b, "[file %s]\n%s\n", f.Filename, data)
			} else {
				fmt.Fprintf(&b, "[file %s (%s): binary, not read]\n", f.Filename, f.MimeType)
			}
		}
		if over() {
			return nil, fmt.Errorf("chat exceeds %d bytes", maxBytes)
		}
	}
	return []byte(b.String()), nil
}

// ACL: chats carry no sharing field (snapshots and project sharing only appear in the Activity Feed).
func (c *Claude) ACL(context.Context, connector.Item) ([]connector.Grant, error) { return nil, nil }

func (c *Claude) Labels(context.Context, connector.Item) ([]string, error) { return nil, nil }

func (c *Claude) Remediate(context.Context, connector.Item, connector.Action, bool) (connector.Change, error) {
	return connector.Change{}, connector.ErrNotSupported
}

func (c *Claude) Undo(context.Context, connector.Item, json.RawMessage, bool) (connector.Change, error) {
	return connector.Change{}, connector.ErrNotSupported
}

// --- ChatGPT Enterprise (Compliance Logs) ---

// ChatGPT reads conversation_message log files of one workspace with an Enterprise Compliance API key.
type ChatGPT struct {
	BaseURL   string // https://api.chatgpt.com
	Key       string
	Workspace string
	HTTP      *http.Client
	Backoff   connector.Backoff
}

func (c *ChatGPT) get(ctx context.Context, path string, q url.Values) (*http.Response, error) {
	return c.Backoff.Do(ctx, c.HTTP, func() (*http.Request, error) {
		u := c.BaseURL + "/v1/compliance/workspaces/" + url.PathEscape(c.Workspace) + path
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+c.Key)
		}
		return req, err
	}, nil)
}

func (c *ChatGPT) Containers(context.Context) ([]connector.Container, error) {
	return []connector.Container{{ID: "chatgpt:" + c.Workspace, Name: "ChatGPT Enterprise " + c.Workspace, Kind: "chatgpt_enterprise"}}, nil
}

// Items lists log files after a time; cursor "after=<time>" is the previous answer's last_end_time. Log files
// never change, so a file id is its own content tag.
func (c *ChatGPT) Items(ctx context.Context, ct connector.Container, cursor string) (connector.Page, error) {
	after := strings.TrimPrefix(cursor, "after=")
	if after == "" {
		after = epoch
	}
	resp, err := c.get(ctx, "/logs", url.Values{"event_type": {"conversation_message"}, "limit": {"100"}, "after": {after}})
	if err != nil {
		return connector.Page{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	var r struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		HasMore     bool   `json:"has_more"`
		LastEndTime string `json:"last_end_time"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&r); err != nil {
		return connector.Page{}, err
	}
	p := connector.Page{Done: !r.HasMore}
	if r.LastEndTime != "" {
		after = r.LastEndTime
	}
	p.Next = "after=" + after
	for _, l := range r.Data {
		p.Items = append(p.Items, connector.Item{ID: l.ID, ContainerID: ct.ID, Name: l.ID + ".jsonl", Path: "logs/" + l.ID, ContentTag: l.ID, MimeType: "application/jsonl"})
	}
	return p, nil
}

// Get downloads a log file (JSONL; the API redirects to the file).
func (c *ChatGPT) Get(ctx context.Context, it connector.Item, maxBytes int64) ([]byte, error) {
	resp, err := c.get(ctx, "/logs/"+url.PathEscape(it.ID), nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err == nil && int64(len(b)) > maxBytes {
		err = fmt.Errorf("log file exceeds %d bytes", maxBytes)
	}
	return b, err
}

func (c *ChatGPT) ACL(context.Context, connector.Item) ([]connector.Grant, error) { return nil, nil }

func (c *ChatGPT) Labels(context.Context, connector.Item) ([]string, error) { return nil, nil }

func (c *ChatGPT) Remediate(context.Context, connector.Item, connector.Action, bool) (connector.Change, error) {
	return connector.Change{}, connector.ErrNotSupported
}

func (c *ChatGPT) Undo(context.Context, connector.Item, json.RawMessage, bool) (connector.Change, error) {
	return connector.Change{}, connector.ErrNotSupported
}
