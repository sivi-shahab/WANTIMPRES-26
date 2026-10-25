package datascan

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"wantimpres26/internal/connector"
)

// aiWords: app names that say "AI" (FR-AGT-1 shadow agents via OAuth). The AI app catalog (ticket 16) adds its
// vendors and app names.
var aiWords = regexp.MustCompile(`(?i)\b(?:ai|gpt|chatgpt|openai|claude|anthropic|gemini|bard|copilot|perplexity|mistral|llama|deepseek|grok|llm|jasper|writesonic|otter|fireflies|notion ai)\b`)

// OAuthAudit records third-party OAuth grants from a source's audit feed and queues the AI apps among them for
// review (agents.discovered, source oauth_grant). Its position is kept like a container cursor.
type OAuthAudit struct {
	DB     *pgxpool.Pool
	Source string
	Fetch  func(ctx context.Context, since time.Time) ([]connector.OAuthGrant, error)
	Pepper []byte
	Now    func() time.Time
}

// Lag: audit reports arrive late (Google: up to hours), so each pass re-reads the last day; grants are
// idempotent per (app, user).
const Lag = 24 * time.Hour

// Run reads grants since the last pass and returns how many AI apps were seen.
func (a *OAuthAudit) Run(ctx context.Context) (int, error) {
	var cursor string
	err := a.DB.QueryRow(ctx, "SELECT cursor FROM data.containers WHERE source_id = $1 AND container_id = '@oauth-audit'", a.Source).Scan(&cursor)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	since := a.Now().Add(-30 * 24 * time.Hour) // first pass: the last 30 days
	if t, err := time.Parse(time.RFC3339, cursor); err == nil {
		since = t.Add(-Lag)
	}
	grants, err := a.Fetch(ctx, since)
	if err != nil {
		return 0, err
	}
	names, err := catalogNames(ctx, a.DB)
	if err != nil {
		return 0, err
	}
	ai := map[string]bool{}
	err = pgx.BeginFunc(ctx, a.DB, func(tx pgx.Tx) error {
		for _, g := range grants {
			isAI := aiWords.MatchString(g.AppName) || matchesCatalog(g.AppName, names)
			if _, err := tx.Exec(ctx, `INSERT INTO data.oauth_grants (source, client_id, app_name, scopes, ai, first_seen, last_seen)
				VALUES ($1, $2, $3, $4, $5, $6, $6) ON CONFLICT (source, client_id) DO UPDATE SET app_name = $3,
				scopes = ARRAY(SELECT DISTINCT unnest(data.oauth_grants.scopes || $4)), ai = $5,
				first_seen = least(data.oauth_grants.first_seen, $6), last_seen = greatest(data.oauth_grants.last_seen, $6)`,
				a.Source, g.ClientID, g.AppName, nonNil(g.Scopes), isAI, g.At); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "INSERT INTO data.oauth_grant_users (source, client_id, user_hash) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
				a.Source, g.ClientID, a.hash(g.User)); err != nil {
				return err
			}
			if isAI && !ai[g.ClientID] {
				ai[g.ClientID] = true
				// The shadow-agent review queue (ticket 27): an AI app holding bank users' OAuth grants.
				if _, err := tx.Exec(ctx, `INSERT INTO agents.discovered (agent_id, source, state, first_seen, last_seen, events)
					VALUES ($1, 'oauth_grant', 'pending', $2, $2, 1) ON CONFLICT (agent_id) DO UPDATE SET
					last_seen = greatest(agents.discovered.last_seen, $2), events = agents.discovered.events + 1`,
					"oauth:"+g.ClientID, g.At); err != nil {
					return err
				}
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO data.containers (source_id, container_id, name, kind, cursor, last_scan) VALUES ($1, '@oauth-audit', 'OAuth grants', 'oauth_audit', $2, $3)
			ON CONFLICT (source_id, container_id) DO UPDATE SET cursor = $2, last_scan = $3`, a.Source, a.Now().UTC().Format(time.RFC3339), a.Now())
		return err
	})
	return len(ai), err
}

func (a *OAuthAudit) hash(user string) string {
	s := Scanner{Pepper: a.Pepper, Source: a.Source}
	return s.hash("user:" + strings.ToLower(user))
}

// catalogNames: app names of the current AI app catalog feed (ticket 16), lower-case. Not vendors: "Google" or
// "Microsoft" would make every Drive or Office add-on an AI app.
func catalogNames(ctx context.Context, db *pgxpool.Pool) ([]string, error) {
	rows, err := db.Query(ctx, `SELECT DISTINCT lower(a->>'name') FROM catalog.feeds f, jsonb_array_elements(f.apps) a
		WHERE f.version = (SELECT max(version) FROM catalog.feeds) AND length(a->>'name') >= 4`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func matchesCatalog(app string, names []string) bool {
	app = strings.ToLower(app)
	for _, n := range names {
		// "ChatGPT / OpenAI API" → its parts; any part naming the app counts.
		for _, part := range strings.FieldsFunc(n, func(r rune) bool { return r == '/' || r == '(' || r == ')' || r == ',' }) {
			part = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(part), " api"))
			if len(part) >= 4 && strings.Contains(app, part) {
				return true
			}
		}
	}
	return false
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
