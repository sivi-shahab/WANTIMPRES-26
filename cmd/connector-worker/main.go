package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"wantimpres26/internal/connector"
	"wantimpres26/internal/connector/compliance"
	"wantimpres26/internal/connector/gdrive"
	"wantimpres26/internal/connector/m365"
	"wantimpres26/internal/connector/objstore"
	"wantimpres26/internal/datascan"
	"wantimpres26/internal/extract"
	"wantimpres26/internal/privacy"
	"wantimpres26/internal/remediate"
	"wantimpres26/internal/server"
	"wantimpres26/internal/similarity"
	"wantimpres26/internal/tenantdb"
)

// Env (each source is on when its variables are set; at least one):
//
//	common   DATABASE_URL, TENANT_PEPPER, TIKA_URL (optional), SCAN_INTERVAL (default 1h), LABELS (JSON: external
//	         label id → public|internal|confidential|restricted)
//	m365     M365_TENANT_ID, M365_CLIENT_ID, M365_CLIENT_SECRET, M365_DOMAINS
//	gdrive   GDRIVE_KEY_FILE (service account JSON, domain-wide delegation), GDRIVE_ADMIN, GDRIVE_DOMAINS; also runs
//	         the OAuth grant audit (AI apps → shadow-agent review queue)
//	s3       S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY, S3_INSECURE=true for plain HTTP, S3_BUCKETS (optional)
//	gcs      GCS_HMAC_ACCESS, GCS_HMAC_SECRET, GCS_BUCKETS (optional) — the S3-interoperable XML API
//	azure    AZURE_BLOB_ENDPOINT, AZURE_BLOB_SAS (list+read account SAS), AZURE_CONTAINERS (optional)
//	claude   CLAUDE_COMPLIANCE_KEY (Compliance Access Key, read:compliance_user_data)
//	chatgpt  CHATGPT_COMPLIANCE_KEY, CHATGPT_WORKSPACE
//	events   EVENTS_TOKEN_SHA256 (hex): bucket notifications at POST /events/{s3|gcs|azure}
//
// Remediation (ticket 33) runs only for sources given write credentials, separate from the scanning ones:
// M365_REMEDIATE_CLIENT_ID + M365_REMEDIATE_CLIENT_SECRET, GDRIVE_REMEDIATE=true (delegation also grants the
// drive scope), S3_REMEDIATE_ACCESS_KEY + S3_REMEDIATE_SECRET_KEY + S3_QUARANTINE_BUCKET. TENANT_ID (audit log).
func main() {
	log := privacy.NewLogger("connector-worker")
	fail := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(1)
	}
	env := os.Getenv
	list := func(k string) []string {
		var out []string
		for _, v := range strings.Split(env(k), ",") {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	for _, k := range []string{"DATABASE_URL", "TENANT_PEPPER", "TENANT_ID"} {
		if env(k) == "" {
			fail("config", errors.New(k+" is required"))
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	db, err := tenantdb.Pool(ctx, env("DATABASE_URL"), env("TENANT_ID"))
	if err != nil {
		fail("database", err)
	}
	if err := remediate.Open(ctx, db); err != nil { // includes the data scan schema
		fail("data schema", err)
	}
	if err := objstore.Open(ctx, db); err != nil {
		fail("object event schema", err)
	}
	labels := map[string]string{}
	if v := env("LABELS"); v != "" {
		if err := json.Unmarshal([]byte(v), &labels); err != nil {
			fail("LABELS", err)
		}
	}
	interval := time.Hour
	if v := env("SCAN_INTERVAL"); v != "" {
		if interval, err = time.ParseDuration(v); err != nil || interval <= 0 {
			fail("SCAN_INTERVAL", errors.New("positive Go duration"))
		}
	}
	var tika *extract.Tika
	if u := env("TIKA_URL"); u != "" {
		tika = &extract.Tika{URL: u, HTTP: &http.Client{Timeout: 2 * time.Minute}}
	}
	pepper := []byte(env("TENANT_PEPPER"))
	if err := similarity.Open(ctx, db); err != nil {
		fail("similarity schema", err)
	}
	similar, err := similarity.Watch(ctx, db, env("TENANT_ID"), pepper, time.Minute, log)
	if err != nil {
		fail("similarity index", err)
	}
	var scanners []*datascan.Scanner
	bySource := map[string]*datascan.Scanner{}
	add := func(source string, c connector.Connector) {
		s := &datascan.Scanner{DB: db, Source: source, Conn: c, Pepper: pepper, Similar: similar, Labels: labels, Tika: tika, Log: log}
		s.Defaults()
		scanners = append(scanners, s)
		bySource[source] = s
	}
	var audits []*datascan.OAuthAudit

	if env("M365_TENANT_ID") != "" {
		g := m365.New(env("M365_TENANT_ID"), env("M365_CLIENT_ID"), env("M365_CLIENT_SECRET"), list("M365_DOMAINS"))
		if id := env("M365_REMEDIATE_CLIENT_ID"); id != "" {
			g.Writer(env("M365_TENANT_ID"), id, env("M365_REMEDIATE_CLIENT_SECRET"))
		}
		add("m365", g)
	}
	if f := env("GDRIVE_KEY_FILE"); f != "" {
		key, err := os.ReadFile(f)
		if err != nil {
			fail("GDRIVE_KEY_FILE", err)
		}
		d, err := gdrive.New(key, env("GDRIVE_ADMIN"), list("GDRIVE_DOMAINS"), env("GDRIVE_REMEDIATE") == "true")
		if err != nil {
			fail("google drive", err)
		}
		add("gdrive", d)
		audits = append(audits, &datascan.OAuthAudit{DB: db, Source: "gworkspace", Fetch: d.OAuthGrants, Pepper: pepper, Now: time.Now})
	}
	formats := map[string]string{}
	addS3 := func(source, kind, endpoint, access, secret string, secure bool, buckets []string) {
		c, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(access, secret, ""), Secure: secure})
		if err != nil {
			fail(source, err)
		}
		be := objstore.NewS3(c, kind)
		st := &objstore.Store{Source: source, DB: db, Backend: be, Buckets: buckets, PolicyCache: time.Minute}
		if source == "s3" && env("S3_REMEDIATE_ACCESS_KEY") != "" {
			if be.Writer, err = minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(env("S3_REMEDIATE_ACCESS_KEY"), env("S3_REMEDIATE_SECRET_KEY"), ""), Secure: secure}); err != nil {
				fail(source+" remediation", err)
			}
			st.QuarantineBucket = env("S3_QUARANTINE_BUCKET")
		}
		add(source, st)
		formats[source] = kind
	}
	if ep := env("S3_ENDPOINT"); ep != "" {
		addS3("s3", "s3", ep, env("S3_ACCESS_KEY"), env("S3_SECRET_KEY"), env("S3_INSECURE") != "true", list("S3_BUCKETS"))
	}
	if env("GCS_HMAC_ACCESS") != "" {
		addS3("gcs", "gcs", "storage.googleapis.com", env("GCS_HMAC_ACCESS"), env("GCS_HMAC_SECRET"), true, list("GCS_BUCKETS"))
	}
	if ep := env("AZURE_BLOB_ENDPOINT"); ep != "" {
		add("azure", &objstore.Store{Source: "azure", DB: db, Backend: &objstore.Azure{Endpoint: ep, SAS: env("AZURE_BLOB_SAS"),
			HTTP: &http.Client{Timeout: 5 * time.Minute}}, Buckets: list("AZURE_CONTAINERS"), PolicyCache: time.Minute})
		formats["azure"] = "azure"
	}
	if k := env("CLAUDE_COMPLIANCE_KEY"); k != "" {
		add("claude", &compliance.Claude{BaseURL: "https://api.anthropic.com", Key: k, HTTP: &http.Client{Timeout: 5 * time.Minute}, Backoff: connector.DefaultBackoff})
	}
	if k := env("CHATGPT_COMPLIANCE_KEY"); k != "" {
		add("chatgpt", &compliance.ChatGPT{BaseURL: "https://api.chatgpt.com", Key: k, Workspace: env("CHATGPT_WORKSPACE"),
			HTTP: &http.Client{Timeout: 5 * time.Minute}, Backoff: connector.DefaultBackoff})
	}
	if len(scanners) == 0 {
		fail("config", errors.New("no data source configured"))
	}

	mux := http.NewServeMux()
	if len(formats) > 0 {
		sum, err := hex.DecodeString(env("EVENTS_TOKEN_SHA256"))
		if err != nil || len(sum) != 32 {
			fail("EVENTS_TOKEN_SHA256 must be a hex SHA-256 (object storage sources need event notifications)", err)
		}
		(&objstore.Receiver{DB: db, TokenSHA256: sum, Formats: formats, Now: time.Now}).Routes(mux)
	}
	// Remediation: plan new requests and execute approved ones every 30 s, independent of the scan interval.
	ex := &remediate.Executor{DB: db, Tenant: env("TENANT_ID"), Scanners: bySource, Now: time.Now, Log: log}
	go func() {
		for t := time.NewTicker(30 * time.Second); ctx.Err() == nil; <-t.C {
			if n, err := ex.Run(ctx); err != nil {
				log.Error("remediation", "err", err)
			} else if n > 0 {
				log.Info("remediation", "handled", n)
			}
		}
	}()
	go func() {
		for t := time.NewTicker(interval); ctx.Err() == nil; <-t.C {
			for _, s := range scanners {
				run(ctx, log, s)
			}
			if len(formats) > 0 {
				if _, err := objstore.PurgeEvents(ctx, db, time.Now()); err != nil {
					log.Error("purge object events", "err", err)
				}
			}
			for _, a := range audits {
				if n, err := a.Run(ctx); err != nil {
					log.Error("oauth audit", "source", a.Source, "err", err)
				} else {
					log.Info("oauth audit", "source", a.Source, "ai_apps", n)
				}
			}
		}
	}()
	server.Run("connector-worker", mux)
	cancel()
	db.Close()
}

func run(ctx context.Context, log *slog.Logger, s *datascan.Scanner) {
	start := time.Now()
	st, err := s.Run(ctx)
	log.Info("scan pass", "source", s.Source, "containers", st.Containers, "items", st.Items, "content_read", st.ContentRead,
		"acl_read", st.ACLRead, "unchanged", st.Unchanged, "deleted", st.Deleted, "errors", st.Errors, "took", time.Since(start).String())
	if err != nil {
		log.Error("scan pass", "source", s.Source, "err", err)
	}
}
