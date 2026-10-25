package objstore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/notification"

	"wantimpres26/internal/connector"
	"wantimpres26/internal/connector/connectortest"
)

const token = "event-token"

func db(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("AUDIT_TEST_DATABASE_URL")
	if dbURL == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("AUDIT_TEST_DATABASE_URL must be set in CI")
		}
		t.Skip("no test Postgres")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("objstore_test_%d", time.Now().UnixNano()%1e9)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)"); admin.Close() })
	u, _ := neturl.Parse(dbURL)
	u.Path = "/" + name
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := Open(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

// receiver starts a Receiver and returns a func posting a raw body for a source.
func receiver(t *testing.T, pool *pgxpool.Pool) func(source string, body any) *http.Response {
	sum := sha256.Sum256([]byte(token))
	rc := &Receiver{DB: pool, TokenSHA256: sum[:], Formats: map[string]string{"minio": "s3", "gcs": "gcs", "azure": "azure"}, Now: time.Now}
	mux := http.NewServeMux()
	rc.Routes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return func(source string, body any) *http.Response {
		b, _ := json.Marshal(body)
		resp, err := http.Post(srv.URL+"/events/"+source+"?token="+token, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 {
			t.Fatalf("receiver: %d", resp.StatusCode)
		}
		return resp
	}
}

func minioClient(t *testing.T) *minio.Client {
	t.Helper()
	ep := os.Getenv("AUDIT_TEST_S3_ENDPOINT")
	if ep == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("AUDIT_TEST_S3_ENDPOINT must be set in CI")
		}
		t.Skip("no test MinIO")
	}
	c, err := minio.New(ep, &minio.Options{Creds: credentials.NewStaticV4(os.Getenv("AUDIT_TEST_S3_ACCESS_KEY"), os.Getenv("AUDIT_TEST_S3_SECRET_KEY"), "")})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func bucket(t *testing.T, c *minio.Client) string {
	t.Helper()
	name := fmt.Sprintf("objstore-%d", time.Now().UnixNano()%1e9)
	if err := c.MakeBucket(context.Background(), name, minio.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	return name
}

// AC (ticket 32): S3-compatible connector (MinIO) against the SDK contract, its feed fed by S3 event records.
func TestS3Contract(t *testing.T) {
	pool := db(t)
	mc := minioClient(t)
	b := bucket(t, mc)
	post := receiver(t, pool)
	ctx := context.Background()
	record := func(name, key string, size int64, etag string) map[string]any {
		return map[string]any{"Records": []any{map[string]any{"eventName": "s3:" + name, "eventTime": time.Now().UTC().Format(time.RFC3339Nano),
			"s3": map[string]any{"bucket": map[string]any{"name": b}, "object": map[string]any{"key": neturl.QueryEscape(key), "size": size, "eTag": etag}}}}}
	}
	connectortest.Run(t, connectortest.Harness{
		Conn: &Store{Source: "minio", DB: pool, Backend: NewS3(mc, "s3"), Buckets: []string{b}}, Container: b,
		Put: func(t *testing.T, name string, data []byte) string {
			key := "laporan q3/" + name // a space: event keys arrive URL-encoded
			info, err := mc.PutObject(ctx, b, key, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			post("minio", record("ObjectCreated:Put", key, info.Size, info.ETag))
			return key
		},
		Delete: func(t *testing.T, key string) {
			if err := mc.RemoveObject(ctx, b, key, minio.RemoveObjectOptions{}); err != nil {
				t.Fatal(err)
			}
			post("minio", record("ObjectRemoved:Delete", key, 0, ""))
		},
		Share: func(t *testing.T, _ string) {
			pol := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::%s/*"]}]}`, b)
			if err := mc.SetBucketPolicy(ctx, b, pol); err != nil {
				t.Fatal(err)
			}
		},
	})
}

// GCS: the same S3-compatible backend (GCS XML API) with Cloud Storage notifications through Pub/Sub. The event's
// md5Hash must land as the same content tag the listing reports, or every object would be re-read.
func TestGCSContract(t *testing.T) {
	pool := db(t)
	mc := minioClient(t)
	b := bucket(t, mc)
	post := receiver(t, pool)
	ctx := context.Background()
	notify := func(eventType, key string, data []byte, extra map[string]string) {
		attrs := map[string]string{"bucketId": b, "objectId": key, "eventType": eventType}
		for k, v := range extra {
			attrs[k] = v
		}
		obj := map[string]any{"name": key, "bucket": b, "size": fmt.Sprint(len(data)), "updated": time.Now().UTC().Format(time.RFC3339Nano)}
		if data != nil {
			sum := md5.Sum(data)
			obj["md5Hash"] = base64.StdEncoding.EncodeToString(sum[:])
		}
		raw, _ := json.Marshal(obj)
		post("gcs", map[string]any{"message": map[string]any{"attributes": attrs, "data": base64.StdEncoding.EncodeToString(raw), "messageId": "1"}, "subscription": "projects/p/subscriptions/s"})
	}
	store := &Store{Source: "gcs", DB: pool, Backend: NewS3(mc, "gcs"), Buckets: []string{b}}
	connectortest.Run(t, connectortest.Harness{
		Conn: store, Container: b,
		Put: func(t *testing.T, name string, data []byte) string {
			if _, err := mc.PutObject(ctx, b, name, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{}); err != nil {
				t.Fatal(err)
			}
			notify("OBJECT_FINALIZE", name, data, nil)
			// An overwrite also deletes the old generation: that DELETE must not read as a deletion.
			notify("OBJECT_DELETE", name, nil, map[string]string{"overwrittenByGeneration": "2"})
			return name
		},
		Delete: func(t *testing.T, key string) {
			if err := mc.RemoveObject(ctx, b, key, minio.RemoveObjectOptions{}); err != nil {
				t.Fatal(err)
			}
			notify("OBJECT_DELETE", key, nil, nil)
		},
	})
	// Tags agree between the listing and the events.
	p, _ := store.Items(ctx, connector.Container{ID: b}, "")
	listed := map[string]string{}
	for _, it := range p.Items {
		listed[it.ID] = it.ContentTag
	}
	rows, _ := pool.Query(ctx, "SELECT key, etag FROM data.object_events WHERE source = 'gcs' AND NOT deleted ORDER BY id")
	latest := map[string]string{}
	for rows.Next() {
		var k, e string
		_ = rows.Scan(&k, &e)
		latest[k] = e
	}
	n := 0
	for k, e := range latest {
		if tag, ok := listed[k]; ok {
			n++
			if tag != e {
				t.Errorf("%s: listing tag %s, event tag %s", k, tag, e)
			}
		}
	}
	if n == 0 {
		t.Error("no object to compare tags on")
	}
}

// --- Azure Blob against Azurite, with a real account SAS ---

const azuriteKey = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==" // Azurite's published dev key

func accountSAS(perms string) string {
	expiry := time.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05Z")
	const version = "2021-06-08"
	toSign := strings.Join([]string{"devstoreaccount1", perms, "b", "sco", "", expiry, "", "", version, "", ""}, "\n")
	key, _ := base64.StdEncoding.DecodeString(azuriteKey)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(toSign))
	q := neturl.Values{"sv": {version}, "ss": {"b"}, "srt": {"sco"}, "sp": {perms}, "se": {expiry}, "sig": {base64.StdEncoding.EncodeToString(m.Sum(nil))}}
	return q.Encode()
}

// sharedKey signs a body-less Blob request as the Azurite account owner (Shared Key, path-style URL).
func sharedKey(req *http.Request) {
	var hs []string
	for k, v := range req.Header {
		if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-ms-") {
			hs = append(hs, lk+":"+v[0])
		}
	}
	sort.Strings(hs)
	res := "/devstoreaccount1" + req.URL.Path
	q := req.URL.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res += "\n" + strings.ToLower(k) + ":" + q.Get(k)
	}
	toSign := req.Method + strings.Repeat("\n", 12) + strings.Join(hs, "\n") + "\n" + res
	key, _ := base64.StdEncoding.DecodeString(azuriteKey)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(toSign))
	req.Header.Set("Authorization", "SharedKey devstoreaccount1:"+base64.StdEncoding.EncodeToString(m.Sum(nil)))
}

func TestAzureContract(t *testing.T) {
	ep := os.Getenv("OBJSTORE_TEST_AZURITE")
	if ep == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("OBJSTORE_TEST_AZURITE must be set in CI")
		}
		t.Skip("no Azurite")
	}
	pool := db(t)
	post := receiver(t, pool)
	admin := accountSAS("rwdlac")
	do := func(method, path string, header map[string]string, body []byte) *http.Response {
		req, _ := http.NewRequest(method, ep+path+"?"+admin, bytes.NewReader(body))
		req.Header.Set("x-ms-version", "2021-06-08")
		for k, v := range header {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 {
			t.Fatalf("%s %s: %d", method, path, resp.StatusCode)
		}
		return resp
	}
	container := fmt.Sprintf("objstore-%d", time.Now().UnixNano()%1e9)
	req, _ := http.NewRequest(http.MethodPut, ep+"/"+container+"?restype=container&"+admin, nil)
	req.Header.Set("x-ms-version", "2021-06-08")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("create container: %v %v", resp, err)
	}
	event := func(typ, name string, etag string, size int) {
		post("azure", []any{map[string]any{"id": "e1", "eventType": typ, "subject": "/blobServices/default/containers/" + container + "/blobs/" + name,
			"eventTime": time.Now().UTC().Format(time.RFC3339Nano), "data": map[string]any{"eTag": etag, "contentLength": size}}})
	}
	// The connector reads with a list+read SAS only.
	az := &Azure{Endpoint: ep, SAS: accountSAS("rl"), HTTP: http.DefaultClient}
	connectortest.Run(t, connectortest.Harness{
		Conn: &Store{Source: "azure", DB: pool, Backend: az, Buckets: []string{container}}, Container: container,
		Put: func(t *testing.T, name string, data []byte) string {
			resp := do(http.MethodPut, "/"+container+"/docs/"+name, map[string]string{"x-ms-blob-type": "BlockBlob"}, data)
			event("Microsoft.Storage.BlobCreated", "docs/"+name, resp.Header.Get("ETag"), len(data))
			return "docs/" + name
		},
		Delete: func(t *testing.T, key string) {
			do(http.MethodDelete, "/"+container+"/"+key, nil, nil)
			event("Microsoft.Storage.BlobDeleted", key, "", 0)
		},
		Share: func(t *testing.T, _ string) {
			// Public access is the account owner's call (Shared Key), as on Azure: a SAS cannot change it.
			req, _ := http.NewRequest(http.MethodPut, ep+"/"+container+"?restype=container&comp=acl", nil)
			req.Header.Set("x-ms-version", "2021-06-08")
			req.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))
			req.Header.Set("x-ms-blob-public-access", "blob")
			sharedKey(req)
			if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode >= 300 {
				t.Fatalf("set public access: %v %v", resp, err)
			}
		},
	})
}

// Receiver: formats, handshakes, auth.
func TestReceiver(t *testing.T) {
	now := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	evs, err := parseS3([]byte(`{"EventName":"s3:ObjectCreated:Put","Key":"b/a%20b+c.txt","Records":[{"eventName":"s3:ObjectCreated:Put","eventTime":"2026-10-04T08:00:00.000Z",
		"s3":{"bucket":{"name":"b"},"object":{"key":"laporan+q3%2Fa%20b.txt","size":5,"eTag":"\"ABC\""}}},{"eventName":"s3:ObjectAccessed:Get","s3":{"bucket":{"name":"b"},"object":{"key":"x"}}}]}`), now)
	if err != nil || len(evs) != 1 || evs[0].key != "laporan q3/a b.txt" || evs[0].etag != "abc" || evs[0].at.Hour() != 8 {
		t.Errorf("s3: %+v %v", evs, err)
	}
	evs, _, err = parseAzure([]byte(`[{"eventType":"Microsoft.Storage.BlobDeleted","subject":"/blobServices/default/containers/c/blobs/a/b.txt","data":{}}]`), now)
	if err != nil || len(evs) != 1 || !evs[0].deleted || evs[0].bucket != "c" || evs[0].key != "a/b.txt" {
		t.Errorf("azure: %+v %v", evs, err)
	}
	_, code, _ := parseAzure([]byte(`[{"eventType":"Microsoft.EventGrid.SubscriptionValidationEvent","data":{"validationCode":"V123"}}]`), now)
	if code != "V123" {
		t.Errorf("validation code %q", code)
	}
	sum := md5.Sum([]byte("isi"))
	data, _ := json.Marshal(map[string]string{"md5Hash": base64.StdEncoding.EncodeToString(sum[:]), "size": "3"})
	evs, err = parseGCS([]byte(fmt.Sprintf(`{"message":{"attributes":{"bucketId":"b","objectId":"o","eventType":"OBJECT_FINALIZE"},"data":%q}}`, base64.StdEncoding.EncodeToString(data))), now)
	if err != nil || len(evs) != 1 || evs[0].etag != hex.EncodeToString(sum[:]) || evs[0].size != 3 {
		t.Errorf("gcs: %+v %v", evs, err)
	}

	// Auth and routing, end to end over HTTP with the Event Grid handshake.
	pool := db(t)
	sumTok := sha256.Sum256([]byte(token))
	rc := &Receiver{DB: pool, TokenSHA256: sumTok[:], Formats: map[string]string{"azure": "azure"}, Now: time.Now}
	mux := http.NewServeMux()
	rc.Routes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	for _, c := range []struct {
		url  string
		auth string
		want int
	}{
		{"/events/azure", "", 401},
		{"/events/azure?token=wrong", "", 401},
		{"/events/unknown?token=" + token, "", 404},
		{"/events/azure", "Bearer " + token, 200},
	} {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+c.url, strings.NewReader(`[{"eventType":"Microsoft.EventGrid.SubscriptionValidationEvent","data":{"validationCode":"V9"}}]`))
		if c.auth != "" {
			req.Header.Set("Authorization", c.auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&out)
		_ = resp.Body.Close()
		if resp.StatusCode != c.want || (c.want == 200 && out["validationResponse"] != "V9") {
			t.Errorf("%s: %d %v", c.url, resp.StatusCode, out)
		}
	}
}

func TestPolicyPublic(t *testing.T) {
	for pol, want := range map[string]bool{
		`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}`:                             true,
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:ListBucket","s3:*"]}]}`:         true,
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::1:root"]},"Action":"s3:GetObject"}]}`: false,
		`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject"}]}`:                              false,
		`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:PutObject"}]}`:                             false,
		``: false,
	} {
		if got := policyPublic(pol); got != want {
			t.Errorf("%s: %v", pol, got)
		}
	}
}

// Real MinIO notifications (local run only: MinIO must be started with a webhook target pointing at this test,
// see the ticket's verification notes). Checks the parser against MinIO's actual payload: URL-encoded keys,
// ETag form, removals.
func TestMinIOWebhook(t *testing.T) {
	listen := os.Getenv("OBJSTORE_TEST_WEBHOOK_LISTEN")
	if listen == "" {
		t.Skip("set OBJSTORE_TEST_WEBHOOK_LISTEN and point MinIO's webhook target PRIMARY at it")
	}
	pool := db(t)
	mc := minioClient(t)
	b := bucket(t, mc)
	sum := sha256.Sum256([]byte(token))
	rc := &Receiver{DB: pool, TokenSHA256: sum[:], Formats: map[string]string{"minio": "s3"}, Now: time.Now}
	mux := http.NewServeMux()
	rc.Routes(mux)
	srv := &http.Server{Addr: listen, Handler: mux}
	go func() { _ = srv.ListenAndServe() }()
	defer func() { _ = srv.Close() }()
	ctx := context.Background()
	cfg := notification.NewConfig(notification.NewArn("minio", "sqs", "", "PRIMARY", "webhook"))
	cfg.AddEvents(notification.ObjectCreatedAll, notification.ObjectRemovedAll)
	nc := notification.Configuration{}
	nc.AddQueue(cfg)
	if err := mc.SetBucketNotification(ctx, b, nc); err != nil {
		t.Fatal(err)
	}
	key := "laporan q3/a b+c.txt"
	info, err := mc.PutObject(ctx, b, key, strings.NewReader("isi berkas"), 10, minio.PutObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = mc.RemoveObject(ctx, b, key, minio.RemoveObjectOptions{})
	type row struct {
		key, etag string
		deleted   bool
	}
	var rows []row
	for deadline := time.Now().Add(15 * time.Second); len(rows) < 2 && time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		rows = rows[:0]
		rs, _ := pool.Query(ctx, "SELECT key, etag, deleted FROM data.object_events WHERE bucket = $1 ORDER BY id", b)
		for rs.Next() {
			var r row
			_ = rs.Scan(&r.key, &r.etag, &r.deleted)
			rows = append(rows, r)
		}
	}
	if len(rows) != 2 || rows[0] != (row{key, normETag(info.ETag), false}) || rows[1].key != key || !rows[1].deleted {
		t.Fatalf("MinIO delivered %+v (want key %q etag %s, then its removal)", rows, key, normETag(info.ETag))
	}
}

// Ticket 33: quarantine moves the object to the quarantine bucket; undo moves it back.
func TestS3Quarantine(t *testing.T) {
	pool := db(t)
	mc := minioClient(t)
	b, q := bucket(t, mc), bucket(t, mc)
	ctx := context.Background()
	if _, err := mc.PutObject(ctx, b, "hr/gaji.csv", strings.NewReader("nik,gaji"), 8, minio.PutObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	be := NewS3(mc, "s3")
	st := &Store{Source: "minio", DB: pool, Backend: be, QuarantineBucket: q}
	it := connector.Item{ID: "hr/gaji.csv", ContainerID: b}
	if _, err := st.Remediate(ctx, it, connector.Action{Kind: connector.Quarantine}, false); err == nil {
		t.Fatal("moved without remediation credentials")
	}
	be.Writer = mc
	exists := func(bucket, key string) bool {
		_, err := mc.StatObject(ctx, bucket, key, minio.StatObjectOptions{})
		return err == nil
	}
	plan, err := st.Remediate(ctx, it, connector.Action{Kind: connector.Quarantine}, true)
	if err != nil || len(plan.Steps) != 1 || !exists(b, "hr/gaji.csv") || exists(q, b+"/hr/gaji.csv") {
		t.Fatalf("dry run: %+v %v", plan, err)
	}
	done, err := st.Remediate(ctx, it, connector.Action{Kind: connector.Quarantine}, false)
	if err != nil || exists(b, "hr/gaji.csv") || !exists(q, b+"/hr/gaji.csv") {
		t.Fatalf("execute: %+v %v", done, err)
	}
	if _, err := st.Undo(ctx, it, done.Undo, false); err != nil || !exists(b, "hr/gaji.csv") || exists(q, b+"/hr/gaji.csv") {
		t.Errorf("undo: %v", err)
	}
	if _, err := st.Remediate(ctx, it, connector.Action{Kind: connector.RevokeAnyoneLinks}, true); !errors.Is(err, connector.ErrNotSupported) {
		t.Errorf("revoke on object storage: %v", err)
	}
}
