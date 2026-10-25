package events

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// Ticket 41 AC: a production config cannot fall back to plaintext or to an anonymous client.
func TestKafkaOptsRefusesPlaintext(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "pw")
	_ = os.WriteFile(pw, []byte("secret\n"), 0o600)
	ca := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(ca, []byte("not a certificate"), 0o600)
	for name, env := range map[string]map[string]string{
		"no identity":   {"KAFKA_BROKERS": "k:9093"},
		"bad CA":        {"KAFKA_BROKERS": "k:9093", "KAFKA_CA_FILE": ca, "KAFKA_SASL_USER": "u", "KAFKA_SASL_PASSWORD_FILE": pw},
		"no password":   {"KAFKA_BROKERS": "k:9093", "KAFKA_SASL_USER": "u"},
		"bad mechanism": {"KAFKA_BROKERS": "k:9093", "KAFKA_SASL_USER": "u", "KAFKA_SASL_PASSWORD_FILE": pw, "KAFKA_SASL_MECHANISM": "GSSAPI"},
		"plaintext=1":   {"KAFKA_BROKERS": "k:9093", "KAFKA_PLAINTEXT": "1"}, // only the literal "true" opts out, and still no identity
	} {
		if _, err := KafkaOpts(envOf(env)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// TLS + SCRAM: three options (brokers, TLS dialer, SASL).
	opts, err := KafkaOpts(envOf(map[string]string{"KAFKA_BROKERS": "k:9093", "KAFKA_SASL_USER": "u", "KAFKA_SASL_PASSWORD_FILE": pw}))
	if err != nil || len(opts) != 3 {
		t.Errorf("tls+sasl: %d opts, %v", len(opts), err)
	}
	// The explicit local opt-out has no TLS dialer.
	opts, err = KafkaOpts(envOf(map[string]string{"KAFKA_BROKERS": "k:9092", "KAFKA_PLAINTEXT": "true"}))
	if err != nil || len(opts) != 1 {
		t.Errorf("plaintext opt-out: %d opts, %v", len(opts), err)
	}
}

// The TLS dialer checks the broker certificate against KAFKA_CA_FILE: the handshake completes with the right CA and
// fails with another one. (A TLS listener stands in for the broker; the Kafka protocol after the handshake is moot.)
func TestKafkaTLSVerifiesBroker(t *testing.T) {
	broker := httptest.NewUnstartedServer(nil) // only for its localhost certificate
	broker.StartTLS()
	broker.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: broker.TLS.Certificates})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	results := make(chan error, 64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				results <- c.(*tls.Conn).HandshakeContext(ctx)
				_ = c.Close()
			}()
		}
	}()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	foreign, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)

	dir := t.TempDir()
	pw := filepath.Join(dir, "pw")
	_ = os.WriteFile(pw, []byte("x"), 0o600)
	// try connects with ca as KAFKA_CA_FILE and reports whether a handshake succeeded.
	try := func(ca []byte) bool {
		t.Helper()
		f := filepath.Join(dir, "ca.pem")
		_ = os.WriteFile(f, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca}), 0o600)
		opts, err := KafkaOpts(envOf(map[string]string{"KAFKA_BROKERS": ln.Addr().String(), "KAFKA_CA_FILE": f,
			"KAFKA_SASL_USER": "u", "KAFKA_SASL_PASSWORD_FILE": pw, "KAFKA_SASL_MECHANISM": "PLAIN"}))
		if err != nil {
			t.Fatal(err)
		}
		kc, err := kgo.NewClient(opts...)
		if err != nil {
			t.Fatal(err)
		}
		defer kc.Close()
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = kc.Ping(ctx)
		}()
		select {
		case err := <-results:
			return err == nil
		case <-time.After(15 * time.Second):
			t.Fatal("client never connected")
		}
		return false
	}
	if !try(broker.Certificate().Raw) {
		t.Error("TLS handshake failed with the broker's CA")
	}
	for len(results) > 0 { // retries of the first client
		<-results
	}
	if try(foreign) {
		t.Error("TLS handshake succeeded with a foreign CA")
	}
}

// Ticket 41 AC: against a real broker with an authorizer, a client without credentials or with a wrong password
// is refused, and an authenticated service that is not a PEP cannot produce decision events.
// IT_KAFKA_SASL_BROKERS is a SASL_PLAINTEXT listener; IT_KAFKA_ADMIN_PASSWORD the super user "admin" (PLAIN).
func TestBrokerACLs(t *testing.T) {
	brokers, adminPW := os.Getenv("IT_KAFKA_SASL_BROKERS"), os.Getenv("IT_KAFKA_ADMIN_PASSWORD")
	if brokers == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("IT_KAFKA_SASL_BROKERS must be set in CI")
		}
		t.Skip("no SASL broker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dir := t.TempDir()
	client := func(user, pass, mech string) *kgo.Client {
		t.Helper()
		env := map[string]string{"KAFKA_BROKERS": brokers, "KAFKA_PLAINTEXT": "true", "KAFKA_SASL_USER": user, "KAFKA_SASL_MECHANISM": mech}
		if user != "" {
			f := filepath.Join(dir, user)
			_ = os.WriteFile(f, []byte(pass), 0o600)
			env["KAFKA_SASL_PASSWORD_FILE"] = f
		}
		opts, err := KafkaOpts(envOf(env))
		if err != nil {
			t.Fatal(err)
		}
		kc, err := kgo.NewClient(append(opts, kgo.RequestRetries(2), kgo.ProduceRequestTimeout(5*time.Second))...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(kc.Close)
		return kc
	}
	admin := client("admin", adminPW, "PLAIN")
	adm := kadm.NewClient(admin)
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	topic, suffix := "wantimpres26.acl-test."+hex.EncodeToString(b), hex.EncodeToString(b)
	if _, err := adm.CreateTopic(ctx, 1, 1, nil, topic); err != nil {
		t.Fatal(err)
	}
	// Service accounts as the bank would create them: SCRAM-SHA-512.
	pep, intruder := "ai-gateway-"+suffix, "siem-export-"+suffix
	res, err := adm.AlterUserSCRAMs(ctx, nil, []kadm.UpsertSCRAM{
		{User: pep, Mechanism: kadm.ScramSha512, Iterations: 8192, Password: "pep-pw"},
		{User: intruder, Mechanism: kadm.ScramSha512, Iterations: 8192, Password: "siem-pw"},
	})
	if err != nil || res.Error() != nil {
		t.Fatalf("scram users: %v %v", err, res.Error())
	}
	if err := ApplyACLs(ctx, admin, []Grant{
		{Principal: "User:" + pep, Produce: []string{topic}},
		{Principal: "User:" + intruder, Consume: []string{topic}, Groups: []string{"g-" + suffix}},
	}); err != nil {
		t.Fatal(err)
	}
	// Applying again is a no-op, not an error.
	if err := ApplyACLs(ctx, admin, []Grant{{Principal: "User:" + pep, Produce: []string{topic}}}); err != nil {
		t.Errorf("re-apply: %v", err)
	}
	produce := func(kc *kgo.Client) error {
		pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		return kc.ProduceSync(pctx, &kgo.Record{Topic: topic, Value: []byte("{}")}).FirstErr()
	}

	// The PEP may (SCRAM credentials and ACLs propagate asynchronously: retry briefly).
	var perr error
	for range 20 {
		if perr = produce(client(pep, "pep-pw", "")); perr == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if perr != nil {
		t.Fatalf("PEP produce: %v", perr)
	}
	// Without topic WRITE the idempotent producer is already refused at InitProducerID (cluster) or at the topic.
	if err := produce(client(intruder, "siem-pw", "")); !errors.Is(err, kerr.TopicAuthorizationFailed) && !errors.Is(err, kerr.ClusterAuthorizationFailed) {
		t.Errorf("non-PEP produce: %v, want an authorization failure", err)
	}
	// A failed SASL handshake is retried by the client until the deadline; either way nothing is written.
	if err := produce(client(pep, "wrong", "")); err == nil {
		t.Error("wrong password produced")
	}
	if err := produce(client("", "", "")); err == nil {
		t.Error("client without credentials produced to the SASL listener")
	}
	// The topic holds the PEP's record only.
	cons := client("admin", adminPW, "PLAIN")
	cons.AddConsumeTopics(topic)
	n := 0
	pctx, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	for pctx.Err() == nil {
		n += cons.PollFetches(pctx).NumRecords()
	}
	if n != 1 {
		t.Errorf("topic has %d records, want only the PEP's 1", n)
	}
}
