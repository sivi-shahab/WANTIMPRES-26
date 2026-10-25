// Command nfr is the ticket 21 NFR harness: a mock LLM provider, a static file server for the OPA bundle, a signed
// bundle builder, a load generator and file-scan timing. Run from the repo root: deploy/nfr/run.sh nfr <command>.
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wantimpres26/internal/detect"
	"wantimpres26/internal/extract"
	"wantimpres26/internal/policysvc"
	"wantimpres26/policy"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: nfr mock|files|bundle|load|events [flags]")
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{"mock": mock, "files": files, "bundle": buildBundle, "load": load, "events": eventLatency, "filescan": fileScan}
	f, ok := cmds[os.Args[1]]
	if !ok {
		fmt.Fprintln(os.Stderr, "unknown command", os.Args[1])
		os.Exit(2)
	}
	if err := f(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "nfr:", err)
		os.Exit(1)
	}
}

// mock is an OpenAI-compatible provider answering at once (or streaming -chunks SSE chunks -gap apart), so what
// the load generator measures through the gateway minus straight to the mock is the gateway's own cost.
func mock(args []string) error {
	fs := flag.NewFlagSet("mock", flag.ExitOnError)
	addr := fs.String("addr", ":9000", "listen address")
	chunks := fs.Int("chunks", 20, "SSE chunks per streamed answer")
	gap := fs.Duration("gap", 5*time.Millisecond, "time between streamed chunks")
	_ = fs.Parse(args)
	answer := "Berikut ringkasan kebijakan cuti tahunan karyawan sesuai peraturan perusahaan yang berlaku. "
	http.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Stream bool `json:"stream"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if !req.Stream {
			w.Header().Set("Content-Type", "application/json")
			// nosemgrep: no-fprintf-to-responsewriter -- mock provider JSON, not HTML
			_, _ = fmt.Fprintf(w, `{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120}}`, answer)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		for i := range *chunks {
			// nosemgrep: no-fprintf-to-responsewriter -- mock provider SSE, not HTML
			_, _ = fmt.Fprintf(w, "data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":%q}}]}\n\n", fmt.Sprintf("bagian %d dari jawaban. ", i))
			if fl != nil {
				fl.Flush()
			}
			time.Sleep(*gap)
		}
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	})
	// nosemgrep: use-tls -- plain-HTTP mock provider for the NFR benchmark
	return http.ListenAndServe(*addr, nil)
}

func files(args []string) error {
	fs := flag.NewFlagSet("files", flag.ExitOnError)
	addr := fs.String("addr", ":8000", "listen address")
	dir := fs.String("dir", ".", "directory")
	_ = fs.Parse(args)
	// nosemgrep: use-tls -- plain-HTTP file server for the NFR benchmark
	return http.ListenAndServe(*addr, http.FileServer(http.Dir(*dir)))
}

// buildBundle signs the built-in policy (as on an empty database) with a fresh dev key into -out: wantimpres26.tar.gz and
// the public key for the sidecar's slot a.
func buildBundle(args []string) error {
	fs := flag.NewFlagSet("bundle", flag.ExitOnError)
	out := fs.String("out", "bundle", "output directory")
	_ = fs.Parse(args)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, _ := x509.MarshalECPrivateKey(k)
	signer, err := policysvc.FileSigner(policysvc.KeyIDs[0], pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	if err != nil {
		return err
	}
	tarball, rev, err := policysvc.Build(context.Background(), policy.Files, signer, nil)
	if err != nil {
		return err
	}
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "wantimpres26.tar.gz"), tarball, 0o644); err != nil {
		return err
	}
	fmt.Println("bundle revision", rev)
	return os.WriteFile(filepath.Join(*out, policysvc.KeyIDs[0]+".pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), 0o644)
}

// text is about n tokens (4 characters each) of ordinary Indonesian office prose: no detector fires.
func text(n int) string {
	const s = "Mohon bantu merangkum notulen rapat koordinasi proyek migrasi sistem pembayaran minggu ini secara singkat. "
	return strings.Repeat(s, max(1, n*4/len(s)))
}

type result struct {
	Label    string         `json:"label"`
	Requests int            `json:"requests"`
	Codes    map[string]int `json:"codes"`
	RPS      float64        `json:"achieved_rps"`
	P50, P95 float64        // ms
	P99, Max float64        // ms
	Minutes  []minute       `json:"minutes,omitempty"`
}

type minute struct {
	Minute   int     `json:"minute"`
	Requests int     `json:"requests"`
	Errors   int     `json:"errors"`
	P95      float64 `json:"p95_ms"`
}

func pct(d []float64, p float64) float64 {
	if len(d) == 0 {
		return 0
	}
	return d[min(len(d)-1, int(float64(len(d))*p))]
}

// load sends chat requests at -rps (open loop) or as fast as -c workers can (closed loop, -rps 0) for -d and prints
// a JSON result: status codes, achieved RPS, latency percentiles and, with -minutes, per-minute drift for a soak.
func load(args []string) error {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	url := fs.String("url", "http://localhost:8080/openai/v1/chat/completions", "endpoint")
	key := fs.String("key", "nfr-app-key", "bearer key")
	rps := fs.Float64("rps", 0, "open-loop rate; 0 = closed loop")
	conc := fs.Int("c", 32, "workers")
	dur := fs.Duration("d", 30*time.Second, "duration")
	tokens := fs.Int("tokens", 1000, "prompt size in tokens")
	stream := fs.Bool("stream", false, "stream the answer")
	label := fs.String("label", "", "label in the output")
	minutes := fs.Bool("minutes", false, "per-minute buckets (soak)")
	_ = fs.Parse(args)
	body, _ := json.Marshal(map[string]any{"model": "gpt-4o-mini", "stream": *stream, "messages": []map[string]string{{"role": "user", "content": text(*tokens)}}})
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: *conc * 2}}
	type sample struct {
		at   time.Duration
		ms   float64
		code string
	}
	var mu sync.Mutex
	var samples []sample
	start := time.Now()
	deadline := start.Add(*dur)
	one := func(i int64) {
		req, _ := http.NewRequest(http.MethodPost, *url, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+*key)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Wantimpres26-User", fmt.Sprintf("user-%d", i%500))
		t0 := time.Now()
		resp, err := client.Do(req)
		code := "error"
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			code = fmt.Sprint(resp.StatusCode)
		}
		ms := float64(time.Since(t0).Microseconds()) / 1000
		mu.Lock()
		samples = append(samples, sample{t0.Sub(start), ms, code})
		mu.Unlock()
	}
	var n atomic.Int64
	var wg sync.WaitGroup
	if *rps > 0 {
		tick := time.NewTicker(time.Duration(float64(time.Second) / *rps))
		sem := make(chan struct{}, *conc*8)
		for now := range tick.C {
			if now.After(deadline) {
				break
			}
			select {
			case sem <- struct{}{}:
				wg.Add(1)
				go func() { defer wg.Done(); one(n.Add(1)); <-sem }()
			default: // saturated: count as a client-side drop
				mu.Lock()
				samples = append(samples, sample{now.Sub(start), 0, "dropped"})
				mu.Unlock()
			}
		}
		tick.Stop()
	} else {
		for range *conc {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for time.Now().Before(deadline) {
					one(n.Add(1))
				}
			}()
		}
	}
	wg.Wait()
	r := result{Label: *label, Requests: len(samples), Codes: map[string]int{}}
	var ok []float64
	byMin := map[int]*struct {
		ms        []float64
		n, errors int
	}{}
	for _, s := range samples {
		r.Codes[s.code]++
		m := int(s.at / time.Minute)
		b := byMin[m]
		if b == nil {
			b = &struct {
				ms        []float64
				n, errors int
			}{}
			byMin[m] = b
		}
		b.n++
		if s.code == "200" {
			ok = append(ok, s.ms)
			b.ms = append(b.ms, s.ms)
		} else {
			b.errors++
		}
	}
	slices.Sort(ok)
	r.RPS = float64(len(ok)) / dur.Seconds()
	r.P50, r.P95, r.P99 = pct(ok, .50), pct(ok, .95), pct(ok, .99)
	if len(ok) > 0 {
		r.Max = ok[len(ok)-1]
	}
	if *minutes {
		for m := 0; byMin[m] != nil; m++ {
			slices.Sort(byMin[m].ms)
			r.Minutes = append(r.Minutes, minute{m, byMin[m].n, byMin[m].errors, pct(byMin[m].ms, .95)})
		}
	}
	return json.NewEncoder(os.Stdout).Encode(r)
}

// eventLatency sends -n requests one by one and, for each decision id, polls OpenSearch until the event is
// searchable: the "event to dashboard/SIEM" path (Kafka → event-ingest → OpenSearch, refresh included).
func eventLatency(args []string) error {
	fs := flag.NewFlagSet("events", flag.ExitOnError)
	url := fs.String("url", "http://localhost:8080/openai/v1/chat/completions", "gateway endpoint")
	key := fs.String("key", "nfr-app-key", "bearer key")
	osURL := fs.String("opensearch", "http://localhost:9200", "OpenSearch")
	n := fs.Int("n", 100, "events")
	gap := fs.Duration("gap", 200*time.Millisecond, "between requests")
	_ = fs.Parse(args)
	body, _ := json.Marshal(map[string]any{"model": "gpt-4o-mini", "messages": []map[string]string{{"role": "user", "content": text(200)}}})
	var mu sync.Mutex
	var lat []float64
	var wg sync.WaitGroup
	missing := atomic.Int64{}
	for i := range *n {
		req, _ := http.NewRequest(http.MethodPost, *url, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+*key)
		req.Header.Set("X-Wantimpres26-User", fmt.Sprintf("ev-%d", i))
		t0 := time.Now()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		id := resp.Header.Get("X-Wantimpres26-Decision-Id")
		wg.Add(1)
		go func() {
			defer wg.Done()
			q, _ := json.Marshal(map[string]any{"query": map[string]any{"ids": map[string]any{"values": []string{id}}}})
			for time.Since(t0) < 3*time.Minute {
				r, err := http.Post(*osURL+"/wantimpres26-events-*/_search?size=0", "application/json", bytes.NewReader(q))
				if err == nil {
					var out struct {
						Hits struct {
							Total struct {
								Value int `json:"value"`
							} `json:"total"`
						} `json:"hits"`
					}
					_ = json.NewDecoder(r.Body).Decode(&out)
					_ = r.Body.Close()
					if out.Hits.Total.Value > 0 {
						mu.Lock()
						lat = append(lat, time.Since(t0).Seconds())
						mu.Unlock()
						return
					}
				}
				time.Sleep(250 * time.Millisecond)
			}
			missing.Add(1)
		}()
		time.Sleep(*gap)
	}
	wg.Wait()
	slices.Sort(lat)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"events": *n, "found": len(lat), "missing": missing.Load(),
		"p50_s": pct(lat, .5), "p95_s": pct(lat, .95), "max_s": pct(lat, 1)})
}

// fileScan times the in-process file path (internal/extract with its default limits, then L1 detection) on a zip of
// CSV sheets with identity numbers: -mb of input, -n runs. Formats that go through Tika (PDF, legacy Office) are
// not covered: they add the Tika round trip.
func fileScan(args []string) error {
	fs := flag.NewFlagSet("filescan", flag.ExitOnError)
	mb := fs.Int("mb", 5, "input size in MB")
	n := fs.Int("n", 20, "runs")
	_ = fs.Parse(args)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; buf.Len() < *mb<<20; i++ {
		w, _ := zw.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("sheet-%04d.csv", i), Method: zip.Store})
		for r := range 2000 {
			_, _ = fmt.Fprintf(w, "%d,Nasabah %d,317101%06d0001,Jl. Sudirman No %d Jakarta,%d\n", r, r, (i*2000+r)%1000000, r%200, r*1000)
		}
	}
	_ = zw.Close()
	data := buf.Bytes()
	var ms []float64
	var findings int
	for range *n {
		t0 := time.Now()
		res, err := extract.Extract(context.Background(), data, "upload.zip", extract.Default, nil)
		if err != nil {
			return err
		}
		findings = len(detect.Scan(res.Text).Matches)
		ms = append(ms, float64(time.Since(t0).Milliseconds()))
	}
	slices.Sort(ms)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"input_mb": float64(len(data)) / (1 << 20), "runs": *n,
		"p50_ms": pct(ms, .5), "p95_ms": pct(ms, .95), "max_ms": ms[len(ms)-1], "l1_findings": findings})
}
