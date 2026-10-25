// Command evalcorpus manages the frozen detector eval sets (ticket 04, spec §9.3–9.4).
//
//	evalcorpus freeze -dir data/eval/v2 -seed 2  # generate synthetic files, hash everything, write MANIFEST.json
//	evalcorpus score  -dir data/eval/v1          # verify hashes, score detection L1, print Markdown
//	evalcorpus sheet  -dir data/eval/v1 > s.jsonl  # blind sheet for annotators: id + text, no labels
//	evalcorpus kappa  a.jsonl b.jsonl            # Cohen's κ per question; exit 1 below 0.8
//	evalcorpus train -seed 7 -n 3000 > t.jsonl    # L2 training data (train-only templates; tickets 09-10)
//	evalcorpus nergold -dir data/eval/v1 > g.jsonl # holdout PII with derived name/address gold (NER scoring)
//	evalcorpus l2eval -dir data/eval/v1 -url http://localhost:8080 -threshold 0.5  # score the served L2 model
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	"wantimpres26/internal/detect"
	"wantimpres26/internal/evalcorpus"
	"wantimpres26/internal/l2"
)

// MinKappa is the inter-annotator agreement the spec requires (§9.3).
const MinKappa = 0.8

// public lists the open-licensed sets a version may include; their files are fetched once and frozen with it.
var public = map[string]evalcorpus.File{
	"public-deepset-test.jsonl": {Kind: "mixed", Source: "https://huggingface.co/datasets/deepset/prompt-injections (split test)",
		License: "Apache-2.0", Upstream: "4f61ecb038e9c3fb77e21034b22511b523772cdd"},
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	dir := fs.String("dir", "data/eval/v1", "eval set directory")
	seed := fs.Uint64("seed", 1, "generator seed (freeze)")
	threshold := fs.Float64("threshold", 0.8, "injection score counted as flagged (score)")
	n := fs.Int("n", 3000, "generator rounds (train)")
	url := fs.String("url", "http://localhost:8080", "model-inference (l2eval)")
	_ = fs.Parse(os.Args[2:])
	var err error
	switch os.Args[1] {
	case "freeze":
		err = freeze(*dir, *seed)
	case "score":
		var ss []evalcorpus.Sample
		if _, ss, err = evalcorpus.Load(*dir); err == nil {
			err = evalcorpus.Score(ss, detect.Scan, *threshold).Markdown(os.Stdout)
		}
	case "sheet":
		var ss []evalcorpus.Sample
		if _, ss, err = evalcorpus.Load(*dir); err == nil {
			enc := json.NewEncoder(os.Stdout)
			for _, s := range ss {
				if err = enc.Encode(map[string]string{"id": s.ID, "text": s.Text}); err != nil {
					break
				}
			}
		}
	case "kappa":
		err = kappa(fs.Args())
	case "train":
		_, err = os.Stdout.Write(evalcorpus.Encode(evalcorpus.Training(*seed, *n)))
	case "nergold":
		err = nerGold(*dir)
	case "l2eval":
		err = l2Eval(*dir, *url, *threshold)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "evalcorpus:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: evalcorpus freeze|score|sheet|kappa|train|nergold [flags]")
	os.Exit(2)
}

func freeze(dir string, seed uint64) error {
	if _, err := os.Stat(filepath.Join(dir, "MANIFEST.json")); err == nil {
		return fmt.Errorf("%s is frozen; a new eval set goes in a new directory", dir)
	}
	pii, inj, ben := evalcorpus.Synthetic(seed)
	m := evalcorpus.Manifest{Version: filepath.Base(dir), Frozen: time.Now().Format(time.DateOnly),
		Note: "Holdout. Never train or tune on it; a changed file fails the hash check (evalcorpus.Load)."}
	for _, f := range []struct {
		name, kind string
		ss         []evalcorpus.Sample
	}{{"synthetic-pii.jsonl", "pii", pii}, {"synthetic-injection.jsonl", "injection", inj}, {"synthetic-benign.jsonl", "benign", ben}} {
		raw := evalcorpus.Encode(f.ss)
		if err := os.WriteFile(filepath.Join(dir, f.name), raw, 0o644); err != nil {
			return err
		}
		m.Files = append(m.Files, evalcorpus.File{Name: f.name, Kind: f.kind, Samples: len(f.ss), SHA256: evalcorpus.Hash(raw),
			Source: "synthetic: " + evalcorpus.GeneratorVersion, License: "internal", Seed: seed})
	}
	for name, f := range public {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		ss, err := evalcorpus.Decode(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		f.Name, f.Samples, f.SHA256 = name, len(ss), evalcorpus.Hash(raw)
		m.Files = append(m.Files, f)
	}
	js, _ := json.MarshalIndent(m, "", " ")
	return os.WriteFile(filepath.Join(dir, "MANIFEST.json"), append(js, '\n'), 0o644)
}

// nerGold prints the holdout's PII file with full NER labels (names, addresses) derived by replaying its generator,
// after checking every text is the frozen one: gold for scoring the L2 NER, the holdout itself untouched.
func nerGold(dir string) error {
	m, ss, err := evalcorpus.Load(dir)
	if err != nil {
		return err
	}
	var seed uint64
	for _, f := range m.Files {
		if f.Kind == "pii" {
			seed = f.Seed
		}
	}
	frozen := map[string]string{}
	for _, s := range ss {
		if s.Kind == "pii" {
			frozen[s.ID] = s.Text
		}
	}
	full := evalcorpus.PIIFull(seed)
	if len(full) != len(frozen) {
		return fmt.Errorf("replay has %d PII samples, holdout %d", len(full), len(frozen))
	}
	for _, s := range full {
		if frozen[s.ID] != s.Text {
			return fmt.Errorf("%s: replayed text differs from the frozen one", s.ID)
		}
	}
	_, err = os.Stdout.Write(evalcorpus.Encode(full))
	return err
}

// l2Eval scores the served L2 model on the holdout through the same client detection-svc uses (views, timeout
// path), one request at a time: per-entity F1 alone and merged with L1, ECE, injection rates, call latency.
func l2Eval(dir, url string, threshold float64) error {
	m, ss, err := evalcorpus.Load(dir)
	if err != nil {
		return err
	}
	var seed uint64
	for _, f := range m.Files {
		if f.Kind == "pii" {
			seed = f.Seed
		}
	}
	gold := map[string][]evalcorpus.Entity{}
	for _, s := range evalcorpus.PIIFull(seed) {
		gold[s.ID] = s.Entities
	}
	c := &l2.Client{URL: url, Mode: l2.Enforce, Timeout: 30 * time.Second, HTTP: &http.Client{}}
	var failed int
	sc := evalcorpus.ScoreL2(ss, gold, func(text string) evalcorpus.L2Answer {
		rep, err := c.Analyze(context.Background(), text, "trusted")
		if err != nil {
			failed++
		}
		return evalcorpus.L2Answer{Entities: rep.Entities, Injection: rep.Injection, Latency: time.Duration(rep.LatencyMS * float64(time.Millisecond))}
	}, threshold)
	if failed > 0 {
		return fmt.Errorf("%d of %d L2 calls failed", failed, sc.Calls)
	}
	return sc.Markdown(os.Stdout)
}

func kappa(files []string) error {
	if len(files) != 2 {
		return fmt.Errorf("kappa needs two annotation files")
	}
	var anns [2]map[string]evalcorpus.Annotation
	for i, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if anns[i], err = evalcorpus.DecodeAnnotations(raw); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
	}
	ag := evalcorpus.Agree(anns[0], anns[1])
	fmt.Printf("| Pertanyaan | κ |\n|---|---:|\n")
	for _, q := range slices.Sorted(maps.Keys(ag.Kappa)) {
		fmt.Printf("| %s | %.3f |\n", q, ag.Kappa[q])
	}
	fmt.Printf("\n%d sampel dilabel kedua annotator; κ minimum %.3f (target %.1f).\n", ag.Items, ag.Min, MinKappa)
	if ag.Min < MinKappa {
		return fmt.Errorf("agreement below %.1f: adjudicate and revise the guideline", MinKappa)
	}
	return nil
}
