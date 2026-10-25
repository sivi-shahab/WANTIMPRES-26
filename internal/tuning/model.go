// Package tuning is the per-tenant detector tuning of spec §9.3/§9.4 (ticket 38): SOC triage labels (true or false
// positive per class of an incident event) feed an active-learning queue; with the tenant's explicit opt-in a
// tenant model is trained on those labels, inside the tenant boundary, to suppress the detector findings the bank's
// analysts keep marking as false positives. A model ships only through the §9.4 release gate and a shadow → canary
// → 100% rollout.
//
// The model is a logistic regression over keyed-hashed features of the redacted event snippet (detect.Snippet) and
// the event context. Training data is what events already carry: no raw content, no customer data outside the
// tenant. Feature hashes are keyed with the tenant pepper, so weights mean nothing to another tenant. It tunes the
// L1 detectors only; the NER and injection models (tickets 09, 10) do not exist yet.
package tuning

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"math/rand/v2" // nosemgrep: math-random-used -- seeded PCG for a reproducible run, not crypto
	"sort"
	"strings"
	"unicode"
)

const (
	dims = 1 << 18
	// Gate (spec §9.4): no F1 regression above 1 point, no FPR rise above 0.2 point, against the model in production
	// (or the bare detector). MinRecall is ours: a tuning model exists to drop false positives, never real leaks.
	MaxF1Drop  = 0.01
	MaxFPRRise = 0.002
	MinRecall  = 0.98
	// recallTarget picks the threshold on the training split: at most 1% of true positives fall below it.
	recallTarget = 0.99
	maxThreshold = 0.5
)

// Sample is one labelled (or to-be-scored) detector finding: a class in a decision event with the event's context.
type Sample struct {
	Class      string
	Channel    string
	Direction  string
	AppID      string
	Confidence float64
	Snippet    string // detect.Snippet: redacted, ≤ 200 bytes
	TP         bool   // label: the finding is real
}

type featurizer struct{ mac hash.Hash }

func newFeaturizer(key []byte) *featurizer { return &featurizer{hmac.New(sha256.New, key)} }

func (f *featurizer) index(s string) uint32 {
	f.mac.Reset()
	f.mac.Write([]byte(s))
	var sum [sha256.Size]byte
	return binary.BigEndian.Uint32(f.mac.Sum(sum[:0])) % dims
}

// features: context fields, words and word pairs of the snippet, each also crossed with the class.
func (f *featurizer) features(s Sample) []uint32 {
	words := strings.FieldsFunc(strings.ToLower(s.Snippet), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' })
	fs := []string{"class=" + s.Class, "channel=" + s.Channel, "direction=" + s.Direction, "app=" + s.AppID,
		fmt.Sprintf("conf=%s|%.1f", s.Class, math.Floor(s.Confidence*10)/10)}
	for i, w := range words {
		fs = append(fs, "w="+w, "w="+s.Class+"|"+w)
		if i > 0 {
			fs = append(fs, "b="+words[i-1]+"_"+w, "b="+s.Class+"|"+words[i-1]+"_"+w)
		}
	}
	seen := map[uint32]bool{}
	out := make([]uint32, 0, len(fs))
	for _, x := range fs {
		if i := f.index(x); !seen[i] {
			seen[i] = true
			out = append(out, i)
		}
	}
	return out
}

// Weights is a trained model: P(true positive) = σ(Bias + Σ W[feature]).
type Weights struct {
	Bias      float64            `json:"bias"`
	W         map[uint32]float64 `json:"w"`
	Threshold float64            `json:"threshold"` // below it the finding is suppressed
}

func sigmoid(z float64) float64 { return 1 / (1 + math.Exp(-z)) }

func (m *Weights) prob(fs []uint32) float64 {
	z := m.Bias
	for _, i := range fs {
		z += m.W[i]
	}
	return sigmoid(z)
}

// Train fits the model on samples (deterministic for a given seed) and sets the threshold on the same split.
func Train(key []byte, samples []Sample, seed uint64) *Weights {
	f := newFeaturizer(key)
	xs := make([][]uint32, len(samples))
	var pos int
	for i, s := range samples {
		xs[i] = f.features(s)
		if s.TP {
			pos++
		}
	}
	// Balanced class weights: false positives are usually the majority of what analysts label.
	wPos := float64(len(samples)) / (2 * float64(max(pos, 1)))
	wNeg := float64(len(samples)) / (2 * float64(max(len(samples)-pos, 1)))
	w := make([]float64, dims)
	bias := 0.0
	const lr, l2, epochs = 0.2, 1e-4, 30
	order := make([]int, len(samples))
	for i := range order {
		order[i] = i
	}
	r := rand.New(rand.NewPCG(seed, 38))
	for range epochs {
		r.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		for _, k := range order {
			z := bias
			for _, i := range xs[k] {
				z += w[i]
			}
			y, cw := 0.0, wNeg
			if samples[k].TP {
				y, cw = 1, wPos
			}
			g := cw * (sigmoid(z) - y)
			bias -= lr * g
			for _, i := range xs[k] {
				w[i] -= lr * (g + l2*w[i])
			}
		}
	}
	m := &Weights{Bias: bias, W: map[uint32]float64{}}
	for i, v := range w {
		if v != 0 {
			m.W[uint32(i)] = v
		}
	}
	// Threshold: the TP probability at the 1st percentile, capped, so ≥ 99% of training TPs stay above it.
	var tps []float64
	for k, s := range samples {
		if s.TP {
			tps = append(tps, m.prob(xs[k]))
		}
	}
	sort.Float64s(tps)
	if len(tps) > 0 {
		m.Threshold = min(maxThreshold, tps[int(float64(len(tps))*(1-recallTarget))]-1e-9)
	}
	m.Threshold = max(m.Threshold, 0)
	return m
}

// Scorer scores samples with a model under the tenant key.
type Scorer struct {
	f *featurizer
	m *Weights
}

func NewScorer(key []byte, m *Weights) *Scorer { return &Scorer{newFeaturizer(key), m} }

// Prob is P(the finding is a true positive). A nil scorer keeps everything (probability 1).
func (s *Scorer) Prob(x Sample) float64 {
	if s == nil || s.m == nil {
		return 1
	}
	return s.m.prob(s.f.features(x))
}

// Keep reports whether the finding survives the model.
func (s *Scorer) Keep(x Sample) bool { return s == nil || s.m == nil || s.Prob(x) >= s.m.Threshold }

// Metrics on a labelled set, positive = a true finding kept. Keeping everything (no model) is F1 = 2P/(2P+N),
// FPR = 1, recall = 1.
type Metrics struct {
	N      int     `json:"n"`
	F1     float64 `json:"f1"`
	FPR    float64 `json:"fpr"`
	Recall float64 `json:"recall"`
}

func Evaluate(s *Scorer, samples []Sample) Metrics {
	var tp, fn, fp, tn float64
	for _, x := range samples {
		keep := s.Keep(x)
		switch {
		case x.TP && keep:
			tp++
		case x.TP:
			fn++
		case keep:
			fp++
		default:
			tn++
		}
	}
	r := func(f float64) float64 { return math.Round(f*10000) / 10000 }
	return Metrics{N: len(samples), F1: r(2 * tp / max(2*tp+fp+fn, 1)), FPR: r(fp / max(fp+tn, 1)), Recall: r(tp / max(tp+fn, 1))}
}

// Gate is the §9.4 release gate of a candidate against the production baseline on the same holdout.
type Gate struct {
	Candidate Metrics  `json:"candidate"`
	Baseline  Metrics  `json:"baseline"` // the active model, or the bare detector
	Pass      bool     `json:"pass"`
	Reasons   []string `json:"reasons,omitempty"`
}

func CheckGate(cand, base Metrics) Gate {
	g := Gate{Candidate: cand, Baseline: base}
	if cand.F1 < base.F1-MaxF1Drop {
		g.Reasons = append(g.Reasons, fmt.Sprintf("F1 %.4f < baseline %.4f - %.2f", cand.F1, base.F1, MaxF1Drop))
	}
	if cand.FPR > base.FPR+MaxFPRRise {
		g.Reasons = append(g.Reasons, fmt.Sprintf("FPR %.4f > baseline %.4f + %.3f", cand.FPR, base.FPR, MaxFPRRise))
	}
	if cand.Recall < MinRecall {
		g.Reasons = append(g.Reasons, fmt.Sprintf("recall %.4f < %.2f: the model would hide real findings", cand.Recall, MinRecall))
	}
	g.Pass = len(g.Reasons) == 0
	return g
}
