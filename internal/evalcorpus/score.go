package evalcorpus

import (
	"cmp"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"wantimpres26/internal/detect"
)

// Detector is what is scored: detect.Scan for L1, or a wrapper that adds L2 later.
type Detector func(text string) detect.Result

// Counts is a confusion tally.
type Counts struct{ TP, FP, FN int }

func (c Counts) Precision() float64 { return ratio(c.TP, c.TP+c.FP) }
func (c Counts) Recall() float64    { return ratio(c.TP, c.TP+c.FN) }
func (c Counts) F1() float64 {
	p, r := c.Precision(), c.Recall()
	return ratio2(2*p*r, p+r)
}

func ratio(a, b int) float64 { return ratio2(float64(a), float64(b)) }
func ratio2(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

// Scores are the §9.4 metrics this corpus supports.
type Scores struct {
	Threshold     float64            // injection score at or above which a text counts as flagged
	PII           map[string]*Counts // per class, span level (a finding overlapping a gold span of its type)
	PIIBenignFPR  float64            // benign texts with any PII finding
	Injection     map[string][2]int  // per technique: flagged, total
	InjectionFPR  float64            // benign texts flagged as injection
	HardNegFPR    float64            // the same on the hard_negative subset
	Benign, Hards int
}

// Score runs d over the samples.
func Score(ss []Sample, d Detector, threshold float64) Scores {
	s := Scores{Threshold: threshold, PII: map[string]*Counts{}, Injection: map[string][2]int{}}
	var piiFP, injFP, hardFP int
	for _, x := range ss {
		r := d(x.Text)
		switch x.Kind {
		case "pii":
			s.matchPII(x.Entities, r.Matches)
		case "injection":
			v := s.Injection[x.Technique]
			v[1]++
			if r.Injection.Score >= threshold {
				v[0]++
			}
			s.Injection[x.Technique] = v
			continue
		case "benign":
			s.Benign++
			if r.Injection.Score >= threshold {
				injFP++
				if x.Technique == "hard_negative" {
					hardFP++
				}
			}
			if x.Technique == "hard_negative" {
				s.Hards++
			}
			if len(r.Classes) > 0 {
				piiFP++
			}
			s.matchPII(nil, r.Matches)
		}
	}
	s.PIIBenignFPR, s.InjectionFPR, s.HardNegFPR = ratio(piiFP, s.Benign), ratio(injFP, s.Benign), ratio(hardFP, s.Hards)
	return s
}

func (s *Scores) counts(t string) *Counts {
	if s.PII[t] == nil {
		s.PII[t] = &Counts{}
	}
	return s.PII[t]
}

func overlaps(e Entity, m detect.Match) bool { return m.Span[0] < e.End && e.Start < m.Span[1] }

func (s *Scores) matchPII(gold []Entity, found []detect.Match) {
	var ms []detect.Match
	for _, m := range found {
		if !strings.HasPrefix(m.Type, "INJECTION.") {
			ms = append(ms, m)
		}
	}
	used := make([]bool, len(ms))
	for _, e := range gold {
		i := slices.IndexFunc(ms, func(m detect.Match) bool { return m.Type == e.Type && overlaps(e, m) })
		if i < 0 {
			s.counts(e.Type).FN++
			continue
		}
		s.counts(e.Type).TP++
		used[i] = true
	}
	for i, m := range ms {
		// A finding on a gold span of another type is a false positive of its own type (wrong class).
		if !used[i] && !slices.ContainsFunc(gold, func(e Entity) bool { return e.Type == m.Type && overlaps(e, m) }) {
			s.counts(m.Type).FP++
		}
	}
}

// Markdown writes the scores as tables.
func (s Scores) Markdown(w io.Writer) error {
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	p("### Data sensitif (span)\n\n| Kelas | Precision | Recall | F1 | TP | FP | FN |\n|---|---:|---:|---:|---:|---:|---:|\n")
	for _, t := range slices.Sorted(maps.Keys(s.PII)) {
		c := s.PII[t]
		p("| %s | %.3f | %.3f | %.3f | %d | %d | %d |\n", t, c.Precision(), c.Recall(), c.F1(), c.TP, c.FP, c.FN)
	}
	p("\nTeks benign dengan temuan data sensitif: %.2f%% dari %d.\n\n", 100*s.PIIBenignFPR, s.Benign)
	p("### Prompt injection (ambang %.2f)\n\n| Teknik | Terdeteksi | Total | Rate |\n|---|---:|---:|---:|\n", s.Threshold)
	ts := slices.Collect(maps.Keys(s.Injection))
	slices.SortFunc(ts, func(a, b string) int { return cmp.Compare(a, b) })
	for _, t := range ts {
		v := s.Injection[t]
		p("| %s | %d | %d | %.1f%% |\n", t, v[0], v[1], 100*ratio(v[0], v[1]))
	}
	p("\nFPR benign: %.2f%% dari %d; pada hard negative: %.1f%% dari %d.\n", 100*s.InjectionFPR, s.Benign, 100*s.HardNegFPR, s.Hards)
	_, err := io.WriteString(w, b.String())
	return err
}
