package similarity

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"wantimpres26/internal/detect"
)

var key = []byte("test-pepper")

// corpus generates synthetic bank documents: Zipf-distributed pseudo-words, common short phrases (< Guarantee
// words) sprinkled everywhere, and letter boilerplate (> Guarantee words) shared by every document, registered or
// not. The boilerplate is the false-positive trap: real bank letters share long template sentences.
type corpus struct {
	r       *rand.Rand
	zipf    *rand.Zipf
	vocab   []string
	phrases []string
	plate   []string
}

func newCorpus(seed uint64) *corpus {
	r := rand.New(rand.NewPCG(seed, 1))
	syl := []string{"ka", "ban", "da", "ta", "ri", "nya", "si", "lu", "pe", "mer", "ang", "gu", "na", "ja", "ko", "rek", "sal", "do"}
	seen := map[string]bool{}
	var vocab []string
	for len(vocab) < 4000 {
		w := ""
		for range 2 + r.IntN(3) {
			w += syl[r.IntN(len(syl))]
		}
		if !seen[w] {
			seen[w] = true
			vocab = append(vocab, w)
		}
	}
	c := &corpus{r: r, vocab: vocab, zipf: rand.NewZipf(r, 1.1, 2, uint64(len(vocab)-1))}
	for range 40 {
		c.phrases = append(c.phrases, c.words(3+r.IntN(4))) // 3-6 words: shorter than Guarantee
	}
	c.plate = []string{
		"Dengan hormat, bersama ini kami sampaikan bahwa sesuai dengan ketentuan yang berlaku di lingkungan Bank,",
		"Demikian kami sampaikan, atas perhatian dan kerja sama Bapak/Ibu kami ucapkan terima kasih.",
		"Dokumen ini bersifat RAHASIA dan hanya untuk penggunaan internal; dilarang menggandakan tanpa izin tertulis Direksi.",
	}
	return c
}

func (c *corpus) words(n int) string {
	ws := make([]string, n)
	for i := range ws {
		ws[i] = c.vocab[c.zipf.Uint64()]
	}
	return strings.Join(ws, " ")
}

func (c *corpus) doc(n int) string {
	var b strings.Builder
	b.WriteString(c.plate[0] + "\n\n")
	for b.Len() < n*6 {
		s := c.words(6 + c.r.IntN(14))
		if c.r.IntN(3) == 0 {
			s += " " + c.phrases[c.r.IntN(len(c.phrases))]
		}
		b.WriteString(strings.ToUpper(s[:1]) + s[1:] + ". ")
		if c.r.IntN(6) == 0 {
			b.WriteString("\n")
		}
	}
	b.WriteString("\n\n" + c.plate[1] + "\n" + c.plate[2])
	return b.String()
}

// excerpt is n consecutive words of doc, starting at a random word.
func (c *corpus) excerpt(doc string, n int) string {
	ws := strings.Fields(doc)
	n = min(n, len(ws))
	at := c.r.IntN(len(ws) - n + 1)
	return strings.Join(ws[at:at+n], " ")
}

func (c *corpus) prompt(body string) string {
	return "Tolong ringkas teks berikut dalam tiga poin " + c.phrases[0] + ":\n\n" + body + "\n\nJawab singkat ya, " + c.words(8) + "."
}

func reformat(s string) string { // case, punctuation and line-break changes
	s = strings.ToUpper(s)
	s = strings.NewReplacer(". ", ";\n", ", ", " - ", " ", "  ").Replace(s)
	return s
}

func substitute(c *corpus, s string, every int) string { // one word in every `every` replaced
	ws := strings.Fields(s)
	for i := every / 2; i < len(ws); i += every {
		ws[i] = c.vocab[c.r.IntN(len(c.vocab))]
	}
	return strings.Join(ws, " ")
}

type tally struct{ tp, fn, fp, tn int }

func (t tally) recall() float64    { return float64(t.tp) / float64(max(t.tp+t.fn, 1)) }
func (t tally) precision() float64 { return float64(t.tp) / float64(max(t.tp+t.fp, 1)) }

// TestEval is the precision/recall acceptance check on a synthetic confidential corpus (ticket 37): 200 registered
// documents, 200 unregistered ones from the same generator with the same boilerplate.
func TestEval(t *testing.T) {
	c := newCorpus(37)
	var docs []Doc
	var fps [][]int64
	var reg, unreg []string
	for i := range 400 {
		d := c.doc(300 + c.r.IntN(2700))
		if i%2 == 1 {
			unreg = append(unreg, d)
			continue
		}
		f := Fingerprints(key, d)
		docs = append(docs, Doc{ID: int64(len(docs) + 1), Name: fmt.Sprint("doc-", len(docs)+1), Sensitivity: "confidential", Size: len(f)})
		fps = append(fps, f)
		reg = append(reg, d)
	}
	ix := Build(key, docs, fps)

	found := func(text string, id int64) bool {
		for _, h := range ix.Match(text) {
			if id == 0 || h.Doc.ID == id {
				return true
			}
		}
		return false
	}
	cases := []struct {
		name      string
		make      func(d string) string
		minRecall float64
	}{
		{"whole document", func(d string) string { return d }, 1},
		{"verbatim excerpt 40 words in prompt", func(d string) string { return c.prompt(c.excerpt(d, 40)) }, 0.99},
		{"verbatim excerpt 150 words in prompt", func(d string) string { return c.prompt(c.excerpt(d, 150)) }, 1},
		{"reformatted excerpt 80 words", func(d string) string { return c.prompt(reformat(c.excerpt(d, 80))) }, 0.99},
		{"1 in 12 words replaced, 120 words", func(d string) string { return c.prompt(substitute(c, c.excerpt(d, 120), 12)) }, 0.95},
		{"1 in 6 words replaced, 200 words (beyond Guarantee: measured, not required)", func(d string) string {
			return c.prompt(substitute(c, c.excerpt(d, 200), 6))
		}, 0},
	}
	all := tally{}
	for _, tc := range cases {
		var tl tally
		for i, d := range reg {
			if found(tc.make(d), docs[i].ID) {
				tl.tp++
			} else {
				tl.fn++
			}
		}
		for _, d := range unreg {
			if found(tc.make(d), 0) {
				tl.fp++
			} else {
				tl.tn++
			}
		}
		t.Logf("%-75s recall %.3f precision %.3f (fp %d / %d)", tc.name, tl.recall(), tl.precision(), tl.fp, tl.fp+tl.tn)
		if tl.recall() < tc.minRecall {
			t.Errorf("%s: recall %.3f < %.2f", tc.name, tl.recall(), tc.minRecall)
		}
		all.tp, all.fn, all.fp, all.tn = all.tp+tl.tp, all.fn+tl.fn, all.fp+tl.fp, all.tn+tl.tn
	}
	// Benign prompts that only share boilerplate and common phrases with registered documents.
	for range 500 {
		p := c.prompt(c.plate[c.r.IntN(3)] + " " + c.words(30) + " " + c.plate[2])
		if found(p, 0) {
			all.fp++
		} else {
			all.tn++
		}
	}
	t.Logf("overall precision %.4f, false positives %d / %d negatives", all.precision(), all.fp, all.fp+all.tn)
	if all.precision() < 0.99 {
		t.Errorf("precision %.4f < 0.99", all.precision())
	}
}

func TestWinnowGuarantee(t *testing.T) {
	c := newCorpus(1)
	d := c.doc(2000)
	ix := Build(key, []Doc{{ID: 1, Sensitivity: "restricted", Size: 1}}, [][]int64{Fingerprints(key, d)})
	ws := strings.Fields(d)
	// Every shared run of Guarantee words yields a shared fingerprint.
	doc := map[int64]bool{}
	for _, f := range Fingerprints(key, d) {
		doc[f] = true
	}
	for at := 0; at+Guarantee <= len(ws); at += 7 {
		run := strings.Join(ws[at:at+Guarantee], " ")
		if !slices.ContainsFunc(Fingerprints(key, run), func(f int64) bool { return doc[f] }) {
			t.Fatalf("run at word %d has no shared fingerprint", at)
		}
	}
	// Different keys, different fingerprints: the stored set is useless without the tenant pepper.
	if a, b := Fingerprints(key, d), Fingerprints([]byte("other"), d); slices.Equal(a, b) || len(a) != len(b) {
		t.Fatalf("keying: equal=%v, %d vs %d", slices.Equal(a, b), len(a), len(b))
	}
	// Apply raises sensitivity and reports a span that Redact can use.
	text := "intro kalimat pembuka saja. " + c.excerpt(d, 60) + " penutup."
	r := detect.Scan(text)
	Apply(&r, ix.Match(text))
	if r.Sensitivity != "restricted" || len(r.Classes) != 1 || r.Classes[0].Type != Type || r.Classes[0].Count != 1 {
		t.Fatalf("apply: %+v", r)
	}
	// Up to W-1 words at each edge of the passage fall outside the first and last selected shingle.
	if red := detect.Redact(text, r.Matches, Type); !strings.HasPrefix(red, "intro kalimat pembuka saja. ") ||
		!strings.HasSuffix(red, " penutup.") || !strings.Contains(red, "[REDACTED:"+Type+"]") || len(red) > len(text)/2 {
		t.Fatalf("redact: %q", red)
	}
	if ix.Match("terlalu pendek") != nil || (*Index)(nil).Match(text) != nil {
		t.Fatal("short text or empty index must not match")
	}
}

// TestLatency: the inline budget (spec §9.1, §13.1). An 8K-token prompt (~6k words) against 1000 registered
// documents stays well inside the L2 50 ms p95 budget.
func TestLatency(t *testing.T) {
	if raceEnabled || testing.Short() {
		t.Skip("timing is meaningless under -race")
	}
	c := newCorpus(2)
	var docs []Doc
	var fps [][]int64
	for i := range 1000 {
		f := Fingerprints(key, c.doc(3000))
		docs, fps = append(docs, Doc{ID: int64(i + 1), Size: len(f)}), append(fps, f)
	}
	ix := Build(key, docs, fps)
	text := c.doc(6000)
	var ds []time.Duration
	for range 50 {
		t0 := time.Now()
		ix.Match(text)
		ds = append(ds, time.Since(t0))
	}
	slices.Sort(ds)
	p95 := ds[len(ds)*95/100]
	t.Logf("6k-word text vs 1000 documents: p50 %v p95 %v", ds[len(ds)/2], p95)
	if p95 > 20*time.Millisecond {
		t.Errorf("p95 %v > 20ms", p95)
	}
}
