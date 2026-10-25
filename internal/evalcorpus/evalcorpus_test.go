package evalcorpus

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"wantimpres26/internal/detect"
)

const holdout = "../../data/eval/v1"

// TestHoldoutFrozen: the files match the manifest hashes, and the synthetic ones are exactly what the recorded
// generator and seed produce, so nothing was edited or hand-added (ticket 04 AC: frozen and hashed).
func TestHoldoutFrozen(t *testing.T) {
	m, ss, err := Load(holdout)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, s := range ss {
		if ids[s.ID] {
			t.Errorf("duplicate id %s", s.ID)
		}
		ids[s.ID] = true
	}
	pii, inj, ben := Synthetic(m.Files[0].Seed)
	for _, f := range m.Files {
		want := map[string][]Sample{"synthetic-pii.jsonl": pii, "synthetic-injection.jsonl": inj, "synthetic-benign.jsonl": ben}[f.Name]
		if want == nil {
			if f.License == "" || f.Upstream == "" || f.Source == "" {
				t.Errorf("%s: public file without source, licence or revision", f.Name)
			}
			continue
		}
		raw, _ := os.ReadFile(filepath.Join(holdout, f.Name))
		if !bytes.Equal(raw, Encode(want)) {
			t.Errorf("%s differs from %s seed=%d: bump GeneratorVersion and freeze a new version instead", f.Name, GeneratorVersion, f.Seed)
		}
	}
}

// TestSyntheticLabels: every labelled entity is structurally valid by an independent check, references and
// invoices (unlabelled) are not, cards are published test numbers: no real customer data (ticket 04 AC).
func TestSyntheticLabels(t *testing.T) {
	pii, inj, ben := Synthetic(1)
	for _, s := range pii {
		for i, e := range s.Entities {
			v := digitsOf(s.Text[e.Start:e.End])
			if !validEntity(e.Type, v) {
				t.Errorf("%s: %s %q not valid", s.ID, e.Type, s.Text[e.Start:e.End])
			}
			if e.Type == "PCI.PAN" && !slices.Contains(testPANs, v) {
				t.Errorf("%s: card %s is not a published test number", s.ID, v)
			}
			if i > 0 && s.Entities[i-1].End > e.Start {
				t.Errorf("%s: overlapping entities", s.ID)
			}
		}
	}
	if len(pii) < 500 || len(inj) < 400 || len(ben) < 500 {
		t.Errorf("sizes pii %d injection %d benign %d", len(pii), len(inj), len(ben))
	}
	techniques := map[string]int{}
	for _, s := range inj {
		techniques[s.Technique]++
	}
	for _, tq := range []string{"direct", "roleplay", "role_confusion", "indirect_html", "indirect_email", "indirect_pdf", "indirect_tool_result",
		"exfil_markdown", "encoded_base64", "encoded_hex", "encoded_url", "encoded_homoglyph", "encoded_zero_width", "encoded_unicode_tags", "multilingual", "gcg_suffix"} {
		if techniques[tq] < 15 {
			t.Errorf("technique %s: %d samples", tq, techniques[tq])
		}
	}
}

func digitsOf(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
}

func validEntity(typ, d string) bool {
	luhnOK := func(d string) bool { return luhnDigit(d[:len(d)-1]) == d[len(d)-1] }
	switch typ {
	case "PII_ID.NIK", "PII_ID.KK":
		return len(d) == 16 && slices.Contains(provinceNo, d[:2]) && d[12:] != "0000"
	case "PII_ID.NPWP":
		if len(d) == 16 && d[0] == '0' {
			d = d[1:]
		}
		return len(d) == 15 && luhnOK(d[:9])
	case "PCI.PAN":
		return luhnOK(d)
	case "PII_ID.PHONE":
		if strings.HasPrefix(d, "62") {
			d = "0" + d[2:]
		}
		return d[0] == '0' && slices.Contains(mobile, d[1:4]) && len(d) >= 10 && len(d) <= 13
	case "FIN.ACCOUNT":
		return slices.ContainsFunc(banks, func(b struct {
			name string
			n    int
		}) bool {
			return b.n == len(d)
		})
	}
	return false
}

// TestPublicSetHasNoPII: the open dataset brings no sensitive data the detector recognises.
func TestPublicSetHasNoPII(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(holdout, "public-deepset-test.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	ss, _ := Decode(raw)
	for _, s := range ss {
		if r := detect.Scan(s.Text); len(r.Classes) > 0 {
			t.Errorf("%s: %+v", s.ID, r.Classes)
		}
	}
}

func TestKappa(t *testing.T) {
	near := func(a, b float64) bool { return math.Abs(a-b) < 1e-9 }
	if k := Kappa([]bool{true, true, false, false}, []bool{true, false, false, false}); !near(k, 0.5) {
		t.Errorf("κ = %v, want 0.5", k)
	}
	if k := Kappa([]bool{true, false}, []bool{true, false}); !near(k, 1) {
		t.Errorf("perfect κ = %v", k)
	}
	a := map[string]Annotation{"1": {ID: "1", Attack: true, PII: []string{"PII_ID.NIK"}}, "2": {ID: "2"}, "3": {ID: "3", Attack: true}, "4": {ID: "4"}}
	b := map[string]Annotation{"1": {ID: "1", Attack: true, PII: []string{"PII_ID.NIK"}}, "2": {ID: "2", Attack: true}, "3": {ID: "3", Attack: true}, "4": {ID: "4"}, "5": {ID: "5"}}
	ag := Agree(a, b)
	if ag.Items != 4 || !near(ag.Kappa["PII_ID.NIK"], 1) || !near(ag.Kappa["attack"], 0.5) || !near(ag.Min, 0.5) {
		t.Errorf("agreement %+v", ag)
	}
}

// TestScoreL1 scores detection L1 on the holdout and logs the §9.4 tables (the numbers are in ticket 04).
func TestScoreL1(t *testing.T) {
	_, ss, err := Load(holdout)
	if err != nil {
		t.Fatal(err)
	}
	s := Score(ss, detect.Scan, 0.8)
	var b bytes.Buffer
	_ = s.Markdown(&b)
	t.Log("\n" + b.String())
	if s.PII["PII_ID.PHONE"].TP == 0 || s.Injection["direct"][0] == 0 {
		t.Error("scorer counts nothing")
	}
}

// TestPIIFull: the derived NER gold replays the frozen PII file byte for byte, keeps its labels and adds every
// name and street address (ticket 09: scoring NER on the holdout without editing it).
func TestPIIFull(t *testing.T) {
	_, ss, err := Load(holdout)
	if err != nil {
		t.Fatal(err)
	}
	frozen := map[string]Sample{}
	for _, s := range ss {
		frozen[s.ID] = s
	}
	names, addrs := 0, 0
	for _, s := range PIIFull(1) {
		f := frozen[s.ID]
		if f.Text != s.Text {
			t.Fatalf("%s: replay differs", s.ID)
		}
		var kept []Entity
		for _, e := range s.Entities {
			switch e.Type {
			case "PII.NAME":
				names++
				if !slices.ContainsFunc(firstNames, func(n string) bool { return strings.HasPrefix(s.Text[e.Start:e.End], n) }) {
					t.Errorf("%s: name %q", s.ID, s.Text[e.Start:e.End])
				}
			case "PII.ADDRESS":
				addrs++
				if v := s.Text[e.Start:e.End]; !strings.HasPrefix(v, "Jl. ") || !slices.ContainsFunc(cities, func(c string) bool { return strings.HasSuffix(v, c) }) {
					t.Errorf("%s: address %q", s.ID, v)
				}
			default:
				kept = append(kept, e)
			}
		}
		if !slices.Equal(kept, f.Entities) {
			t.Errorf("%s: structured labels changed: %v vs %v", s.ID, kept, f.Entities)
		}
	}
	if names < 600 || addrs < 50 {
		t.Errorf("%d names, %d addresses labelled", names, addrs)
	}
}

// TestTrainingDisjoint: the L2 training data shares no template, name, place, goal or text with the holdout, so
// holdout scores measure generalisation; its labels are valid like the holdout's (tickets 09-10).
func TestTrainingDisjoint(t *testing.T) {
	_, ss, err := Load(holdout)
	if err != nil {
		t.Fatal(err)
	}
	held := map[string]bool{}
	for _, s := range ss {
		held[s.Text] = true
	}
	for _, l := range [][2][]string{{firstNames, trainFirst}, {lastNames, trainLast}, {cities, trainCities}, {streets, trainStreets},
		{goalsEN, trainGoalsEN}, {goalsID, trainGoalsID}, {gcgTokens, trainSuffix}} {
		for _, x := range l[1] {
			if slices.Contains(l[0], x) {
				t.Errorf("%q is in both the holdout and the training vocabulary", x)
			}
		}
	}
	kinds := map[string]int{}
	for _, s := range Training(7, 300) {
		kinds[s.Kind]++
		if held[s.Text] {
			t.Errorf("training text is in the holdout: %q", s.Text)
		}
		for _, e := range s.Entities {
			if strings.HasPrefix(e.Type, "PII_ID.") || e.Type == "PCI.PAN" {
				if v := digitsOf(s.Text[e.Start:e.End]); !validEntity(e.Type, v) {
					t.Errorf("%s %q not valid", e.Type, s.Text[e.Start:e.End])
				}
			}
		}
	}
	if kinds["pii"] < 250 || kinds["injection"] < 500 || kinds["benign"] < 100 {
		t.Errorf("kinds %v", kinds)
	}
}

func TestECE(t *testing.T) {
	// 0.75 confidence, right 3 of 4 times: calibrated. 0.95 confidence, right half the time: off by 0.45.
	if e := ECE([]float64{0.75, 0.75, 0.75, 0.75}, []bool{true, true, true, false}, 10); math.Abs(e) > 1e-9 {
		t.Errorf("calibrated: %v", e)
	}
	if e := ECE([]float64{0.95, 0.95, 0.75, 0.75, 0.75, 0.75}, []bool{true, false, true, true, true, false}, 10); math.Abs(e-2.0/6*0.45) > 1e-9 {
		t.Errorf("overconfident bin: %v", e)
	}
}
