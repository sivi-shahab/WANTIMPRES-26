package incident

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"wantimpres26/internal/events"
)

var allStates = []State{New, Triaged, Investigating, Contained, Resolved, Closed}

// FR-INC-3: every pair of states, valid exactly when the diagram has the edge.
func TestTransitions(t *testing.T) {
	valid := map[[2]State]bool{
		{New, Triaged}: true, {Triaged, Investigating}: true, {Investigating, Contained}: true,
		{Contained, Resolved}: true, {Investigating, Resolved}: true, {Resolved, Closed}: true,
		{Resolved, Investigating}: true, {Triaged, Closed}: true,
	}
	for _, from := range allStates {
		for _, to := range allStates {
			err := CheckTransition(from, to, "because the analyst said so")
			if valid[[2]State{from, to}] != (err == nil) {
				t.Errorf("%s -> %s: err %v, want valid=%v", from, to, err, valid[[2]State{from, to}])
			}
			if err != nil && !errors.Is(err, ErrInvalidTransition) {
				t.Errorf("%s -> %s: %v is not ErrInvalidTransition", from, to, err)
			}
		}
	}
	if CheckTransition("Bogus", Triaged, "x") == nil || CheckTransition(New, "Bogus", "x") == nil {
		t.Error("unknown state accepted")
	}
}

// The edges the diagram labels (duplicate, false positive, reopen) need a reason; the others do not.
func TestLabelledTransitionsNeedNote(t *testing.T) {
	for _, e := range [][2]State{{Triaged, Closed}, {Investigating, Resolved}, {Resolved, Investigating}} {
		if CheckTransition(e[0], e[1], "  ") == nil {
			t.Errorf("%s -> %s without a note accepted", e[0], e[1])
		}
	}
	if err := CheckTransition(New, Triaged, ""); err != nil {
		t.Errorf("plain edge needs no note: %v", err)
	}
}

func TestSeverityFor(t *testing.T) {
	for score, want := range map[int]string{0: "low", 39: "low", 40: "medium", 69: "medium", 70: "high", 89: "high", 90: "critical", 100: "critical"} {
		if got := SeverityFor(score); got != want {
			t.Errorf("SeverityFor(%d) = %s, want %s", score, got, want)
		}
	}
	if SeverityRank("critical") <= SeverityRank("high") || SeverityRank("bogus") != -1 {
		t.Error("severity ranks out of order")
	}
}

func TestDedupKey(t *testing.T) {
	e := events.Event{PrincipalID: "p", AppID: "a", MatchedRules: []string{"r2", "r1"},
		Classes: []events.Class{{Type: "PII_ID.NIK", Count: 2}, {Type: "PCI.PAN", Count: 1}, {Type: "PII_ID.NIK", Count: 1}}}
	same := e
	same.MatchedRules = []string{"r1", "r2"}
	same.Classes = []events.Class{{Type: "PCI.PAN", Count: 9}, {Type: "PII_ID.NIK", Count: 1}}
	if DedupKey(e) != DedupKey(same) {
		t.Errorf("order or counts changed the key: %q vs %q", DedupKey(e), DedupKey(same))
	}
	for name, mutate := range map[string]func(*events.Event){
		"principal": func(x *events.Event) { x.PrincipalID = "q" },
		"app":       func(x *events.Event) { x.AppID = "b" },
		"class":     func(x *events.Event) { x.Classes = x.Classes[:1] },
		"policy":    func(x *events.Event) { x.MatchedRules = []string{"r1"} },
	} {
		other := e
		other.Classes = append([]events.Class(nil), e.Classes...)
		mutate(&other)
		if DedupKey(other) == DedupKey(e) {
			t.Errorf("different %s, same key", name)
		}
	}
}

func TestSealBindsToContext(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	ct, err := seal(key, []byte("NIK 3171234567890001"), []byte("evidence:i1:e1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("3171234567890001")) {
		t.Fatal("plaintext visible in ciphertext")
	}
	if pt, err := open(key, ct, []byte("evidence:i1:e1")); err != nil || string(pt) != "NIK 3171234567890001" {
		t.Fatalf("round trip: %q %v", pt, err)
	}
	if _, err := open(key, ct, []byte("evidence:i2:e1")); err == nil {
		t.Error("evidence opened under another incident")
	}
	ct[len(ct)-1] ^= 1
	if _, err := open(key, ct, []byte("evidence:i1:e1")); err == nil {
		t.Error("tampered ciphertext opened")
	}
}
