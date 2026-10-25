// Package incident is SOC triage (spec §4.10): decision events with enough risk open or join an incident, which
// then moves through the FR-INC-3 state machine under an acknowledge SLA.
package incident

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"wantimpres26/internal/events"
	sealpkg "wantimpres26/internal/seal"
)

type State string

const (
	New           State = "New"
	Triaged       State = "Triaged"
	Investigating State = "Investigating"
	Contained     State = "Contained"
	Resolved      State = "Resolved"
	Closed        State = "Closed"
)

// OpenStates still collect new events (dedup); Resolved/Closed do not.
var OpenStates = []State{New, Triaged, Investigating, Contained}

// transitions is FR-INC-3. A non-empty label marks an edge the diagram names (duplicate, false positive, reopen):
// those need a note saying why.
var transitions = map[State]map[State]string{
	New:           {Triaged: ""},
	Triaged:       {Investigating: "", Closed: "duplicate"},
	Investigating: {Contained: "", Resolved: "false positive / benign"},
	Contained:     {Resolved: ""},
	Resolved:      {Closed: "", Investigating: "reopen"},
}

var ErrInvalidTransition = errors.New("invalid transition")

// CheckTransition validates from -> to with its note.
func CheckTransition(from, to State, note string) error {
	label, ok := transitions[from][to]
	if !ok {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, from, to)
	}
	if label != "" && strings.TrimSpace(note) == "" {
		return fmt.Errorf("%w: %s -> %s (%s) needs a note", ErrInvalidTransition, from, to, label)
	}
	return nil
}

// Severities, weakest first (FR-INC-2).
var Severities = []string{"low", "medium", "high", "critical"}

func SeverityRank(s string) int { return slices.Index(Severities, s) }

// SeverityFor maps a risk score: critical >= 90, high 70-89, medium 40-69, low < 40.
func SeverityFor(score int) string {
	switch {
	case score >= 90:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 40:
		return "medium"
	}
	return "low"
}

// MinRisk is the lowest event risk that opens an incident: low-risk events stay in search only.
const MinRisk = 40

// AckSLA is FR-INC-7: time to leave New. Severities without an entry have no SLA.
var AckSLA = map[string]time.Duration{"critical": 15 * time.Minute, "high": time.Hour}

// DedupWindow: an event joins an open incident with the same key if it is within this of the incident's events.
const DedupWindow = 30 * time.Minute

// DedupKey is FR-INC-1's (principal, destination, class, policy): the class set and the matched rules stand in
// for class and policy_id, because one event can carry several classes and the PDP's policy_id is constant.
func DedupKey(e events.Event) string {
	classes := make([]string, 0, len(e.Classes))
	for _, c := range e.Classes {
		classes = append(classes, c.Type)
	}
	slices.Sort(classes)
	rules := slices.Sorted(slices.Values(e.MatchedRules))
	return strings.Join([]string{e.PrincipalID, e.AppID, strings.Join(slices.Compact(classes), ","), strings.Join(rules, ",")}, "|")
}

// seal / open: AES-256-GCM (internal/seal). aad binds the ciphertext to where it belongs, so a wrapped DEK or
// evidence blob copied to another incident does not decrypt.
var (
	seal = sealpkg.Seal
	open = sealpkg.Open
)
