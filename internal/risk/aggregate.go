// Package risk aggregates event risk scores per user, app, agent or data asset (spec FR-RISK-4). Event scores
// themselves come from the PDP (policy/wantimpres26/risk).
package risk

import (
	"math"
	"time"
)

// HalfLife is FR-RISK-4's decay: an event 14 days older than another counts half as much.
const HalfLife = 14 * 24 * time.Hour

// Agg is a time-weighted mean of scores, weight 2^(-age/HalfLife), updated in O(1) per event. Its zero value is
// empty. Persist the three fields per entity; events may arrive out of order.
type Agg struct {
	Sum    float64   // Σ weight·score, weights relative to At
	Weight float64   // Σ weight, relative to At
	At     time.Time // newest event seen
}

func decay(d time.Duration) float64 { return math.Exp2(-float64(d) / float64(HalfLife)) }

// Add folds in one event score observed at t.
func (a *Agg) Add(score float64, t time.Time) {
	w := 1.0
	if t.After(a.At) {
		f := decay(t.Sub(a.At))
		a.Sum, a.Weight, a.At = a.Sum*f, a.Weight*f, t
	} else {
		w = decay(a.At.Sub(t))
	}
	a.Sum += w * score
	a.Weight += w
}

// Value is the weighted mean, 0 when empty. Every weight decays at the same rate, so it does not change with
// the passage of time alone, only with new events.
func (a Agg) Value() float64 {
	if a.Weight == 0 {
		return 0
	}
	return a.Sum / a.Weight
}
