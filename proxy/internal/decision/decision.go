// Package decision is the proxy-side reduction of Coraza + ML outputs into a
// single allow/review/block verdict. The richer multi-signal consensus engine
// (M6) lives in the Python ML service; this is the lightweight local fallback
// used when ML is unreachable (safe mode).
package decision

const (
	ActionAllow  = "allow"
	ActionReview = "review"
	ActionBlock  = "block"
)

// Verdict is what gets enforced by the proxy and recorded in Mongo.
type Verdict struct {
	Action       string
	Score        float64
	Reasons      []string
	FallbackUsed bool
}

// FromCorazaOnly is the rule-only reduction: ML is bypassed and the verdict
// is decided purely from Coraza output. The fallback flag distinguishes the
// two callers — true when ML was unreachable (real safe-mode fallback), false
// when ML was deliberately skipped because Coraza already blocked. The flag
// is recorded in the audit log so operators can tell genuine ML outages apart
// from rule-driven blocks.
func FromCorazaOnly(corazaInterrupted bool, maxSeverity int, fallback bool, reasons []string) Verdict {
	v := Verdict{Reasons: append([]string{}, reasons...), FallbackUsed: fallback}
	v.Score = severityToScore(maxSeverity)
	if corazaInterrupted {
		v.Action = ActionBlock
		v.Reasons = append(v.Reasons, "Coraza disruptive rule fired")
		return v
	}
	v.Action = ActionAllow
	return v
}

// FromML takes the ML service's already-reduced action and ensures Coraza
// disruptive rules override an ML "allow" — defence in depth: a rule block
// is always honoured even if the model disagrees.
func FromML(corazaInterrupted bool, maxSeverity int, mlAction string, mlScore float64, reasons []string) Verdict {
	v := Verdict{
		Action:  mlAction,
		Score:   mlScore,
		Reasons: append([]string{}, reasons...),
	}
	if corazaInterrupted && v.Action != ActionBlock {
		v.Action = ActionBlock
		v.Score = 1.0
		v.Reasons = append(v.Reasons, "Coraza disruptive rule overrides ML allow")
	}
	return v
}

func severityToScore(sev int) float64 {
	if sev <= 0 {
		return 0
	}
	if sev >= 5 {
		return 1.0
	}
	return float64(sev) / 5.0
}
