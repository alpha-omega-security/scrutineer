package coverage

import "strings"

const (
	PreflightReady    = "ready"
	PreflightDegraded = "degraded"
	PreflightBlocked  = "blocked"
)

// Preflight is worker-owned evidence, not part of the skill's coverage claim.
// Missing entries are namespaced as command:<name> or feature:<name>.
type Preflight struct {
	Status   string   `json:"status"`
	Missing  []string `json:"missing"`
	Degraded bool     `json:"degraded"`
	// Error means the probe itself failed; degraded mode cannot waive it.
	Error string `json:"error,omitempty"`
}

// CapPreflight must also run after reconciliation so model receipts cannot
// turn known runtime shortfalls into a claim of complete coverage.
func (rec *Record) CapPreflight() {
	if rec.Preflight == nil || rec.Preflight.Status == PreflightReady {
		return
	}
	rec.Completeness = CompletenessPartial
	rec.Reason = "capability preflight " + rec.Preflight.Status
	if len(rec.Preflight.Missing) > 0 {
		rec.Reason += ": " + strings.Join(rec.Preflight.Missing, ", ")
	}
	if rec.Preflight.Error != "" {
		rec.Reason += ": " + rec.Preflight.Error
	}
}
