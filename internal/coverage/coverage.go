// Package coverage defines the typed contract stored in Scan.Coverage: what
// a scan did and did not reach, and how confident the worker is in that.
//
// The column was an ad-hoc JSON blob with two owners writing different shapes
// into it (the diff-rescan staging path in internal/worker and the
// threat-model update path in internal/web), so a consumer could not tell
// "no findings after a complete scan" from "no findings in the part that
// finished". A Record is that distinction, written by every scan mode.
//
// Completeness is derived by the worker from receipt reconciliation against
// the scope it staged itself, never from the skill's own claim about how much
// it covered. Where the worker has no independently known scope, the honest
// answer is CompletenessUnknown, not CompletenessComplete.
package coverage

import (
	"encoding/json"
	"sort"
	"strings"
)

// Version is the contract version stamped on every Record written. Consumers
// that need to reason about older rows compare against it; rows written
// before the typed contract carry 0.
const Version = 1

// Completeness states how much of the intended scope this scan actually
// reached. Anything other than Complete requires a Reason.
const (
	// CompletenessComplete means every work item in the staged scope has a
	// receipt. Only the worker may assign it, and only for a mode where it
	// enumerated the scope itself.
	CompletenessComplete = "complete"
	// CompletenessPartial means the scope was known and some of it was not
	// reached.
	CompletenessPartial = "partial"
	// CompletenessUnknown means no scope was enumerable, so no claim can be
	// made. This is the correct value for a full-repository scan until a
	// work manifest exists, and it is deliberately not a synonym for
	// "probably fine".
	CompletenessUnknown = "unknown"
)

// Dispositions record what happened to one work item. reviewed_clean and
// reviewed_findings are both completed work; the rest are all reasons a unit
// did not produce a verdict, kept apart so a partial scan can say which kind
// of gap it means.
const (
	DispositionReviewedClean    = "reviewed_clean"
	DispositionReviewedFindings = "reviewed_findings"
	DispositionSupporting       = "supporting"
	DispositionDeferred         = "deferred"
	DispositionExcluded         = "excluded"
	DispositionFailed           = "failed"
	DispositionCostCapped       = "cost_capped"
)

// Record is the whole coverage contract for one scan.
type Record struct {
	Version int `json:"version"`

	// RequestedMode and ActualMode carry the rescan mode the operator asked
	// for and the one that ran; they differ when the worker fell back, and
	// FallbackReason says why.
	RequestedMode  string `json:"requested_mode,omitempty"`
	ActualMode     string `json:"actual_mode,omitempty"`
	FallbackReason string `json:"fallback_reason,omitempty"`

	// Completeness is one of the constants above. Reason is required
	// whenever Completeness is not Complete.
	Completeness string `json:"completeness"`
	Reason       string `json:"reason,omitempty"`

	// IncludedPaths is the scope the worker staged. ExcludedPaths and
	// DeferredPaths carry a reason each, since a bare path list does not
	// say whether the omission was a policy decision or a shortfall.
	IncludedPaths []string     `json:"included_paths,omitempty"`
	ExcludedPaths []PathReason `json:"excluded_paths,omitempty"`
	DeferredPaths []PathReason `json:"deferred_paths,omitempty"`

	// Receipts is the per-work-item record reconciled against
	// IncludedPaths. Produced by the skill; the worker only reconciles.
	Receipts []Receipt `json:"receipts,omitempty"`

	// Surfaces, OpenQuestions and DroppedFindings are declared by this
	// contract but have no producer yet: they arrive with the skill-side
	// reporting channel. They are listed here so the shape is fixed before
	// several skills start inventing their own.
	Surfaces        []Surface         `json:"surfaces,omitempty"`
	OpenQuestions   []string          `json:"open_questions,omitempty"`
	DroppedFindings []DroppedFinding  `json:"dropped_findings,omitempty"`
	ThreatModel     *ThreatModelState `json:"threat_model,omitempty"`
}

// PathReason is a path plus why it is not in the reviewed set.
type PathReason struct {
	Path   string `json:"path"`
	Reason string `json:"reason,omitempty"`
}

// Receipt is one work item's outcome.
type Receipt struct {
	Path        string `json:"path"`
	Disposition string `json:"disposition"`
	Reason      string `json:"reason,omitempty"`
}

// Reviewed reports whether this receipt represents work that ran to
// completion, whatever it concluded. A failed or cost-capped unit did not.
func (r Receipt) Reviewed() bool {
	return r.Disposition == DispositionReviewedClean || r.Disposition == DispositionReviewedFindings
}

// Surface is an attack surface the scan reports having looked at.
type Surface struct {
	Name        string `json:"name"`
	Disposition string `json:"disposition,omitempty"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// DroppedFinding is a candidate discarded before verify ran, kept so a clean
// report can be told apart from a filtered one.
type DroppedFinding struct {
	Fingerprint string `json:"fingerprint,omitempty"`
	Path        string `json:"path,omitempty"`
	Reason      string `json:"reason"`
	Detail      string `json:"detail,omitempty"`
}

// ThreatModelState carries what the diff threat-model path used to merge into
// the untyped blob as threat_model_update / threat_model_material /
// threat_model_update_reason. It is a completeness statement — "the
// repository model was not updated because the diff was too small" — so it
// belongs in the record rather than beside it.
type ThreatModelState struct {
	Update   string `json:"update"`
	Material bool   `json:"material"`
	Reason   string `json:"reason,omitempty"`
}

// Parse reads a stored coverage value. It accepts rows written before this
// contract existed: the legacy keys are read into their typed homes, and a
// row that carries no completeness claim is reported as Unknown rather than
// being guessed at. An empty or unparseable value yields a zero Record and
// ok=false, so callers can tell "nothing recorded" from "recorded nothing".
func Parse(raw string) (Record, bool) {
	if strings.TrimSpace(raw) == "" {
		return Record{}, false
	}
	var rec Record
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return Record{}, false
	}
	if rec.Version == 0 {
		var legacy struct {
			Update   *string `json:"threat_model_update"`
			Material bool    `json:"threat_model_material"`
			Reason   string  `json:"threat_model_update_reason"`
		}
		if json.Unmarshal([]byte(raw), &legacy) == nil && legacy.Update != nil {
			rec.ThreatModel = &ThreatModelState{
				Update:   *legacy.Update,
				Material: legacy.Material,
				Reason:   legacy.Reason,
			}
		}
	}
	if rec.Completeness == "" {
		rec.Completeness = CompletenessUnknown
	}
	return rec, true
}

// Marshal renders a record for storage, stamping the current version.
func Marshal(rec Record) (string, error) {
	rec.Version = Version
	if rec.Completeness == "" {
		rec.Completeness = CompletenessUnknown
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// settled reports whether a disposition closes out a work item. A unit that
// was deliberately left out (excluded) is as settled as one that was
// reviewed; a unit that was deferred, failed, or ran out of budget is not,
// and keeps the scan partial even though it has a receipt.
func settled(disposition string) bool {
	switch disposition {
	case DispositionReviewedClean, DispositionReviewedFindings,
		DispositionSupporting, DispositionExcluded:
		return true
	}
	return false
}

// Reconcile derives Completeness from the receipts against the scope the
// worker staged, and returns the scoped paths that leave the scan short —
// both the ones no receipt mentions and the ones whose receipt says the work
// did not finish.
//
// It is deliberately the worker's job and not the skill's: a skill that
// silently skipped half a diff would otherwise report itself complete. An
// empty scope means the worker had nothing to reconcile against — a full or
// focus-area scan today — and yields Unknown, never Complete, however many
// receipts the skill supplied.
func (rec *Record) Reconcile(scope []string) []string {
	if len(scope) == 0 {
		rec.Completeness = CompletenessUnknown
		if rec.Reason == "" {
			rec.Reason = "no enumerable scope for this scan mode"
		}
		return nil
	}
	byPath := make(map[string]Receipt, len(rec.Receipts))
	for _, r := range rec.Receipts {
		if r.Path != "" {
			byPath[r.Path] = r
		}
	}
	var (
		gaps        []string
		unreceipted bool
		unfinished  bool
	)
	for _, path := range scope {
		receipt, ok := byPath[path]
		switch {
		case !ok:
			unreceipted = true
		case !settled(receipt.Disposition):
			unfinished = true
		default:
			continue
		}
		gaps = append(gaps, path)
	}
	sort.Strings(gaps)
	if len(gaps) == 0 {
		rec.Completeness = CompletenessComplete
		rec.Reason = ""
		return nil
	}
	rec.Completeness = CompletenessPartial
	if rec.Reason == "" {
		switch {
		case unreceipted && unfinished:
			rec.Reason = "staged work items are unreceipted or unfinished"
		case unreceipted:
			rec.Reason = "staged work items have no receipt"
		default:
			rec.Reason = "staged work items did not finish"
		}
	}
	return gaps
}
