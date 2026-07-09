package web

import (
	"encoding/json"
	"sort"

	"scrutineer/internal/db"
)

// fixValidationReport is the single artefact a fix-validation scan emits into
// its Report column. It composes the three signals fix-validation needs:
// the fingerprint diff of the baseline scan against the fix-ref
// re-scan (resolved/surviving/new) and the finding-scoped verify verdicts run
// against the fix ref. Stored as JSON so the existing scan_show report view
// (prettyjson) renders it without new UI.
type fixValidationReport struct {
	FixRef         string                 `json:"fix_ref"`
	Skill          string                 `json:"skill"`
	BaselineScanID uint                   `json:"baseline_scan_id"`
	FixScanID      uint                   `json:"fix_scan_id"`
	FixCommit      string                 `json:"fix_commit,omitempty"`
	Counts         fixValidationCounts    `json:"counts"`
	Resolved       []fixValidationFinding `json:"resolved"`
	Surviving      []fixValidationFinding `json:"surviving"`
	New            []fixValidationFinding `json:"new"`
	Verify         []fixValidationVerify  `json:"verify"`
}

type fixValidationCounts struct {
	Resolved  int `json:"resolved"`
	Surviving int `json:"surviving"`
	New       int `json:"new"`
}

type fixValidationFinding struct {
	FindingID   uint   `json:"finding_id"`
	Fingerprint string `json:"fingerprint"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	CWE         string `json:"cwe,omitempty"`
	Location    string `json:"location,omitempty"`
}

// fixValidationVerify is one targeted finding's reproduction-level verdict
// against the fix ref. Status mirrors the verify skill enum (confirmed, fixed,
// inconclusive, deferred); "pending" means the verify scan had not finished
// when the report was assembled.
type fixValidationVerify struct {
	FindingID uint   `json:"finding_id"`
	Title     string `json:"title"`
	Status    string `json:"status"`
}

const verifyStatusPending = "pending"

// classifyFixValidation splits the baseline scan's findings into the ones the
// fix-ref re-scan no longer reports (resolved) and the ones it still reports
// (surviving), and passes through the re-scan's brand-new findings (new). It
// keys off the re-observation bookkeeping the findings parser already
// maintains rather than diffing two raw sets: re-observing a finding merges
// into its existing row and bumps LastSeenScanID to the observing scan, so a
// baseline finding whose LastSeenScanID is the fix scan survived, and one with
// any other value was missed (resolved). New findings are the rows the fix
// scan created in its own right — a fresh fingerprint for the repository.
// Pure so the classification is unit-testable without a worker run.
func classifyFixValidation(baseline, fixNew []db.Finding, fixScanID uint) (resolved, surviving, newFindings []db.Finding) {
	for _, f := range baseline {
		if f.LastSeenScanID == fixScanID {
			surviving = append(surviving, f)
		} else {
			resolved = append(resolved, f)
		}
	}
	return resolved, surviving, fixNew
}

// buildFixValidationReport assembles the report struct from the already-loaded
// inputs. Kept pure (no DB access) so the composition and ordering are
// testable; the callback in validate_fix_enqueue.go does the loading.
func buildFixValidationReport(fixScan db.Scan, baselineScanID uint, baseline, fixNew []db.Finding, verify []fixValidationVerify) fixValidationReport {
	resolved, surviving, newFindings := classifyFixValidation(baseline, fixNew, fixScan.ID)
	if verify == nil {
		verify = []fixValidationVerify{}
	}
	sortVerify(verify)
	return fixValidationReport{
		FixRef:         fixScan.Ref,
		Skill:          fixScan.SkillName,
		BaselineScanID: baselineScanID,
		FixScanID:      fixScan.ID,
		FixCommit:      fixScan.Commit,
		Counts: fixValidationCounts{
			Resolved:  len(resolved),
			Surviving: len(surviving),
			New:       len(newFindings),
		},
		Resolved:  toValidationFindings(resolved),
		Surviving: toValidationFindings(surviving),
		New:       toValidationFindings(newFindings),
		Verify:    verify,
	}
}

// toValidationFindings projects findings onto the report shape and sorts them
// deterministically (severity high to low, then fingerprint) so the emitted
// JSON is reproducible regardless of DB row order (project rule: sort before
// emitting anything reproducible). Returns a non-nil slice so empty buckets
// marshal as [] rather than null.
func toValidationFindings(fs []db.Finding) []fixValidationFinding {
	out := make([]fixValidationFinding, 0, len(fs))
	for _, f := range fs {
		out = append(out, fixValidationFinding{
			FindingID:   f.ID,
			Fingerprint: f.Fingerprint,
			Title:       f.Title,
			Severity:    f.Severity,
			CWE:         f.CWE,
			Location:    f.Location,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if ri, rj := severityRank(out[i].Severity), severityRank(out[j].Severity); ri != rj {
			return ri > rj
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

func sortVerify(v []fixValidationVerify) {
	sort.Slice(v, func(i, j int) bool { return v[i].FindingID < v[j].FindingID })
}

// parseVerifyStatus pulls the verify skill's status enum out of a verify
// scan's report.json. Empty when the report is absent or unparseable, which
// the caller maps to a pending verdict.
func parseVerifyStatus(report string) string {
	var v struct {
		Status string `json:"status"`
	}
	if json.Unmarshal([]byte(report), &v) != nil {
		return ""
	}
	return v.Status
}
