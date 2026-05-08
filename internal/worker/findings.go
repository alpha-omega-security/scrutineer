package worker

import (
	"encoding/json"
	"fmt"
	"strings"

	"scrutineer/internal/db"
)

// scanReport extracts only the findings array from a security-deep-dive
// report. All other top-level fields (repository, artefact, boundaries,
// inventory, ruled_out, ...) stay in the raw JSON on Scan.Report and are
// never read here, so we do not declare them: a strict Go type on an unused
// field turns model output variance into a fatal scan error (#172).
type scanReport struct {
	Findings []scanFinding `json:"findings"`
}

type scanFinding struct {
	ID           string   `json:"id"`
	Sinks        []string `json:"sinks"`
	Title        string   `json:"title"`
	Severity     string   `json:"severity"`
	Confidence   string   `json:"confidence"`
	CWE          string   `json:"cwe"`
	Location     string   `json:"location"`
	Locations    []string `json:"locations"`
	Affected     string   `json:"affected"`
	Reachability string   `json:"reachability"`
	QualityTier  string   `json:"quality_tier"`
	ReachChecked int      `json:"reach_checked"`
	ReachExposed int      `json:"reach_exposed"`

	// Per-step markdown (security-deep-dive schema)
	Trace      string `json:"trace"`
	Boundary   string `json:"boundary"`
	Validation string `json:"validation"`
	PriorArt   string `json:"prior_art"`
	Reach      string `json:"reach"`
	Rating     string `json:"rating"`

	// Legacy fields (old schema)
	Summary string `json:"summary"`
	Details string `json:"details"`
}

func parseReport(raw []byte) (scanReport, error) {
	var r scanReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return r, fmt.Errorf("report.json: %w", err)
	}
	return r, nil
}

func (r scanReport) toFindings(scanID, repoID uint, commit, subPath string) []db.Finding {
	out := make([]db.Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, db.Finding{
			ScanID:       scanID,
			RepositoryID: repoID,
			Commit:       commit,
			SubPath:      subPath,
			FindingID:    f.ID,
			Sinks:        strings.Join(f.Sinks, ", "),
			Title:        f.Title,
			Severity:     f.Severity,
			Confidence:   strings.ToLower(f.Confidence),
			CWE:          f.CWE,
			Location:     f.Location,
			Locations:    strings.Join(f.Locations, "\n"),
			Affected:     f.Affected,
			Reachability: f.Reachability,
			QualityTier:  f.QualityTier,
			Trace:        f.Trace,
			Boundary:     f.Boundary,
			Validation:   f.Validation,
			PriorArt:     f.PriorArt,
			Reach:        f.Reach,
			Rating:       f.Rating,
		})
	}
	return out
}

// validEmail is a pragmatic filter. Anything without an @ or containing
// "noreply" gets dropped.
func validEmail(s string) bool {
	if !strings.Contains(s, "@") {
		return false
	}
	if strings.Contains(s, "noreply") {
		return false
	}
	return true
}
