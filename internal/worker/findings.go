package worker

import (
	"encoding/json"
	"fmt"
	"strings"

	"scrutineer/internal/db"
)

// scanReport mirrors the security-deep-dive skill's report schema. Report-
// level fields like boundaries, inventory and ruled_out stay in the raw
// JSON (Scan.Report); findings are extracted into db.Finding rows.
type scanReport struct {
	Repository    string          `json:"repository"`
	Commit        string          `json:"commit"`
	Artefact      string          `json:"artefact"`
	SpecVersion   int             `json:"spec_version"`
	Model         string          `json:"model"`
	Date          string          `json:"date"`
	FilesReviewed int             `json:"files_reviewed"`
	Languages     []string        `json:"languages"`
	Findings      []scanFinding   `json:"findings"`
	RuledOut      json.RawMessage `json:"ruled_out"`
	Inventory     json.RawMessage `json:"inventory"`
	Boundaries    json.RawMessage `json:"boundaries"`

	// Legacy fields from the old minimal schema (for backward compat)
	Notes string `json:"notes"`
}

type scanFinding struct {
	ID           string   `json:"id"`
	Sinks        []string `json:"sinks"`
	Title        string   `json:"title"`
	Severity     string   `json:"severity"`
	CWE          string   `json:"cwe"`
	Location     string   `json:"location"`
	Affected     string   `json:"affected"`
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
	Confidence string `json:"confidence"`
	Summary    string `json:"summary"`
	Details    string `json:"details"`
}

func parseReport(raw []byte) (scanReport, error) {
	var r scanReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return r, fmt.Errorf("report.json: %w", err)
	}
	return r, nil
}

func (f scanFinding) summaryText() string {
	if f.Trace != "" {
		if i := strings.Index(f.Trace, "\n\n"); i > 0 {
			return f.Trace[:i]
		}
		return f.Trace
	}
	return f.Summary
}

func (r scanReport) toFindings(scanID uint) []db.Finding {
	out := make([]db.Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, db.Finding{
			ScanID:     scanID,
			FindingID:  f.ID,
			Sinks:      strings.Join(f.Sinks, ", "),
			Title:      f.Title,
			Severity:   f.Severity,
			CWE:        f.CWE,
			Location:   f.Location,
			Affected:   f.Affected,
			Trace:      f.Trace,
			Boundary:   f.Boundary,
			Validation: f.Validation,
			PriorArt:   f.PriorArt,
			Reach:      f.Reach,
			Rating:     f.Rating,
			Confidence: f.Confidence,
			Summary:    f.summaryText(),
			Details:    f.Details,
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
