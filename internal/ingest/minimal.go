package ingest

import (
	"encoding/json"
	"fmt"
	"strings"
)

// minimalReport is the hand-written ingest shape for findings that came
// from a pentest writeup or a tool with no SARIF emitter. It is
// deliberately small: enough to seed a Finding row that verify and
// patch then fill in.
type minimalReport struct {
	Repository string           `json:"repository"`
	Commit     string           `json:"commit"`
	Tool       string           `json:"tool"`
	Findings   []minimalFinding `json:"findings"`
}

type minimalFinding struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	CWE         string `json:"cwe"`
	Location    string `json:"location"`
	Patch       string `json:"patch"`

	// Extended fields scrutineer's own bundle emits. Absent in hand-written
	// reports and in bundles produced before these were added; unmarshalling
	// just leaves them empty, so older bundles still import unchanged.
	Commit       string `json:"commit"`
	SubPath      string `json:"sub_path"`
	Locations    string `json:"locations"`
	VID          string `json:"vid"`
	Reachability string `json:"reachability"`
	QualityTier  string `json:"quality_tier"`
	Boundary     string `json:"boundary"`
	Validation   string `json:"validation"`
	PriorArt     string `json:"prior_art"`
	Reach        string `json:"reach"`
	Rating       string `json:"rating"`
	FixCommit    string `json:"fix_commit"`
}

func parseMinimal(data []byte) ([]Result, error) {
	var r minimalReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, wrapErr(FormatMinimal, err)
	}
	if len(r.Findings) == 0 {
		return nil, wrapErr(FormatMinimal, fmt.Errorf("no findings"))
	}
	res := Result{
		RepoURL: r.Repository,
		Commit:  r.Commit,
		Tool:    firstNonEmpty(r.Tool, "manual"),
	}
	for _, f := range r.Findings {
		res.Findings = append(res.Findings, Finding{
			Title:        f.Title,
			Description:  f.Description,
			Severity:     normaliseSeverity(f.Severity),
			Confidence:   strings.ToLower(strings.TrimSpace(f.Confidence)),
			CWE:          f.CWE,
			Location:     f.Location,
			SuggestedFix: f.Patch,
			Commit:       f.Commit,
			SubPath:      f.SubPath,
			Locations:    f.Locations,
			VID:          f.VID,
			Reachability: strings.ToLower(strings.TrimSpace(f.Reachability)),
			QualityTier:  strings.ToLower(strings.TrimSpace(f.QualityTier)),
			Boundary:     f.Boundary,
			Validation:   f.Validation,
			PriorArt:     f.PriorArt,
			Reach:        f.Reach,
			Rating:       f.Rating,
			FixCommit:    f.FixCommit,
		})
	}
	return []Result{res}, nil
}
