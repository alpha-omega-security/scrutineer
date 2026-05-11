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
			Severity:     strings.ToLower(strings.TrimSpace(f.Severity)),
			Confidence:   strings.ToLower(strings.TrimSpace(f.Confidence)),
			CWE:          f.CWE,
			Location:     f.Location,
			SuggestedFix: f.Patch,
		})
	}
	return []Result{res}, nil
}
