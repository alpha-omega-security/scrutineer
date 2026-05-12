// Package ingest parses externally-produced vulnerability reports into a
// neutral form the web layer turns into Repository/Scan/Finding rows.
//
// Supported input formats are SARIF 2.1.0 (the interchange format most
// scanners emit: CodeQL, Semgrep, Snyk, Checkmarx), a minimal JSON shape
// for hand-written reports, and the CSV and markdown finding exports
// some hosted scanners produce. CSAF and OSV are intentionally left for
// follow-up work; CSAF in particular is lossy against the Finding schema
// so the round-trip needs more thought than a mechanical inverse of the
// existing emitter.
//
// The parser is deliberately permissive: an external report is a lead,
// not a verified finding, and the operator will run verify/reachability
// /patch over the result regardless. Missing fields are left empty
// rather than rejected.
package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// severityCanon maps any casing of the four levels onto the title-case
// form scrutineer uses everywhere else (severityOrder SQL, the
// /findings filter, db.SeverityAtLeast). Anything unrecognised passes
// through unchanged so an oddball source value still surfaces rather
// than being dropped silently.
var severityCanon = map[string]string{
	"critical": "Critical",
	"high":     "High",
	"medium":   "Medium",
	"low":      "Low",
}

func normaliseSeverity(s string) string {
	if v, ok := severityCanon[strings.ToLower(strings.TrimSpace(s))]; ok {
		return v
	}
	return strings.TrimSpace(s)
}

// Result is one batch of findings against one repository from one tool.
// A single uploaded file can yield several Results when it contains
// multiple SARIF runs.
type Result struct {
	// RepoURL is the source repository the findings are against, taken
	// from SARIF versionControlProvenance or the minimal-JSON
	// "repository" field. May be empty when the input did not carry
	// provenance, in which case the caller must supply it.
	RepoURL string
	// Commit is the revision the report was produced at, when known.
	Commit string
	// Tool is the producing scanner's name (SARIF tool.driver.name) and
	// becomes Finding.ImportedFrom.
	Tool     string
	Findings []Finding
}

// Finding is the format-neutral subset of an external report entry.
// Field names mirror db.Finding; the web layer copies them across.
type Finding struct {
	RuleID       string
	Title        string
	Description  string
	Severity     string
	Confidence   string
	CWE          string
	Location     string
	SuggestedFix string
}

// Format names the detected input encoding. Exposed so callers can log
// what was parsed.
type Format string

const (
	FormatSARIF    Format = "sarif"
	FormatMinimal  Format = "minimal"
	FormatCSV      Format = "csv"
	FormatMarkdown Format = "markdown"
)

var ErrUnrecognised = errors.New("ingest: input matches no supported format (want SARIF 2.1.0, minimal JSON, findings CSV, or findings markdown)")

// Parse sniffs data, picks a parser, and returns one Result per
// repository-scoped batch.
func Parse(data []byte) ([]Result, Format, error) {
	switch detect(data) {
	case FormatSARIF:
		rs, err := parseSARIF(data)
		return rs, FormatSARIF, err
	case FormatMinimal:
		rs, err := parseMinimal(data)
		return rs, FormatMinimal, err
	case FormatCSV:
		rs, err := parseCSV(data)
		return rs, FormatCSV, err
	case FormatMarkdown:
		rs, err := parseMarkdown(data)
		return rs, FormatMarkdown, err
	}
	return nil, "", ErrUnrecognised
}

// detect decodes just enough structure to tell the supported formats
// apart. JSON inputs are probed for top-level keys; non-JSON inputs are
// matched on shape (CSV header row, markdown H1 plus metadata block).
func detect(data []byte) Format {
	data = bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	var probe struct {
		Schema   string          `json:"$schema"`
		Runs     json.RawMessage `json:"runs"`
		Findings json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(data, &probe); err == nil {
		if len(probe.Runs) > 0 {
			return FormatSARIF
		}
		if len(probe.Findings) > 0 {
			return FormatMinimal
		}
		return ""
	}
	if isFindingsCSV(data) {
		return FormatCSV
	}
	if isFindingsMarkdown(data) {
		return FormatMarkdown
	}
	return ""
}

func wrapErr(format Format, err error) error {
	return fmt.Errorf("ingest %s: %w", format, err)
}
