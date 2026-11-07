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
	"time"
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

// maxModelLen bounds an imported model id. Real ids are a few dozen
// characters; anything longer is not attribution.
const maxModelLen = 100

// normaliseModel admits an imported model only when it looks like a model
// id: leading alphanumeric, the id charset, bounded length. Anything else
// is dropped to "" — the finding imports as unattributed — because bundle
// text is externally supplied and a partially-stripped value would be
// fabricated attribution. Unlike severity, invalid values do NOT pass
// through: this field ends up in the reporting CSV, where a value with a
// leading `=`, `+`, `-`, `@`, tab, or CR reads as a spreadsheet formula
// (CWE-1236), and the leading-alphanumeric rule is what rules those out.
func normaliseModel(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxModelLen {
		return ""
	}
	if !isAlphanumeric(rune(s[0])) {
		return ""
	}
	for _, r := range s {
		// Brackets carry the context-window suffix on built-in claude ids
		// (claude-fable-5-1[1m]); they are inert in spreadsheets without a
		// leading trigger, which the leading-alphanumeric rule prevents.
		if !isAlphanumeric(r) && !strings.ContainsRune("._:/@+-_[]", r) {
			return ""
		}
	}
	return s
}

func isAlphanumeric(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// normaliseTool is defence in depth for the producer name, which unlike a
// model id is a free-form label ("GitHub Code Scanning"), so it keeps
// interior spaces and punctuation and only rejects the dangerous shapes: a
// leading spreadsheet-formula trigger, control characters, or an unbounded
// length. Invalid values become "unknown" rather than "" because an empty
// Tool would unmark the finding as imported (Finding.ImportedFrom) and
// feed an empty skill name into fingerprinting; "unknown" keeps the import
// provenance honest without carrying the hostile text.
func normaliseTool(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) > maxModelLen {
		return "unknown"
	}
	switch s[0] {
	case '=', '+', '-', '@':
		return "unknown"
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "unknown"
		}
	}
	return s
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
	// Attachments are the artifact URIs a SARIF result names in
	// result.attachments, such as the PoV file a fuzzer bundled with it.
	Attachments []string

	// The fields below are carried by scrutineer's own sharing bundle (see
	// internal/web/api_export.go) so an instance-to-instance round-trip
	// preserves the substance of a finding, not just its title. Other
	// parsers (SARIF, CSV, markdown) leave them empty and the import path
	// then writes the same empty columns it always did.

	// Commit is the revision this individual finding was observed at. Falls
	// back to Result.Commit on import, so a bundle can span findings from
	// scans at different commits without mispinning each Location.
	Commit string
	// SubPath is the monorepo subdirectory Location is relative to.
	SubPath string
	// Locations is the full newline-joined set of file:line positions when a
	// finding fired at several sites; Location holds the primary one.
	Locations string
	// VID is the cross-tool/cross-party correlation hash (the vid CLI).
	VID string
	// Reachability (reachable/harness_only/unclear) and QualityTier
	// (high/low) carry the source's exploitability and sink-quality verdicts.
	Reachability string
	QualityTier  string
	// Boundary, Validation, PriorArt, Reach and Rating are steps two through
	// six of the audit checklist; Description carries the first (Trace).
	Boundary   string
	Validation string
	PriorArt   string
	Reach      string
	Rating     string
	// FixCommit is the base revision SuggestedFix applies to.
	FixCommit string
	// Model is the model id of the scan that produced the finding on the
	// exporting instance, so a bundle round-trip preserves which model
	// generated it rather than attributing it to the receiving ingest run.
	Model string

	// Sinks (comma-joined sink ids) rides the default bundle alongside the
	// six-step prose; it is finding substance, not triage. Snippet and the
	// fields below it travel ONLY in an include=all archival bundle — the
	// finding's enrichment and disclosure work product. All empty for other
	// parsers and for the default share bundle.
	Sinks string

	Snippet                 string
	Affected                string
	FixVersion              string
	CVEID                   string
	GHSAID                  string
	CVSSVector              string
	CVSSv4Vector            string
	Mitigation              string
	MitigationSemgrep       string
	BreakingChange          string
	BreakingChangeRationale string
	DupCheck                string
	DisclosureDraft         string
	DisclosureTitle         string
	SuggestedRecipients     string
	ExploitedInWild         string
	ExploitedInWildEvidence string
	// UpstreamFixCommit is the real upstream fix commit (db.Finding.FixCommit),
	// kept distinct from FixCommit above (the SuggestedFix base) because the
	// bundle's legacy `fix_commit` key was already taken by the latter.
	UpstreamFixCommit string

	// Child records, carried only by an include=all bundle. Nil otherwise.
	Notes          []Note
	Communications []Communication
	References     []Reference
}

// Note, Communication and Reference mirror the db.Finding child tables of the
// same name. They are carried only by scrutineer's own include=all archival
// bundle (see internal/web/api_export.go); every other parser leaves the
// slices nil, so the import path writes no child rows for them.
type Note struct {
	Body      string
	By        string
	CreatedAt time.Time
}

type Communication struct {
	Channel     string
	Direction   string
	Actor       string
	Body        string
	OfferedHelp string
	At          time.Time
	CreatedAt   time.Time
}

type Reference struct {
	URL       string
	Tags      string
	Summary   string
	CreatedAt time.Time
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
// repository-scoped batch. Every result's Tool passes through
// normaliseTool on the way out, whichever parser produced it: SARIF
// driver names and minimal-JSON tool fields are externally supplied and
// flow into Scan.SkillName, Finding.ImportedFrom, and history rows.
func Parse(data []byte) ([]Result, Format, error) {
	rs, format, err := parseDetected(data)
	for i := range rs {
		rs[i].Tool = normaliseTool(rs[i].Tool)
	}
	return rs, format, err
}

func parseDetected(data []byte) ([]Result, Format, error) {
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
