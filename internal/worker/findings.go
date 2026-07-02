package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"scrutineer/internal/db"
)

// ErrInvalidFinding marks a streamed finding the caller sent wrong: malformed
// JSON or missing a required field. Handlers map it to a 4xx rather than 500.
var ErrInvalidFinding = errors.New("invalid finding")

// PersistStreamedFinding records one finding emitted mid-scan into the
// concurrent-finding log so sibling scans in the same ScanGroup can read it
// before this scan completes. It runs the same fingerprint, VID and
// snippet path as the end-of-scan report ingestion, so the final report.json
// reconciles against the streamed row instead of duplicating it. raw is a
// single finding object in the report.json finding shape; the scan's identity
// (id, repo, commit, sub-path) is stamped from scan, never trusted from raw.
func (w *Worker) PersistStreamedFinding(scan *db.Scan, raw []byte) (*db.Finding, error) {
	var sf scanFinding
	if err := json.Unmarshal(raw, &sf); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidFinding, err)
	}
	if strings.TrimSpace(sf.Title) == "" || strings.TrimSpace(sf.Severity) == "" || strings.TrimSpace(sf.Location) == "" {
		return nil, fmt.Errorf("%w: title, severity and location are required", ErrInvalidFinding)
	}
	f := sf.toFinding(scan.ID, scan.RepositoryID, scan.Commit, scan.SubPath)
	f.Fingerprint = db.FingerprintFinding(scan.SkillName, f.SubPath, f.CWE, f.Location, f.Title)

	srcDir := filepath.Join(w.scanWorkRoot(scan), "src")
	f.VID = w.computeVID(srcDir, f.Locations)
	f.Snippet = readSnippet(srcDir, f.Location)

	if _, err := w.persistFinding(scan, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

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

	References []scanReference `json:"references"`

	// Per-step markdown (security-deep-dive schema)
	Trace      string `json:"trace"`
	Boundary   string `json:"boundary"`
	Validation string `json:"validation"`
	PriorArt   string `json:"prior_art"`
	Reach      string `json:"reach"`
	Rating     string `json:"rating"`

	// DupCheck is the agent's one-sentence note on why this finding is
	// distinct from the siblings already filed under the same scan_group.
	DupCheck string `json:"dup_check"`

	// Legacy fields (old schema)
	Summary string `json:"summary"`
	Details string `json:"details"`
}

// scanReference is an external URL a skill attaches to a finding (rule docs,
// upstream advisory, blog post). Materialises as a db.FindingReference row.
type scanReference struct {
	URL     string `json:"url"`
	Summary string `json:"summary"`
	Tags    string `json:"tags"`
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
		out = append(out, f.toFinding(scanID, repoID, commit, subPath))
	}
	return out
}

func (f scanFinding) toFinding(scanID, repoID uint, commit, subPath string) db.Finding {
	return db.Finding{
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
		DupCheck:     f.DupCheck,
		References:   toReferences(f.References),
	}
}

func toReferences(refs []scanReference) []db.FindingReference {
	out := make([]db.FindingReference, 0, len(refs))
	for _, r := range refs {
		url := strings.TrimSpace(r.URL)
		if url == "" {
			continue
		}
		out = append(out, db.FindingReference{
			URL:     url,
			Summary: strings.TrimSpace(r.Summary),
			Tags:    strings.TrimSpace(r.Tags),
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
