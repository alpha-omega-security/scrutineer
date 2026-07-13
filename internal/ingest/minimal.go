package ingest

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
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

	// Sinks rides the default bundle; the fields below it, and the child-record
	// slices, are emitted only by an include=all archival bundle. Absent from
	// the default share bundle and older bundles, which then import unchanged.
	Sinks string `json:"sinks"`

	Snippet                 string `json:"snippet"`
	Affected                string `json:"affected"`
	FixVersion              string `json:"fix_version"`
	CVEID                   string `json:"cve_id"`
	GHSAID                  string `json:"ghsa_id"`
	CVSSVector              string `json:"cvss_vector"`
	CVSSv4Vector            string `json:"cvss_v4_vector"`
	Mitigation              string `json:"mitigation"`
	MitigationSemgrep       string `json:"mitigation_semgrep"`
	BreakingChange          string `json:"breaking_change"`
	BreakingChangeRationale string `json:"breaking_change_rationale"`
	DupCheck                string `json:"dup_check"`
	DisclosureDraft         string `json:"disclosure_draft"`
	SuggestedRecipients     string `json:"suggested_recipients"`
	ExploitedInWild         string `json:"exploited_in_wild"`
	ExploitedInWildEvidence string `json:"exploited_in_wild_evidence"`
	// UpstreamFixCommit is the real upstream fix commit; a new key because the
	// legacy `fix_commit` above already carries the SuggestedFix base.
	UpstreamFixCommit string `json:"upstream_fix_commit"`

	Notes          []minimalNote          `json:"notes"`
	Communications []minimalCommunication `json:"communications"`
	References     []minimalReference     `json:"references"`
}

// minimalNote, minimalCommunication and minimalReference are the wire shapes of
// a finding's child records inside an include=all bundle. They mirror the
// sharing* structs in internal/web/api_export.go field-for-field; the two are
// kept in lock-step so the round-trip stays byte-compatible.
type minimalNote struct {
	Body      string    `json:"body"`
	By        string    `json:"by"`
	CreatedAt time.Time `json:"created_at"`
}

type minimalCommunication struct {
	Channel     string    `json:"channel"`
	Direction   string    `json:"direction"`
	Actor       string    `json:"actor"`
	Body        string    `json:"body"`
	OfferedHelp string    `json:"offered_help"`
	At          time.Time `json:"at"`
	CreatedAt   time.Time `json:"created_at"`
}

type minimalReference struct {
	URL       string    `json:"url"`
	Tags      string    `json:"tags"`
	Summary   string    `json:"summary"`
	CreatedAt time.Time `json:"created_at"`
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
		nf := Finding{
			Title:                   f.Title,
			Description:             f.Description,
			Severity:                normaliseSeverity(f.Severity),
			Confidence:              strings.ToLower(strings.TrimSpace(f.Confidence)),
			CWE:                     f.CWE,
			Location:                f.Location,
			SuggestedFix:            f.Patch,
			Commit:                  f.Commit,
			SubPath:                 f.SubPath,
			Locations:               f.Locations,
			VID:                     f.VID,
			Reachability:            strings.ToLower(strings.TrimSpace(f.Reachability)),
			QualityTier:             strings.ToLower(strings.TrimSpace(f.QualityTier)),
			Boundary:                f.Boundary,
			Validation:              f.Validation,
			PriorArt:                f.PriorArt,
			Reach:                   f.Reach,
			Rating:                  f.Rating,
			FixCommit:               f.FixCommit,
			Sinks:                   f.Sinks,
			Snippet:                 f.Snippet,
			Affected:                f.Affected,
			FixVersion:              f.FixVersion,
			CVEID:                   f.CVEID,
			GHSAID:                  f.GHSAID,
			CVSSVector:              f.CVSSVector,
			CVSSv4Vector:            f.CVSSv4Vector,
			Mitigation:              f.Mitigation,
			MitigationSemgrep:       f.MitigationSemgrep,
			BreakingChange:          f.BreakingChange,
			BreakingChangeRationale: f.BreakingChangeRationale,
			DupCheck:                f.DupCheck,
			DisclosureDraft:         f.DisclosureDraft,
			SuggestedRecipients:     f.SuggestedRecipients,
			ExploitedInWild:         f.ExploitedInWild,
			ExploitedInWildEvidence: f.ExploitedInWildEvidence,
			UpstreamFixCommit:       f.UpstreamFixCommit,
		}
		// The minimal* wire types mirror their ingest counterparts field-for-
		// field, so a direct conversion suffices (and breaks the build if the two
		// ever drift, which is the invariant we want).
		for _, n := range f.Notes {
			nf.Notes = append(nf.Notes, Note(n))
		}
		for _, c := range f.Communications {
			nf.Communications = append(nf.Communications, Communication(c))
		}
		for _, ref := range f.References {
			nf.References = append(nf.References, Reference(ref))
		}
		res.Findings = append(res.Findings, nf)
	}
	return []Result{res}, nil
}
