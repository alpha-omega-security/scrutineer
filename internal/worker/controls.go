package worker

import (
	"fmt"
	"path"

	"scrutineer/internal/db"
	"scrutineer/internal/findingnorm"
	"scrutineer/internal/threatmodel"
)

const (
	controlsNoLocation  = "the finding has no repository-relative location to match against"
	controlsModelBroken = "the repository threat model could not be read"
)

// skillContextControls is the set of threat-model controls that claim to
// protect the file a finding lives in, resolved on the host and staged into
// context.json for the verify skill.
//
// Like novelty, this is deterministic host-side evidence rather than a
// verdict. The worker decides which controls match, because matching is a
// glob evaluation with a namespace precondition that the skill has no way to
// get right from inside the container; what the controls *mean* for the
// finding is the skill's job.
//
// Only matched controls are staged, never the whole model. A verify run is
// scoped to one finding, and handing it every control in the repository
// invites it to re-derive the match in prose — the exact non-determinism
// resolving it on the host is meant to remove.
type skillContextControls struct {
	// FindingFile is the repository-root-relative path the match was
	// performed against, after any subpath rebase. Staged so a report can
	// cite what was actually matched rather than what the finding row says.
	FindingFile string `json:"finding_file,omitempty"`
	// Matched are the controls whose protects.paths cover FindingFile, in
	// model order. Empty means the model declares controls but none claims
	// this file — which is itself worth knowing, and is not the same as a
	// repository with no controls at all.
	Matched []threatmodel.Control `json:"matched"`
	// IDs is the sorted, de-duplicated id set of Matched, for citing.
	IDs []string `json:"ids,omitempty"`
	// UnavailableWhy explains a block that could not be resolved. It is set
	// instead of failing the scan: a verify run answers whether a
	// reproduction still triggers, and refusing to run it because the
	// operator's threat model has a duplicate control id would trade a
	// useful answer for an unrelated authoring error. The skill reports the
	// reason rather than treating an empty match as "nothing protects this".
	UnavailableWhy string `json:"unavailable_reason,omitempty"`
}

// controlsContext resolves the matched-controls block for a finding-scoped
// verify run. It returns nil for every other skill, and for repositories
// whose threat model declares no controls, so context.json does not grow a
// block that carries no information.
func (w *Worker) controlsContext(scan *db.Scan, skill *db.Skill) (*skillContextControls, error) {
	if skill.Name != verifySkillName || scan.FindingID == nil {
		return nil, nil
	}

	model, err := threatmodel.Parse(scan.Repository.ThreatModel)
	if err != nil {
		return &skillContextControls{UnavailableWhy: controlsModelBroken + ": " + err.Error()}, nil
	}
	if len(model.Controls) == 0 {
		return nil, nil
	}
	if err := model.Validate(); err != nil {
		return &skillContextControls{UnavailableWhy: controlsModelBroken + ": " + err.Error()}, nil
	}

	var finding db.Finding
	if err := w.DB.Select("location").First(&finding, *scan.FindingID).Error; err != nil {
		return nil, fmt.Errorf("load finding for controls match: %w", err)
	}

	file := controlsFindingPath(scan.SubPath, finding.Location)
	if file == "" {
		return &skillContextControls{UnavailableWhy: controlsNoLocation}, nil
	}

	matched := model.MatchPath(file)
	return &skillContextControls{
		FindingFile: file,
		Matched:     matched,
		IDs:         threatmodel.IDs(matched),
	}, nil
}

// controlsFindingPath rebases a finding's location into the namespace the
// control globs are authored in.
//
// Control paths are repository-root-relative, because the threat model is a
// single document for the whole repository. A finding from a subpath-scoped
// scan reports its location relative to the sub-folder (the skill treats it
// as project root; see pruneToSubPath), so matching it against root-relative
// globs without the subpath prefix silently matches nothing. That is why the
// rebase happens here and not in threatmodel.MatchPath, which is handed a
// path and cannot tell the two namespaces apart.
//
// This is the same normalisation noveltyFindingPath performs for the same
// reason; both reject absolute paths and parent-segment escapes rather than
// cleaning them, so a malformed location produces no match instead of a match
// against the wrong file.
func controlsFindingPath(subPath, location string) string {
	file := findingnorm.LocationFile(location)
	subPath = findingnorm.RepoPath(subPath)
	if !validNoveltyPath(file) || (subPath != "" && !validNoveltyPath(subPath)) {
		return ""
	}
	return path.Join(subPath, file)
}
