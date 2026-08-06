package worker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"scrutineer/internal/db"
)

// ScanRecipe is the immutable snapshot of the inputs a worker was handed when
// it claimed a scan. It answers "what was this run asked to do", which the
// individual Scan columns stop answering over time: several of them are
// mutable, some are backfilled after the fact, and the threat model and scan
// config that shaped the run live on Repository, where a later edit leaves no
// trace that the scan ran against the older text.
//
// Two deliberate omissions, both because a recipe that is written once cannot
// carry a value that does not exist yet at claim time:
//
//   - The resolved commit. Scan.Commit is set from gitHead after the clone
//     (skill.go), which is well after the claim, so a recipe written at pickup
//     would pin an empty string forever. Recipe.Ref records what was asked for;
//     Scan.Commit remains the record of what that resolved to.
//   - The runner image digest, effective tool set and egress policy. Those are
//     properties of the container the scan runs in, which is not created until
//     after the claim either.
type ScanRecipe struct {
	Kind string `json:"kind,omitempty"`

	// Ref is the requested git ref, not the commit it resolved to. Empty
	// means the repository's default branch.
	Ref string `json:"ref,omitempty"`

	// Backend is the backend the worker resolved at claim time, which is
	// not necessarily the one recorded when the scan was queued.
	Backend string `json:"backend,omitempty"`
	Model   string `json:"model,omitempty"`
	Effort  string `json:"effort,omitempty"`

	Skill              string `json:"skill,omitempty"`
	SkillVersion       int    `json:"skill_version,omitempty"`
	SkillSchemaVersion int    `json:"skill_schema_version,omitempty"`
	SkillsRepoSHA      string `json:"skills_repo_sha,omitempty"`

	Profile   string `json:"profile,omitempty"`
	SubPath   string `json:"sub_path,omitempty"`
	ScopeMode string `json:"scope_mode,omitempty"`

	// FocusArea is embedded as parsed JSON rather than an escaped string so
	// a recipe diff shows the focus fields that changed, not one opaque
	// blob. Invalid JSON is dropped rather than failing the claim.
	FocusArea json.RawMessage `json:"focus_area,omitempty"`

	RescanMode     string `json:"rescan_mode,omitempty"`
	DiffBaseScanID *uint  `json:"diff_base_scan_id,omitempty"`

	// ParentScanID is the scan this one was enqueued as a rerun of, so a
	// chain of reruns can be walked one hop at a time. It is distinct from
	// ResumedFromScanID, which pins the lineage *root* for session reuse.
	ParentScanID *uint `json:"parent_scan_id,omitempty"`

	// ThreatModelSHA256 and ScanConfigSHA256 digest the Repository text in
	// effect at claim time, so a rerun after an edit is distinguishable
	// from one before it. Absent when the repository had none set.
	ThreatModelSHA256 string `json:"threat_model_sha256,omitempty"`
	ScanConfigSHA256  string `json:"scan_config_sha256,omitempty"`
}

// textDigest returns the hex SHA-256 of s, or "" when s is empty, so an
// unset threat model is absent from the recipe rather than recorded as the
// digest of the empty string.
func textDigest(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// buildScanRecipe renders the recipe for scan as JSON. backend is passed
// separately because the worker resolves it during the claim and the value on
// scan may still be the one recorded at enqueue. threatModel and scanConfig
// are the repository's text as read inside the claiming transaction.
func buildScanRecipe(scan *db.Scan, backend, threatModel, scanConfig string) (string, error) {
	r := ScanRecipe{
		Kind:               scan.Kind,
		Ref:                scan.Ref,
		Backend:            backend,
		Model:              scan.Model,
		Effort:             scan.Effort,
		Skill:              scan.SkillName,
		SkillVersion:       scan.SkillVersion,
		SkillSchemaVersion: scan.SkillSchemaVersion,
		SkillsRepoSHA:      scan.SkillsRepoSHA,
		Profile:            scan.Profile,
		SubPath:            scan.SubPath,
		ScopeMode:          scan.ScopeMode,
		RescanMode:         scan.RescanMode,
		DiffBaseScanID:     scan.DiffBaseScanID,
		ParentScanID:       scan.ParentScanID,
		ThreatModelSHA256:  textDigest(threatModel),
		ScanConfigSHA256:   textDigest(scanConfig),
	}
	if scan.FocusArea != "" && json.Valid([]byte(scan.FocusArea)) {
		r.FocusArea = json.RawMessage(scan.FocusArea)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
