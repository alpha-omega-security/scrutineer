// Package db holds GORM setup and the persistent models.
//
// SQLite is the default backend. GORM speaks PostgreSQL with a one-line
// driver swap (gorm.io/driver/postgres) and the schema below uses nothing
// SQLite-specific, so the migration path is "change the Open call".
package db

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Repository struct {
	ID   uint   `gorm:"primarykey"`
	URL  string `gorm:"uniqueIndex;not null"`
	Name string `gorm:"index;not null"`

	// Populated by the metadata job. Metadata holds the full ecosyste.ms
	// JSON payload; the scalar columns are the subset we filter or display
	// on, promoted so they can be queried without unpacking the blob.
	FullName      string
	Owner         string
	Description   string
	DefaultBranch string
	Languages     string
	License       string
	Stars         int `gorm:"index"`
	Forks         int
	Archived      bool
	PushedAt      *time.Time
	HTMLURL       string
	IconURL       string
	Metadata      string `gorm:"type:text"`
	FetchedAt     *time.Time

	// DisclosureChannel is the preferred vector for reporting a
	// vulnerability in this repo — an email, GHSA URL, registry owner
	// handle, or SECURITY.md URL. Written by the maintainers skill from
	// SECURITY.md / CODEOWNERS / registry data; the analyst can overwrite
	// it from the repo page.
	DisclosureChannel string

	// Posture is the disclosure-readiness tier assigned by the posture
	// skill: "ready", "partial", or "unprepared". PostureSummary is the
	// one-line explanation that goes with it. Both are advisory only and
	// are overwritten on each posture run.
	Posture        string `gorm:"index"`
	PostureSummary string

	// Fork is the full_name (owner/name) of this repository's private
	// staging repo inside the configured fork_org. Written by the fork
	// skill so later runs and the UI can find it without re-resolving the
	// name. Named `Fork` for legacy reasons; semantically a staging repo,
	// not a GitHub fork relationship.
	Fork string

	// CloneError is set when the last clone/fetch attempt failed (repo
	// deleted, made private, wrong URL). Non-empty means the repo is
	// currently unreachable. Cleared on next successful clone.
	CloneError string

	CreatedAt time.Time
	UpdatedAt time.Time

	Scans       []Scan       `gorm:"constraint:OnDelete:CASCADE"`
	Maintainers []Maintainer `gorm:"many2many:repository_maintainers"`
}

// IsLocal reports whether this Repository points at a directory on disk
// (file://<abs-path>) rather than a remote git URL. Used by the worker
// to skip the clone step and by the enqueue path to filter out skills
// that require a forge.
func (r Repository) IsLocal() bool { return strings.HasPrefix(r.URL, "file://") }

// LocalPath returns the filesystem path encoded in a local Repository's
// URL. Empty for remote repos.
func (r Repository) LocalPath() string {
	if !r.IsLocal() {
		return ""
	}
	return strings.TrimPrefix(r.URL, "file://")
}

type ScanStatus string

const (
	ScanQueued    ScanStatus = "queued"
	ScanRunning   ScanStatus = "running"
	ScanPaused    ScanStatus = "paused"
	ScanDone      ScanStatus = "done"
	ScanFailed    ScanStatus = "failed"
	ScanCancelled ScanStatus = "cancelled"
)

// Scan is one execution of a job against a repository. Kind names the job
// ("claude", later "semgrep", "brief", "git-pkgs"). Report holds whatever
// the job considers its primary artefact; Log holds the streamed transcript
// so you can see what happened while it ran.
type Scan struct {
	ID           uint `gorm:"primarykey"`
	RepositoryID uint `gorm:"index;not null"`
	Repository   Repository

	Kind   string     `gorm:"index;not null"`
	Status ScanStatus `gorm:"index;not null"`
	Model  string
	// Effort is the claude `--effort` level snapshotted from the runtime
	// setting (or, on a retry, the source scan) at enqueue, so each scan
	// records the effort it ran at. Empty on rows created before the
	// column existed; the runner falls back to its configured default then.
	Effort string

	// SkillID/SkillVersion are set when Kind is "skill": they pin which
	// skill row and which version of it produced this scan. SkillName is
	// the skill name at time of run so old scans remain readable even if
	// the skill is deleted. APIToken is a random bearer generated per-run
	// so skills can call back into scrutineer's HTTP API from inside the
	// workspace; it is cleared when the scan reaches a terminal state.
	SkillID      *uint `gorm:"index"`
	SkillVersion int
	SkillName    string `gorm:"index"`
	// FindingID is set when a scan is finding-scoped (verify, patch,
	// disclose). Skills read it from context.json to know which finding
	// they are acting on.
	FindingID *uint `gorm:"index"`
	// DependentID is set on exposure scans: the Dependent the skill is
	// auditing for reachability of the upstream finding. The scan's
	// Repository remains the library; ./src is staged from the
	// dependent's repo URL via the dependent-clone cache.
	DependentID *uint  `gorm:"index"`
	APIToken    string `gorm:"index"`

	// StatusPriority is a denormalised sort key so the scans index can use
	// an index instead of evaluating a CASE on every row. 0 = running,
	// 1 = queued, 2 = everything else. Set by StatusPriorityFor().
	StatusPriority int

	// Ref is the git ref (branch, tag, commit) to checkout after cloning.
	// Empty means the repository's default branch (origin/HEAD).
	Ref string

	// SkillsRepoSHA pins which commit of the -skills-repo produced this
	// scan. Resolved once at startup and stamped on every Scan row so two
	// runs a week apart can be told apart even if the upstream branch has
	// moved. Empty when -skills-repo is unset or when the scan kind does
	// not run a remote skill (e.g. "import").
	SkillsRepoSHA string

	// SubPath scopes the scan's code analysis to a sub-folder within the
	// clone (e.g. airflow-core inside apache/airflow). Empty means the
	// repo root. Skills that walk files honour this through
	// scrutineer.scan_subpath in context.json; skills that consult
	// external APIs (packages/advisories/dependents) ignore it.
	SubPath string `gorm:"index"`

	// Profile is the runner profile that ran (or was overridden to run)
	// this scan. Empty means the default runner image; non-empty names
	// a docker/profiles/<name>/ entry. Persisted so retries reuse the
	// operator's override and the UI can show the chosen ecosystem.
	Profile string `gorm:"index"`

	// SessionID is the claude-code session this scan's run belongs to,
	// captured from the stream-json init/result events. It is written as
	// soon as the init event arrives (before the run finishes) so it
	// survives a crash, and cleared once the scan reaches "done" so a
	// deliberate re-run from the UI starts a fresh conversation. A retry
	// of a failed scan carries this value forward so the runner can pass
	// `claude -p --resume <id>` and continue from where it left off
	// instead of restarting from turn 0.
	SessionID string
	// ResumedFromScanID points at the lineage-root scan whose claude session
	// and workspace a retry reuses. Nil on a fresh scan. claude keys its
	// session store by working directory, so a resuming run must execute
	// in the same per-scan workspace path as the original; this pins that
	// path across the whole retry chain. Always the root of the lineage,
	// not the immediate parent, so N retries deep still resolve to one
	// workspace.
	ResumedFromScanID *uint `gorm:"index"`

	Commit     string
	StartedAt  *time.Time
	FinishedAt *time.Time
	CostUSD    float64
	Turns      int
	// Token usage from the claude-code result event. CacheWriteTokens is
	// cache_creation_input_tokens; CacheReadTokens is
	// cache_read_input_tokens. AutoMigrate adds these as zero-default
	// integer columns on existing databases.
	InputTokens      int
	OutputTokens     int
	CacheReadTokens  int
	CacheWriteTokens int

	Prompt string
	Report string
	Log    string
	Error  string

	// ImportPayload carries the raw uploaded report for an ingest-skill
	// run created by the /v1/import fallback. The worker stages it into
	// the workspace at import/report before the skill starts. Empty for
	// every other scan.
	ImportPayload []byte

	FindingsCount int
	Findings      []Finding `gorm:"constraint:OnDelete:CASCADE"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Package is one registry entry from packages.ecosyste.ms linked to this repo.
type Package struct {
	ID           uint `gorm:"primarykey"`
	RepositoryID uint `gorm:"index;not null"`
	Repository   Repository

	Name                 string
	Ecosystem            string `gorm:"index"`
	PURL                 string
	Licenses             string
	LatestVersion        string
	VersionsCount        int
	Downloads            int64 `gorm:"index"`
	DependentPackages    int
	DependentRepos       int `gorm:"index"`
	RegistryURL          string
	LatestReleaseAt      *time.Time
	DependentPackagesURL string
	Metadata             string `gorm:"type:text"`

	CreatedAt time.Time
}

type MaintainerStatus string

const (
	MaintainerActive   MaintainerStatus = "active"
	MaintainerInactive MaintainerStatus = "inactive"
	MaintainerUnknown  MaintainerStatus = "unknown"
)

// Maintainer is a person who maintains one or more repositories. The centre
// of the disclosure CRM: findings batch into conversations per maintainer,
// not per repo.
type Maintainer struct {
	ID        uint   `gorm:"primarykey"`
	Login     string `gorm:"uniqueIndex;not null"` // github username or equivalent
	Name      string
	Email     string
	Company   string
	AvatarURL string
	Status    MaintainerStatus `gorm:"index;default:unknown"`
	Notes     string

	// DoNotContact suppresses this maintainer from disclosure routing.
	// Toggled per-maintainer from the UI. The analyst sets it when the
	// maintainer has asked not to be contacted, or when evidence says
	// routing through them is known to leak. Reports and disclosure
	// drafts omit them when true.
	DoNotContact bool `gorm:"index"`

	Repositories []Repository `gorm:"many2many:repository_maintainers"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

type FindingLifecycle string

const (
	FindingNew          FindingLifecycle = "new"
	FindingEnriched     FindingLifecycle = "enriched"
	FindingTriaged      FindingLifecycle = "triaged"
	FindingReady        FindingLifecycle = "ready"
	FindingReported     FindingLifecycle = "reported"
	FindingAcknowledged FindingLifecycle = "acknowledged"
	FindingFixed        FindingLifecycle = "fixed"
	FindingPublished    FindingLifecycle = "published"
	FindingRejected     FindingLifecycle = "rejected"
	FindingDuplicate    FindingLifecycle = "duplicate"
)

// FindingLifecycles lists every finding status in workflow order. Used to
// render the Status filter on the findings index.
var FindingLifecycles = []FindingLifecycle{
	FindingNew, FindingEnriched, FindingTriaged, FindingReady, FindingReported,
	FindingAcknowledged, FindingFixed, FindingPublished, FindingRejected, FindingDuplicate,
}

// Advisory is a known security advisory from advisories.ecosyste.ms.
type Advisory struct {
	ID           uint `gorm:"primarykey"`
	RepositoryID uint `gorm:"index;not null"`

	UUID           string
	URL            string
	Title          string
	Description    string
	Severity       string `gorm:"index"`
	CVSSScore      float64
	Classification string
	Packages       string     // comma-joined affected package names
	PublishedAt    *time.Time `gorm:"index"`
	WithdrawnAt    *time.Time

	CreatedAt time.Time
}

// Dependent is a package that depends on one of this repo's packages.
// Populated by the dependents job from packages.ecosyste.ms.
type Dependent struct {
	ID           uint `gorm:"primarykey"`
	RepositoryID uint `gorm:"index;not null"`

	Name           string
	Ecosystem      string
	PURL           string
	RepositoryURL  string
	Downloads      int64 `gorm:"index"`
	DependentRepos int   `gorm:"index"`
	RegistryURL    string
	LatestVersion  string

	CreatedAt time.Time
}

// Dependency is one package dependency discovered by the git-pkgs job.
// Rows are replaced wholesale each time the job runs for a repository.
type Dependency struct {
	ID             uint `gorm:"primarykey"`
	RepositoryID   uint `gorm:"index;not null"`
	Name           string
	Ecosystem      string `gorm:"index"`
	PURL           string
	Requirement    string
	DependencyType string
	ManifestPath   string
	ManifestKind   string
	CreatedAt      time.Time
}

// FindingResolution says how a finding got resolved. Set by the analyst
// once disclosure runs its course.
type FindingResolution string

const (
	ResolutionFix        FindingResolution = "fix"
	ResolutionMigrate    FindingResolution = "migrate"
	ResolutionWorkaround FindingResolution = "workaround"
	ResolutionAdopt      FindingResolution = "adopt"
	ResolutionWontfix    FindingResolution = "wontfix"
)

// FindingSource is the provenance of a field value: produced by a
// deterministic tool, suggested by a model-backed skill, or set by the
// analyst. Analyst wins over model wins over tool.
type FindingSource string

const (
	SourceTool    FindingSource = "tool"
	SourceModel   FindingSource = "model_suggested"
	SourceAnalyst FindingSource = "analyst"
)

// Finding is one vulnerability reported by a scan. The Finding row holds
// the current value of every mutable field; FindingHistory records who
// changed each one and from which source. Labels, notes, communications,
// and references are normalised into sibling tables.
type Finding struct {
	ID     uint `gorm:"primarykey"`
	ScanID uint `gorm:"index;not null"`
	Scan   Scan
	// RepositoryID, Commit, and SubPath are denormalized from Scan so list
	// queries don't have to join through Scan (GORM's Preload/Joins on
	// Finding.Scan doesn't round-trip cleanly on sqlite). Set at
	// finding-create time and never changed. RepositoryID is not
	// marked not-null so AutoMigrate can widen the column on existing
	// databases without a default; BackfillFindingRepository fills
	// existing rows on startup.
	RepositoryID uint `gorm:"index;index:idx_findings_repo_fp,priority:1"`
	Commit       string
	SubPath      string `gorm:"index"`

	// Fingerprint dedupes the same vulnerability reported by repeated
	// scans; see FingerprintFinding. ScanID/Commit are first-seen;
	// LastSeenScanID/LastSeenCommit/SeenCount track re-observation. The
	// composite index makes the (repo, fingerprint) lookup at ingest
	// cheap without requiring uniqueness (legacy rows may collide).
	Fingerprint    string `gorm:"index:idx_findings_repo_fp,priority:2"`
	LastSeenScanID uint
	LastSeenCommit string
	SeenCount      int
	// MissedCount/LastMissedScanID track the inverse: consecutive
	// same-skill rescans of this repo+subpath where the fingerprint did
	// NOT reappear. Reset to zero on the next re-observation. A non-zero
	// MissedCount is a hint the finding may have been fixed upstream; it
	// is not proof since model-driven audits are nondeterministic.
	MissedCount      int
	LastMissedScanID uint

	// VID identifies the code being pointed at, not the finding: a hash
	// of the enclosing function (or file) bytes at each sink location,
	// computed by the vid CLI (github.com/andrew/VID) against the scanned
	// checkout. Two parties looking at the same code derive the same VID
	// without coordinating, so it correlates findings across tools and
	// reporters. Refreshed on re-observation so it tracks the code as it
	// drifts; empty when the vid binary was unavailable or no location
	// resolved to a file in the checkout. Unlike Fingerprint it is NOT
	// used for dedup: a VID changes whenever the function's bytes change.
	VID string `gorm:"column:vid;index"`

	FindingID  string // e.g. F1, F2 within the report
	Sinks      string // comma-joined sink IDs
	Title      string
	Severity   string           `gorm:"index"`
	Confidence string           `gorm:"index"` // high/medium/low; how certain the audit is
	Status     FindingLifecycle `gorm:"index;default:new"`
	CWE        string
	Location   string
	// Locations is the newline-joined set of file:line positions for
	// findings that represent one rule firing many times (#191). The
	// first entry is duplicated in Location for the fingerprint and the
	// table-view link; this column carries the full set so the finding
	// page can list every hit. groupByFingerprint always seeds it with
	// the primary, so it is non-empty for any finding written through
	// the parser; rows that predate the column have it empty.
	Locations string `gorm:"type:text"`
	Affected  string // version range
	// Reachability records whether a public entry point in the shipped
	// artefact reaches the sink with attacker-controlled input
	// (reachable), only a test driver does (harness_only), or the audit
	// could not decide (unclear). harness_only findings are real bugs
	// but not disclosable as vulnerabilities.
	Reachability string `gorm:"index"`
	// QualityTier classifies the sink: high (heap overflow, UAF, type
	// confusion, controllable write, shell/eval injection) versus low
	// (stack exhaustion, assertion failure, fixed-offset null deref, log
	// injection). Low-tier hits are signposts to keep looking nearby.
	QualityTier string `gorm:"index"`
	// ImportedFrom names the external producer when the finding arrived
	// via /import (e.g. "CodeQL", "Snyk", "manual"). Empty for findings
	// scrutineer produced itself. Used as the skill-name input to the
	// fingerprint so re-importing the same external report dedupes.
	ImportedFrom string `gorm:"index"`

	// Disclosure / triage fields. Any of these may be set by a tool, a
	// model-backed skill, or the analyst; see FindingHistory for the trail.
	CVEID string
	// CVSSVector is the canonical CVSS v3.x base vector (3.0 or 3.1).
	// CVSSv4Vector is the v4.0 base vector. Both may be populated when
	// the analyst (or the disclose skill) carries both forward, which
	// coordinators like the OSS-SIRT expect; v3.1 stays for legacy
	// pipelines that have not yet adopted v4. Each vector has its own
	// derived base-score column so the two scales do not get mixed up
	// (4.0 changes the metric set and the base-score formula).
	CVSSVector   string
	CVSSScore    float64
	CVSSv4Vector string  `gorm:"column:cvss_v4_vector"`
	CVSSv4Score  float64 `gorm:"column:cvss_v4_score"`
	FixVersion   string
	FixCommit    string
	// ReleasedAt, ReleaseTag, ReleaseURL record the upstream release
	// that first contained the fix. Written by the release-watch skill
	// once `status=fixed`, so the metrics in dora-metrics.md can compute
	// fixed-to-released latency rather than ending the funnel at the
	// commit landing. All three move together: zero/empty until a
	// release is found.
	ReleasedAt      *time.Time
	ReleaseTag      string
	ReleaseURL      string
	Resolution      FindingResolution `gorm:"index"`
	DisclosureDraft string            `gorm:"type:text"`
	Assignee        string            `gorm:"index"`
	// LastRevalidateVerdict caches the latest verdict from the
	// revalidate skill (true_positive | false_positive | already_fixed
	// | uncertain; empty when revalidate has not run) so the audit
	// queue can filter on an indexed column rather than LIKE-scanning
	// finding_notes for the revalidate header.
	LastRevalidateVerdict string `gorm:"index"`
	// SuggestedFix is a unified diff from the patch skill that has passed
	// the applicability gate (parses, targets real files, touches a file
	// named in Location, git apply --check clean). Empty when no patch has
	// run or the gate rejected it. SuggestedFixCommit is the sha it applies to.
	SuggestedFix       string `gorm:"type:text"`
	SuggestedFixCommit string

	// BreakingChange and BreakingChangeRationale are the verdict of the
	// breaking-change skill, which analyses the SuggestedFix diff for
	// public-API changes that would break top dependents. Empty when
	// the skill has not run; one of `breaking`, `non_breaking`, or
	// `unknown` once it has. Rationale is the prose the analyst reads,
	// including a bullet list of affected dependents when the verdict
	// is `breaking`.
	BreakingChange          string `gorm:"index"`
	BreakingChangeRationale string `gorm:"type:text"`

	// ExploitedInWild is the analyst's call on whether this finding is
	// known to be exploited at the time of disclosure. One of `yes`,
	// `no`, or empty (`unknown`). Disclosure coordinators ask for this
	// (the OSS-SIRT intake list includes it) and a `yes` changes triage
	// priority. Automation never sets this column: a model guess at
	// exploitation is worse than no answer. Updates flow through
	// WriteFindingField with source=analyst so the timestamp lives in
	// FindingHistory.
	ExploitedInWild string `gorm:"index"`
	// ExploitedInWildEvidence is the source note for the value above:
	// who reported it, the ticket or article link, what the analyst saw.
	// Free-text; empty when the analyst has not weighed in.
	ExploitedInWildEvidence string `gorm:"type:text"`

	// Mitigation is the body of operational mitigation guidance the
	// `mitigate` skill drafts: workarounds consumers can apply now
	// (config flags, input restrictions, safe defaults), plus detection
	// guidance for what to log and what to alert on while the fix is in
	// flight. Markdown. MitigationSemgrep is the optional semgrep rule
	// the same skill emits when the vulnerable pattern is structural
	// enough to flag reliably; YAML, empty when no rule was warranted.
	Mitigation        string `gorm:"type:text"`
	MitigationSemgrep string `gorm:"type:text"`

	// Per-step prose from the six-step audit checklist.
	Trace      string `gorm:"type:text"`
	Boundary   string `gorm:"type:text"`
	Validation string `gorm:"type:text"`
	PriorArt   string `gorm:"type:text"`
	Reach      string `gorm:"type:text"`
	Rating     string `gorm:"type:text"`

	Labels         []FindingLabel         `gorm:"many2many:finding_labels_join"`
	Notes          []FindingNote          `gorm:"constraint:OnDelete:CASCADE"`
	Communications []FindingCommunication `gorm:"constraint:OnDelete:CASCADE"`
	References     []FindingReference     `gorm:"constraint:OnDelete:CASCADE"`
	History        []FindingHistory       `gorm:"constraint:OnDelete:CASCADE"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Summary gives a one-paragraph digest of the finding: first paragraph of
// Trace when present, else the Title. Kept as a method so templates can
// treat it like any other field without callers recomputing it.
func (f Finding) Summary() string {
	if f.Trace == "" {
		return f.Title
	}
	if i := strings.Index(f.Trace, "\n\n"); i > 0 {
		return f.Trace[:i]
	}
	return f.Trace
}

// LocationList splits the Locations column into its file:line entries.
// Returns nil for single-location findings (Locations empty), so
// templates can range without an explicit emptiness check.
func (f Finding) LocationList() []string {
	if f.Locations == "" {
		return nil
	}
	out := strings.Split(f.Locations, "\n")
	for i := range out {
		out[i] = strings.TrimSpace(out[i])
	}
	return out
}

// ExtraLocationCount is the number of grouped match positions beyond the
// primary one shown in Location. Used by table views to render a "+N"
// badge without unpacking the full list.
func (f Finding) ExtraLocationCount() int {
	n := len(f.LocationList())
	if n <= 1 {
		return 0
	}
	return n - 1
}

// FindingLabel is a tag independent of the lifecycle status. A finding can
// carry multiple labels (wontfix, needs-info, regression, etc.).
type FindingLabel struct {
	ID    uint   `gorm:"primarykey"`
	Name  string `gorm:"uniqueIndex;not null"`
	Color string // CSS hex color for the badge

	CreatedAt time.Time
}

// FindingNote is one timestamped internal analyst note about a finding.
// Replaces the old single Notes column so the comment trail is preserved.
type FindingNote struct {
	ID        uint   `gorm:"primarykey"`
	FindingID uint   `gorm:"index;not null"`
	Body      string `gorm:"type:text"`
	By        string // free-text author; scrutineer is single-user so usually empty

	CreatedAt time.Time
}

// FindingCommunication is one external interaction about a finding: an
// email to the maintainer, an inbound reply, a GHSA submission, etc.
// Kept distinct from FindingNote since the semantics (channel, direction,
// external actor) don't fit a generic note.
type FindingCommunication struct {
	ID        uint   `gorm:"primarykey"`
	FindingID uint   `gorm:"index;not null"`
	Channel   string // email | ghsa | issue | pr | direct | registry
	Direction string // outbound | inbound
	Actor     string // name/handle of the other party
	Body      string `gorm:"type:text"`
	// OfferedHelp (optional): pr | funding | adoption | none.
	// Lets disclosure tracking distinguish "reported a bug" from
	// "reported a bug and offered a PR/funding".
	OfferedHelp string
	At          time.Time

	CreatedAt time.Time
}

// FindingReference is an external URL related to a finding: the upstream
// issue/PR, a CVE or GHSA record, a fix commit, a blog post.
type FindingReference struct {
	ID        uint `gorm:"primarykey"`
	FindingID uint `gorm:"index;not null"`
	URL       string
	// Tags is comma-joined: issue, pr, cve, ghsa, patch, advisory, discussion, article.
	Tags    string
	Summary string

	CreatedAt time.Time
}

// CSAF 2.0 product_status buckets, reused as the FindingDependent.Status
// enum so the VEX export can pass them through without translation.
const (
	ExposureKnownAffected      = "known_affected"
	ExposureKnownNotAffected   = "known_not_affected"
	ExposureUnderInvestigation = "under_investigation"
	ExposureFixed              = "fixed"
)

// CSAF 2.0 VEX flag labels. Only valid when Status is known_not_affected.
const (
	JustifComponentNotPresent        = "component_not_present"
	JustifVulnerableCodeNotPresent   = "vulnerable_code_not_present"
	JustifVulnerableCodeNotInPath    = "vulnerable_code_not_in_execute_path"
	JustifVulnerableCodeNotReachable = "vulnerable_code_cannot_be_controlled_by_adversary"
	JustifInlineMitigationsExist     = "inline_mitigations_already_exist"
)

// ValidExposureStatus reports whether s is one of the CSAF product_status
// buckets FindingDependent stores. Empty is treated as under_investigation
// by the caller; this returns false on empty.
func ValidExposureStatus(s string) bool {
	switch s {
	case ExposureKnownAffected, ExposureKnownNotAffected, ExposureUnderInvestigation, ExposureFixed:
		return true
	}
	return false
}

// ValidExposureJustification reports whether j is one of the CSAF VEX
// flag labels. Empty is valid (no flag attached).
func ValidExposureJustification(j string) bool {
	if j == "" {
		return true
	}
	switch j {
	case JustifComponentNotPresent, JustifVulnerableCodeNotPresent,
		JustifVulnerableCodeNotInPath, JustifVulnerableCodeNotReachable,
		JustifInlineMitigationsExist:
		return true
	}
	return false
}

// FindingDependent records, per (finding, dependent), whether that
// downstream consumer of the vulnerable library reaches the sink. Status
// mirrors the CSAF 2.0 product_status bucket so the VEX export can stream
// it through unchanged; Justification holds a CSAF VEX flag label and is
// only set when Status is known_not_affected. ScanCommit is the dependent
// repo HEAD when the call was made so a later rescan can tell whether
// the answer is still valid.
type FindingDependent struct {
	ID          uint `gorm:"primarykey"`
	FindingID   uint `gorm:"index;not null;uniqueIndex:idx_finding_dependent"`
	DependentID uint `gorm:"index;not null;uniqueIndex:idx_finding_dependent"`

	Status        string `gorm:"index"` // known_affected | known_not_affected | under_investigation | fixed
	Justification string // CSAF VEX flag label, only for known_not_affected
	Rationale     string `gorm:"type:text"`

	ScanID     *uint
	ScanCommit string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// FindingHistory records every change to a mutable field on a Finding.
// Together with the Finding row's current columns it gives you "what is
// the current value, who set it, from what source, and when".
type FindingHistory struct {
	ID        uint          `gorm:"primarykey"`
	FindingID uint          `gorm:"index;not null"`
	Field     string        `gorm:"index"` // e.g. severity, cvss_vector, status
	OldValue  string        `gorm:"type:text"`
	NewValue  string        `gorm:"type:text"`
	Source    FindingSource `gorm:"index"`
	By        string        // free text, or the skill name for model_suggested writes

	CreatedAt time.Time
}

// FindingReview is a structured human verdict against an automation
// outcome. Verdict mirrors the revalidate skill's enum so reviewer
// agreement with the model can be measured directly. AutomatedOutcome
// snapshots what the automation said about this finding at the moment
// of review (typically the last revalidate verdict; empty when no
// automation has spoken yet). This is the data behind the audit queue
// in internal/web/audit.go: surfacing recently auto-bucketed findings
// without lasting marks of human review, so the TOC can confirm the
// automation is calibrated and so the agreement rate is computable.
type FindingReview struct {
	ID        uint   `gorm:"primarykey"`
	FindingID uint   `gorm:"index;not null"`
	Verdict   string `gorm:"index"` // true_positive | false_positive | already_fixed | uncertain
	Reason    string `gorm:"type:text"`
	// AutomatedOutcome is the automation verdict (revalidate's) the
	// human is judging. Empty when revalidate has not run on this
	// finding; agreement metrics ignore reviews with empty automated
	// outcomes since there is nothing to compare to.
	AutomatedOutcome string `gorm:"index"`
	Reviewer         string

	CreatedAt time.Time
}

// Skill is one scan recipe expressed as a claude-code skill. It maps 1:1 to
// the agentskills.io SKILL.md format: Body is the markdown that sits after
// the frontmatter, the other fields are frontmatter. Metadata holds the raw
// YAML map serialised as JSON so we do not lose scrutineer-specific keys
// (scrutineer.output_file, scrutineer.output_schema, scrutineer.output_kind,
// scrutineer.max_turns, scrutineer.model).
//
// Skills loaded from a local directory or git repo have Source set; skills
// created in the UI have Source="ui". Version bumps on every save so old
// scans can point at the exact version they used.
type Skill struct {
	ID uint `gorm:"primarykey"`

	Name          string `gorm:"uniqueIndex;not null"`
	Description   string
	License       string
	Compatibility string
	AllowedTools  string
	Metadata      string `gorm:"type:text"` // raw frontmatter metadata map as JSON

	Body       string `gorm:"type:text"` // markdown body after frontmatter
	SchemaJSON string `gorm:"type:text"` // optional schema.json contents
	OutputFile string // from metadata["scrutineer.output_file"]
	OutputKind string `gorm:"index"` // from metadata["scrutineer.output_kind"]
	MaxTurns   int    // from metadata["scrutineer.max_turns"]
	Model      string // from metadata["scrutineer.model"]; empty = use scan/server default
	// Thresholds: MinConfidence drops findings below the given confidence
	// before they are written; FailOn marks the scan failed if any
	// finding's severity is at or above it; ReportOn is the default
	// severity floor for the repo findings tab. All optional.
	MinConfidence string
	ReportOn      string
	FailOn        string

	Version int  `gorm:"not null;default:1"`
	Active  bool `gorm:"not null;default:true"`

	// RequiresRemote opts a skill out of running on local-directory
	// repositories (file:// URLs). Set via the SKILL.md frontmatter key
	// `scrutineer.requires_remote: true` on skills that need a forge URL
	// or remote-only data (fork, exposure, ecosyste.ms enrichment).
	// Default false so newly added skills work on local scans unless they
	// declare otherwise.
	RequiresRemote bool

	// RequiresProfile constrains the skill to a single registered runner
	// profile (e.g. "php"). Set via `scrutineer.requires_profile` in the
	// SKILL.md frontmatter. Empty means no constraint; any other value
	// must match a profile registered in worker.builtinProfiles. Enqueue
	// rejects mismatched overrides with 400; the worker fails the scan if
	// auto-detection resolves to a different profile.
	RequiresProfile string

	// Paths and IgnorePaths are newline-joined shell-glob patterns from
	// scrutineer.paths / scrutineer.ignore_paths in the frontmatter. When
	// Paths is non-empty the skill sees only files matching one of its
	// patterns and the builtin skip list is bypassed; IgnorePaths is
	// always applied on top. See internal/skills.PathIncluded.
	Paths       string `gorm:"type:text"`
	IgnorePaths string `gorm:"type:text"`

	Source     string // "local" | "remote" | "ui"
	SourcePath string // directory on disk (local/remote) or empty (ui)
	SourceHash string // sha256 of SKILL.md + schema.json contents

	CreatedAt time.Time
	UpdatedAt time.Time
}

func (s Scan) Duration() time.Duration {
	if s.StartedAt == nil || s.FinishedAt == nil {
		return 0
	}
	return s.FinishedAt.Sub(*s.StartedAt)
}

// TotalInputTokens is everything billed on the input side: fresh input plus
// both cache categories.
func (s Scan) TotalInputTokens() int {
	return s.InputTokens + s.CacheReadTokens + s.CacheWriteTokens
}

// CacheHitRatio is the share of total input tokens served from the prompt
// cache. 0 when nothing has been recorded.
func (s Scan) CacheHitRatio() float64 {
	total := s.TotalInputTokens()
	if total == 0 {
		return 0
	}
	return float64(s.CacheReadTokens) / float64(total)
}

// HasExportableReport tells the UI whether to offer a "download as
// markdown" button for this scan. A scan that has produced findings is
// always worth exporting. Otherwise we parse the report and look for any
// substantive content: at least one top-level value that isn't an empty
// string, empty array, empty object, or null. That lets through real
// reports of any size — a single-package result is just as worth
// exporting as a 10K-line SBOM — while filtering out structurally
// empty scans like {"subprojects": []} or {"packages": [], "advisories":
// []}. For non-JSON-object reports (bare array, plain text, malformed
// JSON) we accept anything past a small trimmed length so freeform skills
// emitting non-object output aren't accidentally hidden. The
// /scans/{id}/report.md route is unaffected and remains reachable by
// URL regardless of this signal.
func (s Scan) HasExportableReport() bool {
	// nonObjectReportMinLen is the trimmed-length floor below which a
	// non-JSON-object report (bare array, plain text, malformed JSON) is
	// treated as too thin to bother exporting. JSON-object reports get
	// the structural check instead and ignore this.
	const nonObjectReportMinLen = 20
	if s.FindingsCount > 0 {
		return true
	}
	raw := strings.TrimSpace(s.Report)
	if raw == "" {
		return false
	}
	var top map[string]any
	if err := json.Unmarshal([]byte(raw), &top); err == nil {
		for _, v := range top {
			if !isEmptyJSONValue(v) {
				return true
			}
		}
		return false
	}
	return len(raw) > nonObjectReportMinLen
}

// isEmptyJSONValue returns true for the JSON values that carry no
// information — "", [], {}, null. Numbers and booleans are always
// counted as content, on the theory that a skill bothering to emit
// "version": 1 had a reason to.
func isEmptyJSONValue(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	default:
		return false
	}
}

func (s ScanStatus) Terminal() bool {
	return s == ScanDone || s == ScanFailed || s == ScanCancelled
}

const (
	scanPriorityRunning = iota
	scanPriorityQueued
	scanPriorityPaused
	scanPriorityTerminal
)

func StatusPriorityFor(s ScanStatus) int {
	switch s {
	case ScanRunning:
		return scanPriorityRunning
	case ScanQueued:
		return scanPriorityQueued
	case ScanPaused:
		return scanPriorityPaused
	default:
		return scanPriorityTerminal
	}
}

func Open(dsn string) (*gorm.DB, error) {
	cfg := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	}
	gdb, err := gorm.Open(sqlite.Open(dsn), cfg)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// WAL so the web server can read while the worker writes.
	if err := gdb.Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;").Error; err != nil {
		return nil, fmt.Errorf("pragma: %w", err)
	}
	if err := gdb.AutoMigrate(
		&Repository{}, &Scan{},
		&Finding{}, &FindingLabel{}, &FindingNote{},
		&FindingCommunication{}, &FindingReference{}, &FindingHistory{}, &FindingReview{},
		&Dependency{}, &Package{}, &Dependent{}, &FindingDependent{}, &Advisory{},
		&Maintainer{}, &Skill{}, &Subproject{},
		&SBOMUpload{}, &SBOMPackage{}, &CNA{}, &Setting{},
	); err != nil {
		return nil, fmt.Errorf("automigrate: %w", err)
	}
	gdb.Exec(`CREATE INDEX IF NOT EXISTS idx_scans_priority_id ON scans (status_priority, id DESC)`)
	return gdb, nil
}

// Snapshot writes a consistent copy of the SQLite database at src to dest
// using VACUUM INTO. Unlike Open it neither migrates nor otherwise writes to
// src, so a backup never mutates the live database, and it takes only a read
// lock so it is safe to run while scrutineer is serving. WAL frames not yet
// checkpointed are included, so the snapshot is complete even mid-scan.
//
// dest must not already exist: the modernc driver's VACUUM INTO overwrites a
// target file rather than refusing it (unlike upstream SQLite), which would
// leave trailing bytes from a larger prior file, so Snapshot guards the case
// itself. The parent directory of dest must exist.
func Snapshot(src, dest string) error {
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("destination already exists: %s", dest)
	}
	gdb, err := gorm.Open(sqlite.Open(src), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	sqldb, err := gdb.DB()
	if err != nil {
		return err
	}
	defer func() { _ = sqldb.Close() }()
	// Pin one connection so the busy_timeout pragma and VACUUM INTO share it
	// (a pooled Exec could otherwise land the VACUUM on a connection without
	// the pragma). The timeout matches Open so a snapshot taken while the
	// server writes waits out a transient lock (e.g. a checkpoint) rather
	// than failing with SQLITE_BUSY.
	ctx := context.Background()
	conn, err := sqldb.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
		return fmt.Errorf("pragma: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "VACUUM INTO ?", dest); err != nil {
		return fmt.Errorf("vacuum into %s: %w", dest, err)
	}
	return nil
}

// SBOMUpload is one CycloneDX or SPDX document a user uploaded. Packages
// are replaced wholesale on re-upload (cascade delete) but the resolved
// Repository rows survive so prior scan results stay attached.
type SBOMUpload struct {
	ID uint `gorm:"primarykey"`

	Name        string
	Filename    string
	Format      string
	SpecVersion string
	Raw         []byte

	PackageCount int
	Packages     []SBOMPackage `gorm:"constraint:OnDelete:CASCADE"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

// SBOMPackage is one component listed in an upload. RepositoryID is set
// asynchronously once the PURL has been resolved to a source repo and the
// triage scan enqueued; until then it is nil.
type SBOMPackage struct {
	ID           uint `gorm:"primarykey"`
	SBOMUploadID uint `gorm:"index;not null"`

	Name      string
	Version   string
	PURL      string `gorm:"index"`
	Ecosystem string
	License   string
	// Scope is "direct" when the SBOM's dependency graph lists this
	// package as a dependency of the root component, "transitive" when it
	// only appears via another package, and "" when the document had no
	// dependency graph to derive it from.
	Scope string `gorm:"index"`

	RepositoryID *uint `gorm:"index"`
	Repository   *Repository
	ResolveError string

	CreatedAt time.Time
}

// CNA is a CVE Numbering Authority from the public cve.org partner list.
// Stored so the disclosure workflow can route a finding to the CNA whose
// scope covers the project rather than (or in addition to) the maintainer.
// Scope is the free-text coverage description as published; matching a
// repo to a CNA is left to a skill since scopes are prose, not patterns.
type CNA struct {
	ID uint `gorm:"primarykey"`

	ShortName    string `gorm:"uniqueIndex;not null"`
	CNAID        string `gorm:"index"`
	Organization string
	Scope        string `gorm:"type:text"`
	Email        string
	ContactURL   string
	PolicyURL    string
	AdvisoryURL  string
	Root         string
	Types        string
	Country      string
	Metadata     string `gorm:"type:text"`

	FetchedAt *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Subproject is a scannable unit the subprojects skill discovered inside
// a repository. One Repository has many Subprojects; each Scan may refer
// to one of them through Scan.SubPath. Rows are rewritten in full when
// the subprojects skill re-runs, mirroring Package/Advisory semantics.
type Subproject struct {
	ID           uint `gorm:"primarykey"`
	RepositoryID uint `gorm:"index;not null"`

	// Path is the sub-folder within the clone, relative to root. Empty
	// is not allowed — the root case is represented by absence of any
	// Subproject row, not by a Subproject with Path "".
	Path string `gorm:"not null"`
	// Name is a short human label ("airflow-core", "cli", ...). Falls
	// back to the last segment of Path when the skill cannot infer one.
	Name string
	// Kind is the detected flavour: go-module, npm-workspace,
	// python-package, rust-crate, composer-package, monorepo-root, etc.
	// Free-form — the UI just renders it as a badge.
	Kind        string `gorm:"index"`
	Description string `gorm:"type:text"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

func BackfillStatusPriority(gdb *gorm.DB) {
	gdb.Exec(`UPDATE scans SET status_priority = 0 WHERE status = 'running' AND (status_priority IS NULL OR status_priority != 0)`)
	gdb.Exec(`UPDATE scans SET status_priority = 1 WHERE status = 'queued' AND (status_priority IS NULL OR status_priority != 1)`)
	gdb.Exec(`UPDATE scans SET status_priority = 2 WHERE status = 'paused' AND (status_priority IS NULL OR status_priority != 2)`)
	gdb.Exec(`UPDATE scans SET status_priority = 3 WHERE status NOT IN ('running', 'queued', 'paused') AND (status_priority IS NULL OR status_priority != 3)`)
}

// BackfillFindingRepository copies Scan.RepositoryID onto Finding rows
// whose RepositoryID column is still zero. Used on first boot after
// adding the denormalized column so existing findings pick up their repo.
func BackfillFindingRepository(gdb *gorm.DB) {
	gdb.Exec(`
		UPDATE findings
		SET repository_id = (
			SELECT repository_id FROM scans WHERE scans.id = findings.scan_id
		)
		WHERE (repository_id IS NULL OR repository_id = 0)
	`)
	gdb.Exec(`
		UPDATE findings
		SET "commit" = (
			SELECT "commit" FROM scans WHERE scans.id = findings.scan_id
		)
		WHERE "commit" IS NULL OR "commit" = ''
	`)
}

// BackfillFindings re-parses stored report JSON to fill columns that were
// added after the findings were originally created. Safe to call repeatedly;
// only touches rows with empty values.
func BackfillFindings(gdb *gorm.DB) {
	var scans []Scan
	gdb.Where("kind = 'claude' AND status = 'done' AND report != ''").Find(&scans)
	for _, s := range scans {
		var report struct {
			Findings []struct {
				ID    string   `json:"id"`
				Sinks []string `json:"sinks"`
			} `json:"findings"`
		}
		if json.Unmarshal([]byte(s.Report), &report) != nil {
			continue
		}
		for _, f := range report.Findings {
			sinks := strings.Join(f.Sinks, ", ")
			if sinks != "" {
				gdb.Model(&Finding{}).
					Where("scan_id = ? AND finding_id = ? AND (sinks = '' OR sinks IS NULL)", s.ID, f.ID).
					Update("sinks", sinks)
			}
		}
	}
}

// SweepRunning marks any scans still flagged running as failed. Call once at
// startup: a running row with no worker attached means the previous process
// died mid-job and the UI would otherwise show a spinner forever.
func SweepRunning(gdb *gorm.DB) error {
	return gdb.Model(&Scan{}).
		Where("status = ?", ScanRunning).
		Updates(map[string]any{
			"status":      ScanFailed,
			"error":       "server restarted during run",
			"finished_at": new(time.Now()),
		}).Error
}
