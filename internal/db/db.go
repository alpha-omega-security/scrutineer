// Package db holds GORM setup and the persistent models.
//
// SQLite is the default backend. GORM speaks PostgreSQL with a one-line
// driver swap (gorm.io/driver/postgres) and the schema below uses nothing
// SQLite-specific, so the migration path is "change the Open call".
package db

import (
	"encoding/json"
	"fmt"
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

	CreatedAt time.Time
	UpdatedAt time.Time

	Scans       []Scan       `gorm:"constraint:OnDelete:CASCADE"`
	Maintainers []Maintainer `gorm:"many2many:repository_maintainers"`
}

type ScanStatus string

const (
	ScanQueued  ScanStatus = "queued"
	ScanRunning ScanStatus = "running"
	ScanDone    ScanStatus = "done"
	ScanFailed  ScanStatus = "failed"
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

	// SkillID/SkillVersion are set when Kind is "skill": they pin which
	// skill row and which version of it produced this scan. SkillName is
	// the skill name at time of run so old scans remain readable even if
	// the skill is deleted. APIToken is a random bearer generated per-run
	// so skills can call back into scrutineer's HTTP API from inside the
	// workspace; it is cleared when the scan reaches a terminal state.
	SkillID      *uint `gorm:"index"`
	SkillVersion int
	SkillName    string
	// FindingID is set when a scan is finding-scoped (verify, patch,
	// disclose). Skills read it from context.json to know which finding
	// they are acting on.
	FindingID *uint  `gorm:"index"`
	APIToken  string `gorm:"index"`

	// SubPath scopes the scan's code analysis to a sub-folder within the
	// clone (e.g. airflow-core inside apache/airflow). Empty means the
	// repo root. Skills that walk files honour this through
	// scrutineer.scan_subpath in context.json; skills that consult
	// external APIs (packages/advisories/dependents) ignore it.
	SubPath string `gorm:"index"`

	Commit     string
	StartedAt  *time.Time
	FinishedAt *time.Time
	CostUSD    float64
	Turns      int

	Prompt string
	Report string
	Log    string
	Error  string

	FindingsCount int
	Findings      []Finding `gorm:"constraint:OnDelete:CASCADE"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Package is one registry entry from packages.ecosyste.ms linked to this repo.
type Package struct {
	ID           uint       `gorm:"primarykey"`
	RepositoryID uint       `gorm:"index;not null"`
	Repository   Repository

	Name                  string
	Ecosystem             string `gorm:"index"`
	PURL                  string
	Licenses              string
	LatestVersion         string
	VersionsCount         int
	Downloads             int64 `gorm:"index"`
	DependentPackages     int
	DependentRepos        int   `gorm:"index"`
	RegistryURL           string
	LatestReleaseAt       *time.Time
	DependentPackagesURL string
	Metadata             string `gorm:"type:text"`

	CreatedAt time.Time
}

type MaintainerStatus string

const (
	MaintainerActive  MaintainerStatus = "active"
	MaintainerInactive MaintainerStatus = "inactive"
	MaintainerUnknown  MaintainerStatus = "unknown"
)

// Maintainer is a person who maintains one or more repositories. The centre
// of the disclosure CRM: findings batch into conversations per maintainer,
// not per repo.
type Maintainer struct {
	ID     uint   `gorm:"primarykey"`
	Login  string `gorm:"uniqueIndex;not null"` // github username or equivalent
	Name   string
	Email  string
	Company string
	AvatarURL string
	Status MaintainerStatus `gorm:"index;default:unknown"`
	Notes  string

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
	Packages       string // comma-joined affected package names
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
	SourceTool     FindingSource = "tool"
	SourceModel    FindingSource = "model_suggested"
	SourceAnalyst  FindingSource = "analyst"
)

// Finding is one vulnerability reported by a scan. The Finding row holds
// the current value of every mutable field; FindingHistory records who
// changed each one and from which source. Labels, notes, communications,
// and references are normalised into sibling tables.
type Finding struct {
	ID           uint `gorm:"primarykey"`
	ScanID       uint `gorm:"index;not null"`
	Scan         Scan
	// RepositoryID, Commit, and SubPath are denormalized from Scan so list
	// queries don't have to join through Scan (GORM's Preload/Joins on
	// Finding.Scan doesn't round-trip cleanly on sqlite). Set at
	// finding-create time and never changed. RepositoryID is not
	// marked not-null so AutoMigrate can widen the column on existing
	// databases without a default; BackfillFindingRepository fills
	// existing rows on startup.
	RepositoryID uint `gorm:"index"`
	Commit       string
	SubPath      string `gorm:"index"`

	FindingID string // e.g. F1, F2 within the report
	Sinks     string // comma-joined sink IDs
	Title     string
	Severity  string           `gorm:"index"`
	Status    FindingLifecycle `gorm:"index;default:new"`
	CWE       string
	Location  string
	Affected  string // version range

	// Disclosure / triage fields. Any of these may be set by a tool, a
	// model-backed skill, or the analyst; see FindingHistory for the trail.
	CVEID           string
	CVSSVector      string
	CVSSScore       float64
	FixVersion      string
	FixCommit       string
	Resolution      FindingResolution `gorm:"index"`
	DisclosureDraft string            `gorm:"type:text"`
	Assignee        string            `gorm:"index"`

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
	ID        uint `gorm:"primarykey"`
	FindingID uint `gorm:"index;not null"`
	Body      string `gorm:"type:text"`
	By        string // free-text author; scrutineer is single-user so usually empty

	CreatedAt time.Time
}

// FindingCommunication is one external interaction about a finding: an
// email to the maintainer, an inbound reply, a GHSA submission, etc.
// Kept distinct from FindingNote since the semantics (channel, direction,
// external actor) don't fit a generic note.
type FindingCommunication struct {
	ID        uint `gorm:"primarykey"`
	FindingID uint `gorm:"index;not null"`
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

// Skill is one scan recipe expressed as a claude-code skill. It maps 1:1 to
// the agentskills.io SKILL.md format: Body is the markdown that sits after
// the frontmatter, the other fields are frontmatter. Metadata holds the raw
// YAML map serialised as JSON so we do not lose scrutineer-specific keys
// (scrutineer.output_file, scrutineer.output_schema, scrutineer.output_kind).
//
// Skills loaded from a local directory or git repo have Source set; skills
// created in the UI have Source="ui". Version bumps on every save so old
// scans can point at the exact version they used.
type Skill struct {
	ID uint `gorm:"primarykey"`

	Name        string `gorm:"uniqueIndex;not null"`
	Description string
	License     string
	Compatibility string
	AllowedTools  string
	Metadata      string `gorm:"type:text"` // raw frontmatter metadata map as JSON

	Body       string `gorm:"type:text"` // markdown body after frontmatter
	SchemaJSON string `gorm:"type:text"` // optional schema.json contents
	OutputFile string                   // from metadata["scrutineer.output_file"]
	OutputKind string `gorm:"index"`     // from metadata["scrutineer.output_kind"]

	Version int  `gorm:"not null;default:1"`
	Active  bool `gorm:"not null;default:true"`

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

func (s ScanStatus) Terminal() bool {
	return s == ScanDone || s == ScanFailed
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
		&FindingCommunication{}, &FindingReference{}, &FindingHistory{},
		&Dependency{}, &Package{}, &Dependent{}, &Advisory{},
		&Maintainer{}, &Skill{}, &Subproject{},
	); err != nil {
		return nil, fmt.Errorf("automigrate: %w", err)
	}
	return gdb, nil
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
	now := time.Now()
	return gdb.Model(&Scan{}).
		Where("status = ?", ScanRunning).
		Updates(map[string]any{
			"status":      ScanFailed,
			"error":       "server restarted during run",
			"finished_at": &now,
		}).Error
}

// NameFromURL derives a short display name from a git URL. It is the last
// non-empty path segment with a trailing .git stripped.
func NameFromURL(u string) string {
	u = strings.TrimSpace(u)
	u = strings.TrimSuffix(u, "/")
	u = strings.TrimSuffix(u, ".git")
	if i := strings.LastIndexAny(u, "/:"); i >= 0 {
		u = u[i+1:]
	}
	if u == "" {
		return "repo"
	}
	return u
}
