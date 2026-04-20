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

	"gorm.io/driver/sqlite"
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
	Stars         int
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
	// the skill is deleted.
	SkillID      *uint `gorm:"index"`
	SkillVersion int
	SkillName    string

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
	Downloads             int64
	DependentPackages     int
	DependentRepos        int
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
	PublishedAt    *time.Time
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
	Downloads      int64
	DependentRepos int
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

// Finding is one vulnerability reported by a claude scan. Rows are created
// by parsing report.json against the schema in worker/schema.json; the
// columns mirror that schema so the two stay easy to diff.
type Finding struct {
	ID     uint `gorm:"primarykey"`
	ScanID uint `gorm:"index;not null"`
	Scan   Scan

	FindingID string // e.g. F1, F2 within the report
	Sinks     string // comma-joined sink IDs, e.g. "S9, S25, S26"
	Title     string
	Severity  string      `gorm:"index"`
	Status    FindingLifecycle `gorm:"index;default:new"`
	CWE       string
	Location  string
	Affected  string // version range
	Notes     string `gorm:"type:text"`

	// Per-step prose from the six-step checklist
	Trace      string `gorm:"type:text"`
	Boundary   string `gorm:"type:text"` // step 2 analysis
	Validation string `gorm:"type:text"` // step 3 reproduction
	PriorArt   string `gorm:"type:text"`
	Reach      string `gorm:"type:text"`
	Rating     string `gorm:"type:text"` // step 6 severity justification

	// Legacy fields for backward compat with old schema reports
	Confidence string
	Summary    string
	Details    string

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
	if err := gdb.AutoMigrate(&Repository{}, &Scan{}, &Finding{}, &Dependency{}, &Package{}, &Dependent{}, &Advisory{}, &Maintainer{}, &Skill{}); err != nil {
		return nil, fmt.Errorf("automigrate: %w", err)
	}
	return gdb, nil
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
