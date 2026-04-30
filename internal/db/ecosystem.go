package db

import "gorm.io/gorm"

// dependencyEcosystemAlias maps git-pkgs ecosystem names (as stored on
// Dependency rows) to packages.ecosyste.ms registry names (as stored on
// Package rows). The two sources disagree for a handful of registries; the
// join in DependencyFindings needs them to agree.
var dependencyEcosystemAlias = map[string]string{
	"gem":            "rubygems",
	"golang":         "go",
	"composer":       "packagist",
	"github-actions": "actions",
	"brew":           "homebrew",
	"swift":          "swiftpm",
	"nix":            "nixpkgs",
}

func CanonicalEcosystem(dep string) string {
	if v, ok := dependencyEcosystemAlias[dep]; ok {
		return v
	}
	return dep
}

// DependencyFinding is one finding on a library that the given application
// depends on. Returned by DependencyFindings; consumed by the reachability
// skill via the /repositories/{id}/dependency-findings API.
type DependencyFinding struct {
	Package        string `json:"package"`
	Ecosystem      string `json:"ecosystem"`
	Requirement    string `json:"requirement"`
	ManifestPath   string `json:"manifest_path"`
	DependencyType string `json:"dependency_type"`

	FindingID  uint             `json:"finding_id"`
	LibRepoID  uint             `json:"library_repository_id"`
	LibRepoURL string           `json:"library_repository_url"`
	Title      string           `json:"title"`
	Severity   string           `json:"severity"`
	CWE        string           `json:"cwe"`
	Location   string           `json:"location"`
	Sinks      string           `json:"sinks"`
	Status     FindingLifecycle `json:"status"`
	Trace      string           `json:"trace"`
	Boundary   string           `json:"boundary"`
}

// DependencyFindings joins an application repository's Dependency rows
// against every Package row in the database (any repository) and returns
// the live Findings on the matched library repositories. Self-matches and
// findings already marked fixed/rejected/duplicate are excluded.
func DependencyFindings(g *gorm.DB, appRepoID uint) ([]DependencyFinding, error) {
	var deps []Dependency
	if err := g.Where("repository_id = ?", appRepoID).Find(&deps).Error; err != nil {
		return nil, err
	}

	type key struct{ name, eco string }
	want := map[key]Dependency{}
	for _, d := range deps {
		k := key{d.Name, CanonicalEcosystem(d.Ecosystem)}
		if cur, ok := want[k]; !ok || preferDep(d, cur) {
			want[k] = d
		}
	}
	if len(want) == 0 {
		return []DependencyFinding{}, nil
	}

	type pkgRow struct {
		Name          string
		Ecosystem     string
		RepositoryID  uint
		RepositoryURL string
	}
	var pkgs []pkgRow
	if err := g.Table("packages").
		Select("packages.name, packages.ecosystem, packages.repository_id, repositories.url AS repository_url").
		Joins("JOIN repositories ON repositories.id = packages.repository_id").
		Where("packages.repository_id <> ?", appRepoID).
		Scan(&pkgs).Error; err != nil {
		return nil, err
	}

	libDeps := map[uint]DependencyFinding{}
	for _, p := range pkgs {
		d, ok := want[key{p.Name, p.Ecosystem}]
		if !ok {
			continue
		}
		libDeps[p.RepositoryID] = DependencyFinding{
			Package:        p.Name,
			Ecosystem:      p.Ecosystem,
			Requirement:    d.Requirement,
			ManifestPath:   d.ManifestPath,
			DependencyType: d.DependencyType,
			LibRepoID:      p.RepositoryID,
			LibRepoURL:     p.RepositoryURL,
		}
	}
	if len(libDeps) == 0 {
		return []DependencyFinding{}, nil
	}

	libIDs := make([]uint, 0, len(libDeps))
	for id := range libDeps {
		libIDs = append(libIDs, id)
	}
	var findings []Finding
	if err := g.Where("repository_id IN ?", libIDs).
		Where("status NOT IN ?", []FindingLifecycle{FindingFixed, FindingRejected, FindingDuplicate}).
		Order("CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, repository_id").
		Find(&findings).Error; err != nil {
		return nil, err
	}

	out := make([]DependencyFinding, 0, len(findings))
	for _, f := range findings {
		base := libDeps[f.RepositoryID]
		base.FindingID = f.ID
		base.Title = f.Title
		base.Severity = f.Severity
		base.CWE = f.CWE
		base.Location = f.Location
		base.Sinks = f.Sinks
		base.Status = f.Status
		base.Trace = f.Trace
		base.Boundary = f.Boundary
		out = append(out, base)
	}
	return out, nil
}

// preferDep picks the more informative of two Dependency rows for the same
// package: a lockfile row (concrete requirement) beats a manifest row, and
// a runtime dependency beats a development one.
func preferDep(a, b Dependency) bool {
	const runtime = "runtime"
	aRT, bRT := a.DependencyType == runtime, b.DependencyType == runtime
	if aRT != bRT {
		return aRT
	}
	return a.ManifestKind == "lockfile" && b.ManifestKind != "lockfile"
}
