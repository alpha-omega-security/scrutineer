package db

import (
	"strings"

	"github.com/git-pkgs/purl"
	"gorm.io/gorm"
)

// sourceEcosystemAlias rewrites the ecosystem spellings that purl's namespace
// logic does not recognise to the git-pkgs spellings it does. Two cases need
// it: packages.ecosyste.ms emits "actions"/"homebrew"/"swiftpm"/"nixpkgs" (and
// its upstream PURL is stored verbatim) where git-pkgs emits "github-actions"/
// "brew"/"swift"/"nix"; and a row's own stored type is the canonical
// "githubactions", which purl.MakePURL only namespace-splits under the
// hyphenated "github-actions". Reconciling first lets both sources collapse to
// one PURL type and lets the no-PURL fallback split owner/repo, so the join
// still matches a github-actions counterpart that carries a PURL (issue #255).
var sourceEcosystemAlias = map[string]string{
	"actions":       "github-actions",
	"githubactions": "github-actions",
	"homebrew":      "brew",
	"swiftpm":       "swift",
	"nixpkgs":       "nix",
}

func reconcileEcosystem(ecosystem string) string {
	if alias, ok := sourceEcosystemAlias[strings.ToLower(ecosystem)]; ok {
		return alias
	}
	return ecosystem
}

// canonicalType reduces a PURL type or ecosystem string to the one PURL type
// both sources agree on.
func canonicalType(token string) string {
	return purl.EcosystemToPURLType(reconcileEcosystem(token))
}

// ecosystemKey derives the (type, namespace, name) join key for a row. The PURL
// is authoritative; when absent the key is rebuilt by constructing the PURL the
// row would carry and parsing it, so a no-PURL row keys identically to a
// counterpart that has one: same namespace split, same case-folding.
func ecosystemKey(purlStr, ecosystem, name string) (eco, namespace, pkg string) {
	if p, err := purl.Parse(purlStr); err == nil {
		return canonicalType(p.Type), p.Namespace, p.Name
	}
	built := purl.MakePURL(reconcileEcosystem(ecosystem), name, "")
	if p, err := purl.Parse(built.String()); err == nil {
		return canonicalType(p.Type), p.Namespace, p.Name
	}
	// MakePURL produced an invalid PURL: a namespace-required type whose
	// path-like name it does not split (swift). Split on the last separator the
	// way purl.Parse splits a path namespace; if there is none, keep it whole.
	if i := strings.LastIndex(name, "/"); i > 0 {
		return canonicalType(built.Type), name[:i], name[i+1:]
	}
	return canonicalType(built.Type), built.Namespace, built.Name
}

// EcosystemType returns the canonical PURL-type ecosystem to store on Package
// and Dependency rows: the parsed PURL type when present, else the declared
// ecosystem string normalised to its PURL type.
func EcosystemType(purlStr, ecosystem string) string {
	eco, _, _ := ecosystemKey(purlStr, ecosystem, "")
	return eco
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
// the live Findings on the matched library repositories. The join key is the
// parsed PURL (type, namespace, name) on both sides, so the two sources agree
// without a write-time alias map. Self-matches and findings already marked
// fixed/rejected/duplicate are excluded.
func DependencyFindings(g *gorm.DB, appRepoID uint) ([]DependencyFinding, error) {
	var deps []Dependency
	if err := g.Where("repository_id = ?", appRepoID).Find(&deps).Error; err != nil {
		return nil, err
	}

	type key struct{ eco, namespace, name string }
	want := map[key]Dependency{}
	for _, d := range deps {
		eco, ns, name := ecosystemKey(d.PURL, d.Ecosystem, d.Name)
		k := key{eco, ns, name}
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
		PURL          string
		RepositoryID  uint
		RepositoryURL string
	}
	var pkgs []pkgRow
	if err := g.Table("packages").
		Select("packages.name, packages.ecosystem, packages.p_url, packages.repository_id, repositories.url AS repository_url").
		Joins("JOIN repositories ON repositories.id = packages.repository_id").
		Where("packages.repository_id <> ?", appRepoID).
		Scan(&pkgs).Error; err != nil {
		return nil, err
	}

	libDeps := map[uint]DependencyFinding{}
	for _, p := range pkgs {
		eco, ns, name := ecosystemKey(p.PURL, p.Ecosystem, p.Name)
		d, ok := want[key{eco, ns, name}]
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
