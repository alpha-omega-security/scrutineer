// Tool-based job handlers. Each follows the same shape: ensure clone (if
// needed), run tool, return output as the report string. The wrap() in
// worker.go handles status transitions, log capture and error recording.
package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"scrutineer/internal/db"
)

type pkgMaintainer struct {
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type pkgEntry struct {
	Name                 string     `json:"name"`
	Ecosystem            string     `json:"ecosystem"`
	PURL                 string     `json:"purl"`
	Licenses             string     `json:"licenses"`
	LatestVersion        string     `json:"latest_release_number"`
	VersionsCount        int        `json:"versions_count"`
	Downloads            int64      `json:"downloads"`
	DependentPkgs        int        `json:"dependent_packages_count"`
	DependentRepos       int        `json:"dependent_repos_count"`
	RegistryURL          string     `json:"registry_url"`
	LatestReleaseAt      *time.Time      `json:"latest_release_published_at"`
	DependentPackagesURL string          `json:"dependent_packages_url"`
	Maintainers          []pkgMaintainer `json:"maintainers"`
}

func (w *Worker) doPackages(ctx context.Context, scan *db.Scan, emit func(Event)) (string, error) {
	_, raw, err := fetchPackages(ctx, scan.Repository.URL, emit)
	if err != nil {
		return string(raw), err
	}

	var entries []pkgEntry
	if err := json.Unmarshal(raw, &entries); err == nil && len(entries) > 0 {
		w.DB.Where("repository_id = ?", scan.RepositoryID).Delete(&db.Package{})
		pkgs := make([]db.Package, 0, len(entries))
		for _, e := range entries {
			pkgs = append(pkgs, db.Package{
				RepositoryID:         scan.RepositoryID,
				Name:                 e.Name,
				Ecosystem:            e.Ecosystem,
				PURL:                 e.PURL,
				Licenses:             e.Licenses,
				LatestVersion:        e.LatestVersion,
				VersionsCount:        e.VersionsCount,
				Downloads:            e.Downloads,
				DependentPackages:    e.DependentPkgs,
				DependentRepos:       e.DependentRepos,
				RegistryURL:          e.RegistryURL,
				LatestReleaseAt:      e.LatestReleaseAt,
				DependentPackagesURL: e.DependentPackagesURL,
				Metadata:             string(raw),
			})
		}
		if err := w.DB.Create(&pkgs).Error; err != nil {
			emit(Event{Kind: KindError, Text: "save packages: " + err.Error()})
		}
		emit(Event{Kind: KindText, Text: fmt.Sprintf("stored %d package(s)", len(pkgs))})

		// Maintainer extraction is handled by the maintainer-analysis job
	}

	var pretty any
	_ = json.Unmarshal(raw, &pretty)
	out, _ := json.MarshalIndent(pretty, "", "  ")
	return string(out), nil
}

func (w *Worker) doBrief(ctx context.Context, scan *db.Scan, emit func(Event)) (string, error) {
	src, err := ensureClone(ctx, scan.Repository, w.DataDir, emit)
	if err != nil {
		return "", err
	}
	scan.Commit = gitHead(src)
	out, err := runTool(ctx, src, emit, "brief", "--json", ".")
	if err != nil {
		return out, fmt.Errorf("brief: %w", err)
	}
	var pretty any
	_ = json.Unmarshal([]byte(out), &pretty)
	formatted, _ := json.MarshalIndent(pretty, "", "  ")
	return string(formatted), nil
}

type gitPkgEntry struct {
	Name           string `json:"name"`
	Ecosystem      string `json:"ecosystem"`
	PURL           string `json:"purl"`
	Requirement    string `json:"requirement"`
	DependencyType string `json:"dependency_type"`
	ManifestPath   string `json:"manifest_path"`
	ManifestKind   string `json:"manifest_kind"`
}

func (w *Worker) doGitPkgs(ctx context.Context, scan *db.Scan, emit func(Event)) (string, error) {
	src, err := ensureClone(ctx, scan.Repository, w.DataDir, emit)
	if err != nil {
		return "", err
	}
	scan.Commit = gitHead(src)

	// Unshallow so git-pkgs can walk history; no-op if already full.
	_, _ = runTool(ctx, src, emit, "git", "fetch", "--unshallow", "--quiet")

	if out, err := runTool(ctx, src, emit, "git-pkgs", "init", "--no-hooks"); err != nil {
		return out, fmt.Errorf("git-pkgs init: %w", err)
	}
	out, err := runTool(ctx, src, emit, "git-pkgs", "list", "--format", "json")
	if err != nil {
		return out, fmt.Errorf("git-pkgs list: %w", err)
	}

	var entries []gitPkgEntry
	if err := json.Unmarshal([]byte(out), &entries); err == nil && len(entries) > 0 {
		// Replace all deps for this repo
		w.DB.Where("repository_id = ?", scan.RepositoryID).Delete(&db.Dependency{})
		deps := make([]db.Dependency, 0, len(entries))
		for _, e := range entries {
			deps = append(deps, db.Dependency{
				RepositoryID:   scan.RepositoryID,
				Name:           e.Name,
				Ecosystem:      e.Ecosystem,
				PURL:           e.PURL,
				Requirement:    e.Requirement,
				DependencyType: e.DependencyType,
				ManifestPath:   e.ManifestPath,
				ManifestKind:   e.ManifestKind,
			})
		}
		if err := w.DB.Create(&deps).Error; err != nil {
			emit(Event{Kind: KindError, Text: "save deps: " + err.Error()})
		}
		emit(Event{Kind: KindText, Text: fmt.Sprintf("stored %d dependencies", len(deps))})
	}

	var pretty any
	_ = json.Unmarshal([]byte(out), &pretty)
	formatted, _ := json.MarshalIndent(pretty, "", "  ")
	return string(formatted), nil
}

type depPkgEntry struct {
	Name           string `json:"name"`
	Ecosystem      string `json:"ecosystem"`
	PURL           string `json:"purl"`
	RepositoryURL  string `json:"repository_url"`
	Downloads      int64  `json:"downloads"`
	DependentRepos int    `json:"dependent_repos_count"`
	RegistryURL    string `json:"registry_url"`
	LatestVersion  string `json:"latest_release_number"`
}

func (w *Worker) doDependents(ctx context.Context, scan *db.Scan, emit func(Event)) (string, error) {
	// Find packages for this repo that have a dependent_packages_url
	var pkgs []db.Package
	w.DB.Where("repository_id = ? AND dependent_packages_url != ''", scan.RepositoryID).Find(&pkgs)
	if len(pkgs) == 0 {
		return "{}", fmt.Errorf("no packages with dependent_packages_url found; run the packages job first")
	}

	w.DB.Where("repository_id = ?", scan.RepositoryID).Delete(&db.Dependent{})

	var allDeps []db.Dependent
	for _, pkg := range pkgs {
		endpoint := pkg.DependentPackagesURL + "?kind=runtime&order=desc&sort=dependent_repos_count&per_page=25"
		emit(Event{Kind: KindText, Text: "GET " + endpoint})

		raw, err := fetchJSON(ctx, endpoint)
		if err != nil {
			emit(Event{Kind: KindError, Text: pkg.Name + ": " + err.Error()})
			continue
		}

		var entries []depPkgEntry
		if err := json.Unmarshal(raw, &entries); err != nil {
			emit(Event{Kind: KindError, Text: "decode: " + err.Error()})
			continue
		}

		for _, e := range entries {
			allDeps = append(allDeps, db.Dependent{
				RepositoryID:   scan.RepositoryID,
				Name:           e.Name,
				Ecosystem:      e.Ecosystem,
				PURL:           e.PURL,
				RepositoryURL:  e.RepositoryURL,
				Downloads:      e.Downloads,
				DependentRepos: e.DependentRepos,
				RegistryURL:    e.RegistryURL,
				LatestVersion:  e.LatestVersion,
			})
		}
		emit(Event{Kind: KindText, Text: fmt.Sprintf("%s: %d dependents", pkg.Name, len(entries))})
	}

	if len(allDeps) > 0 {
		if err := w.DB.Create(&allDeps).Error; err != nil {
			return "", fmt.Errorf("save dependents: %w", err)
		}
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("stored %d total dependents", len(allDeps))})

	out, _ := json.MarshalIndent(allDeps, "", "  ")
	return string(out), nil
}

type advisoryEntry struct {
	UUID           string     `json:"uuid"`
	URL            string     `json:"url"`
	Title          string     `json:"title"`
	Description    string     `json:"description"`
	Severity       string     `json:"severity"`
	CVSSScore      float64    `json:"cvss_score"`
	Classification string     `json:"classification"`
	PublishedAt    *time.Time `json:"published_at"`
	WithdrawnAt    *time.Time `json:"withdrawn_at"`
	Packages       []struct {
		PackageName string `json:"package_name"`
	} `json:"packages"`
}

func (e advisoryEntry) packageNames() string {
	names := make([]string, 0, len(e.Packages))
	for _, p := range e.Packages {
		names = append(names, p.PackageName)
	}
	return strings.Join(names, ", ")
}

func (w *Worker) doAdvisories(ctx context.Context, scan *db.Scan, emit func(Event)) (string, error) {
	endpoint := "https://advisories.ecosyste.ms/api/v1/advisories/lookup?repository_url=" + url.QueryEscape(scan.Repository.URL)
	emit(Event{Kind: KindText, Text: "GET " + endpoint})

	raw, err := fetchJSON(ctx, endpoint)
	if err != nil {
		return string(raw), err
	}

	var entries []advisoryEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return string(raw), fmt.Errorf("decode: %w", err)
	}

	w.DB.Where("repository_id = ?", scan.RepositoryID).Delete(&db.Advisory{})

	if len(entries) > 0 {
		rows := make([]db.Advisory, 0, len(entries))
		for _, e := range entries {
			rows = append(rows, db.Advisory{
				RepositoryID:   scan.RepositoryID,
				UUID:           e.UUID,
				URL:            e.URL,
				Title:          e.Title,
				Description:    e.Description,
				Severity:       e.Severity,
				CVSSScore:      e.CVSSScore,
				Classification: e.Classification,
				Packages:       e.packageNames(),
				PublishedAt:    e.PublishedAt,
				WithdrawnAt:    e.WithdrawnAt,
			})
		}
		if err := w.DB.Create(&rows).Error; err != nil {
			return string(raw), fmt.Errorf("save advisories: %w", err)
		}
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("stored %d advisory(ies)", len(entries))})

	var pretty any
	_ = json.Unmarshal(raw, &pretty)
	out, _ := json.MarshalIndent(pretty, "", "  ")
	return string(out), nil
}

func (w *Worker) doCommits(ctx context.Context, scan *db.Scan, emit func(Event)) (string, error) {
	endpoint := "https://commits.ecosyste.ms/api/v1/repositories/lookup?url=" + url.QueryEscape(scan.Repository.URL)
	emit(Event{Kind: KindText, Text: "GET " + endpoint})
	raw, err := fetchJSONFollow(ctx, endpoint)
	if err != nil {
		return string(raw), err
	}

	var pretty any
	_ = json.Unmarshal(raw, &pretty)
	out, _ := json.MarshalIndent(pretty, "", "  ")
	return string(out), nil
}

func validEmail(email string) bool {
	if email == "" {
		return false
	}
	if !strings.Contains(email, "@") {
		return false
	}
	if strings.Contains(email, "noreply") || strings.HasSuffix(email, "@users.noreply.github.com") {
		return false
	}
	return true
}


func (w *Worker) doSBOM(ctx context.Context, scan *db.Scan, emit func(Event)) (string, error) {
	src, err := ensureClone(ctx, scan.Repository, w.DataDir, emit)
	if err != nil {
		return "", err
	}
	scan.Commit = gitHead(src)

	// git-pkgs needs its index; init is idempotent if already done by doGitPkgs
	_, _ = runTool(ctx, src, emit, "git", "fetch", "--unshallow", "--quiet")
	if out, err := runTool(ctx, src, emit, "git-pkgs", "init", "--no-hooks"); err != nil {
		return out, fmt.Errorf("git-pkgs init: %w", err)
	}

	out, err := runToolStdout(ctx, src, emit, "git-pkgs", "sbom", "--format", "json")
	if err != nil {
		return out, fmt.Errorf("git-pkgs sbom: %w", err)
	}
	var pretty any
	_ = json.Unmarshal([]byte(out), &pretty)
	formatted, _ := json.MarshalIndent(pretty, "", "  ")
	return string(formatted), nil
}

var semgrepExcludes = []string{"vendor", "node_modules", "dist", "build", ".venv", "venv", "target", "Pods", "third_party"}

func (w *Worker) doSemgrep(ctx context.Context, scan *db.Scan, emit func(Event)) (string, error) {
	src, err := ensureClone(ctx, scan.Repository, w.DataDir, emit)
	if err != nil {
		return "", err
	}
	scan.Commit = gitHead(src)

	args := []string{
		"scan", "--metrics=off", "--quiet", "--sarif",
		"--timeout", "30", "--timeout-threshold", "3", "--max-target-bytes", "1000000",
	}
	for _, d := range semgrepExcludes {
		args = append(args, "--exclude", d)
	}
	args = append(args, "--config", "p/security-audit", "--config", "p/secrets", ".")

	// semgrep exit 1 = findings found (not an error)
	out, err := runToolStdout(ctx, src, emit, "semgrep", args...)
	if err != nil && !strings.Contains(out, `"results"`) {
		return out, fmt.Errorf("semgrep: %w", err)
	}
	var pretty any
	_ = json.Unmarshal([]byte(out), &pretty)
	formatted, _ := json.MarshalIndent(pretty, "", "  ")
	return string(formatted), nil
}

func (w *Worker) doZizmor(ctx context.Context, scan *db.Scan, emit func(Event)) (string, error) {
	src, err := ensureClone(ctx, scan.Repository, w.DataDir, emit)
	if err != nil {
		return "", err
	}
	scan.Commit = gitHead(src)

	wfDir := filepath.Join(src, ".github", "workflows")
	if _, err := os.Stat(wfDir); os.IsNotExist(err) {
		return `{"runs":[]}`, fmt.Errorf("no .github/workflows directory")
	}

	// zizmor exit 13 = findings, 14 = high findings; both are normal
	out, err := runToolStdout(ctx, src, emit, "zizmor", "--no-progress", "--format", "sarif", "--persona", "auditor", ".github/workflows")
	if err != nil && !strings.Contains(out, `"results"`) {
		return out, fmt.Errorf("zizmor: %w", err)
	}
	var pretty any
	_ = json.Unmarshal([]byte(out), &pretty)
	formatted, _ := json.MarshalIndent(pretty, "", "  ")
	return string(formatted), nil
}
