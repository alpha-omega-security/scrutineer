package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	mavenpom "github.com/git-pkgs/pom"
	"gorm.io/gorm"

	"scrutineer/internal/db"
)

const insertBatchSize = 50

const findingDedupSkill = "finding-dedup"

// parseRepoMetadataOutput updates the Repository columns that previously
// came from the metadata Go handler. Shape matches the subset of
// repos.ecosyste.ms fields scrutineer actually uses; the skill picks them
// out of the upstream response so the schema does not couple us to the
// exact upstream field names.
func (w *Worker) parseRepoMetadataOutput(scan *db.Scan, report string, emit func(Event)) error {
	var m struct {
		FullName      string   `json:"full_name"`
		Owner         string   `json:"owner"`
		Description   string   `json:"description"`
		DefaultBranch string   `json:"default_branch"`
		Languages     []string `json:"languages"`
		License       string   `json:"license"`
		Stars         int      `json:"stars"`
		Forks         int      `json:"forks"`
		Archived      bool     `json:"archived"`
		PushedAt      string   `json:"pushed_at"`
		HTMLURL       string   `json:"html_url"`
		IconURL       string   `json:"icon_url"`
	}
	if err := json.Unmarshal([]byte(report), &m); err != nil {
		return fmt.Errorf("parse repo_metadata: %w", err)
	}
	updates := map[string]any{
		"metadata":   report,
		"fetched_at": time.Now(),
	}
	if m.FullName != "" {
		updates["full_name"] = m.FullName
	}
	if m.Owner != "" {
		updates["owner"] = m.Owner
	}
	if m.Description != "" {
		updates["description"] = m.Description
	}
	if m.DefaultBranch != "" {
		updates["default_branch"] = m.DefaultBranch
	}
	if len(m.Languages) > 0 {
		updates["languages"] = strings.Join(m.Languages, ", ")
	}
	if m.License != "" {
		updates["license"] = m.License
	}
	updates["stars"] = m.Stars
	updates["forks"] = m.Forks
	updates["archived"] = m.Archived
	if t, ok := parseTimeField(emit, "pushed_at", m.PushedAt); ok {
		updates["pushed_at"] = t
	}
	if u := safeURL(m.HTMLURL); u != "" {
		updates["html_url"] = u
	}
	if u := safeURL(m.IconURL); u != "" {
		updates["icon_url"] = u
	}
	if err := w.DB.Model(&db.Repository{}).Where("id = ?", scan.RepositoryID).Updates(updates).Error; err != nil {
		return fmt.Errorf("update repository: %w", err)
	}
	emit(Event{Kind: KindText, Text: "updated repository metadata"})
	return nil
}

// safeURL returns u trimmed when it carries an http or https scheme, else
// empty. Applied to model-emitted URLs (html_url, icon_url) before they
// reach the database so a hostile metadata response cannot land a
// javascript: or data: URI that the templates then render as a clickable
// link (T7 in threatmodel.md).
func safeURL(u string) string {
	u = strings.TrimSpace(u)
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return u
	}
	return ""
}

// parsePackagesOutput replaces Package rows for the scan's repository. We
// delete all existing rows and insert whatever the skill produced, mirroring
// the old Go handler which did the same: packages are a projection of the
// upstream registry state, not an incrementally grown set.
func (w *Worker) parsePackagesOutput(scan *db.Scan, report string, emit func(Event)) error {
	var result struct {
		Packages []struct {
			Name                 string `json:"name"`
			Ecosystem            string `json:"ecosystem"`
			PURL                 string `json:"purl"`
			Licenses             string `json:"licenses"`
			LatestVersion        string `json:"latest_version"`
			VersionsCount        int    `json:"versions_count"`
			Downloads            int64  `json:"downloads"`
			DependentPackages    int    `json:"dependent_packages"`
			DependentRepos       int    `json:"dependent_repos"`
			RegistryURL          string `json:"registry_url"`
			LatestReleaseAt      string `json:"latest_release_at"`
			DependentPackagesURL string `json:"dependent_packages_url"`
			Metadata             any    `json:"metadata"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		return fmt.Errorf("parse packages: %w", err)
	}
	rows := make([]db.Package, 0, len(result.Packages))
	for _, p := range result.Packages {
		row := db.Package{
			RepositoryID:         scan.RepositoryID,
			Name:                 p.Name,
			Ecosystem:            db.EcosystemType(p.PURL, p.Ecosystem),
			PURL:                 p.PURL,
			Licenses:             p.Licenses,
			LatestVersion:        p.LatestVersion,
			VersionsCount:        p.VersionsCount,
			Downloads:            p.Downloads,
			DependentPackages:    p.DependentPackages,
			DependentRepos:       p.DependentRepos,
			RegistryURL:          p.RegistryURL,
			DependentPackagesURL: p.DependentPackagesURL,
		}
		if t, ok := parseTimeField(emit, "latest_release_at", p.LatestReleaseAt); ok {
			row.LatestReleaseAt = &t
		}
		if p.Metadata != nil {
			if b, err := json.Marshal(p.Metadata); err == nil {
				row.Metadata = string(b)
			}
		}
		rows = append(rows, row)
	}
	// Replace the prior row set atomically: a failed insert after the
	// delete would otherwise leave the repository with zero packages
	// until the next successful scan.
	if err := w.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("repository_id = ?", scan.RepositoryID).Delete(&db.Package{}).Error; err != nil {
			return fmt.Errorf("delete old packages: %w", err)
		}
		if len(rows) > 0 {
			if err := tx.CreateInBatches(&rows, insertBatchSize).Error; err != nil {
				return fmt.Errorf("save packages: %w", err)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("saved %d package(s)", len(rows))})
	return nil
}

// parseAdvisoriesOutput replaces Advisory rows for the scan's repository.
func (w *Worker) parseAdvisoriesOutput(scan *db.Scan, report string, emit func(Event)) error {
	var result struct {
		Advisories []struct {
			UUID           string  `json:"uuid"`
			URL            string  `json:"url"`
			Title          string  `json:"title"`
			Description    string  `json:"description"`
			Severity       string  `json:"severity"`
			CVSSScore      float64 `json:"cvss_score"`
			Classification string  `json:"classification"`
			Packages       string  `json:"packages"`
			PublishedAt    string  `json:"published_at"`
			WithdrawnAt    string  `json:"withdrawn_at"`
		} `json:"advisories"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		return fmt.Errorf("parse advisories: %w", err)
	}
	rows := make([]db.Advisory, 0, len(result.Advisories))
	for _, a := range result.Advisories {
		row := db.Advisory{
			RepositoryID:   scan.RepositoryID,
			UUID:           a.UUID,
			URL:            a.URL,
			Title:          a.Title,
			Description:    a.Description,
			Severity:       a.Severity,
			CVSSScore:      a.CVSSScore,
			Classification: a.Classification,
			Packages:       a.Packages,
		}
		if t, ok := parseTimeField(emit, "published_at", a.PublishedAt); ok {
			row.PublishedAt = &t
		}
		if t, ok := parseTimeField(emit, "withdrawn_at", a.WithdrawnAt); ok {
			row.WithdrawnAt = &t
		}
		rows = append(rows, row)
	}
	// Replace the prior row set atomically so a failed insert can't leave
	// the repository with zero advisories.
	if err := w.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("repository_id = ?", scan.RepositoryID).Delete(&db.Advisory{}).Error; err != nil {
			return fmt.Errorf("delete old advisories: %w", err)
		}
		if len(rows) > 0 {
			if err := tx.CreateInBatches(&rows, insertBatchSize).Error; err != nil {
				return fmt.Errorf("save advisories: %w", err)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("saved %d advisor(ies)", len(rows))})
	return nil
}

// parseDependenciesOutput replaces Dependency rows for the scan's repository.
// Dependencies come from a git-pkgs-style manifest scan: one row per
// (name, ecosystem, manifest_path) tuple.
func (w *Worker) parseDependenciesOutput(scan *db.Scan, report string, emit func(Event)) error {
	var result struct {
		Dependencies []dependencyReportRow `json:"dependencies"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		return fmt.Errorf("parse dependencies: %w", err)
	}
	w.resolveMavenDependencyRequirements(scan, result.Dependencies, emit)
	rows := make([]db.Dependency, 0, len(result.Dependencies))
	for _, d := range result.Dependencies {
		depType := d.Type
		if depType == "" {
			depType = d.DependencyType
		}
		depType = db.NormalizeDependencyType(depType)
		rows = append(rows, db.Dependency{
			RepositoryID:          scan.RepositoryID,
			Name:                  d.Name,
			Ecosystem:             db.EcosystemType(d.PURL, d.Ecosystem),
			PURL:                  d.PURL,
			Requirement:           d.Requirement,
			RequirementUnresolved: d.RequirementUnresolved,
			RequirementResolution: d.RequirementResolution,
			DependencyType:        depType,
			ManifestPath:          d.ManifestPath,
			ManifestKind:          d.ManifestKind,
		})
	}
	// Replace the prior row set atomically so a failed insert can't leave
	// the repository with zero dependencies.
	if err := w.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("repository_id = ?", scan.RepositoryID).Delete(&db.Dependency{}).Error; err != nil {
			return fmt.Errorf("delete old dependencies: %w", err)
		}
		if len(rows) > 0 {
			if err := tx.CreateInBatches(&rows, insertBatchSize).Error; err != nil {
				return fmt.Errorf("save dependencies: %w", err)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("saved %d dependenc(ies)", len(rows))})
	return nil
}

type dependencyReportRow struct {
	Name                  string `json:"name"`
	Ecosystem             string `json:"ecosystem"`
	PURL                  string `json:"purl"`
	Requirement           string `json:"requirement"`
	RequirementUnresolved bool   `json:"requirement_unresolved"`
	RequirementResolution string `json:"requirement_resolution"`
	Type                  string `json:"type"`
	DependencyType        string `json:"dependency_type"`
	ManifestPath          string `json:"manifest_path"`
	ManifestKind          string `json:"manifest_kind"`
}

func (w *Worker) resolveMavenDependencyRequirements(scan *db.Scan, deps []dependencyReportRow, emit func(Event)) {
	srcRoot := filepath.Join(w.scanWorkRoot(scan), "src")
	resolved := map[string]map[string]mavenpom.ResolvedDep{}
	for i := range deps {
		if !isMavenPOMDependency(deps[i]) {
			continue
		}
		pomPath, ok := containedPOMPath(srcRoot, deps[i].ManifestPath)
		if !ok {
			markRequirementUnresolved(&deps[i], string(mavenpom.UnresolvedParent))
			continue
		}
		byGA, ok := resolved[pomPath]
		if !ok {
			byGA = resolveLocalPOMDependencies(pomPath, srcRoot, emit)
			resolved[pomPath] = byGA
		}
		if byGA == nil {
			markRequirementUnresolved(&deps[i], string(mavenpom.UnresolvedParent))
			continue
		}
		rd, ok := byGA[deps[i].Name]
		if !ok {
			markRequirementUnresolved(&deps[i], fallbackRequirementResolution(deps[i].Requirement))
			continue
		}
		if rd.Version != "" {
			deps[i].Requirement = rd.Version
		} else if rd.Expression != "" {
			deps[i].Requirement = rd.Expression
		}
		deps[i].RequirementResolution = string(rd.Resolution)
		deps[i].RequirementUnresolved = rd.Resolution != mavenpom.Resolved
	}
}

func isMavenPOMDependency(dep dependencyReportRow) bool {
	if dep.ManifestPath == "" || filepath.Base(dep.ManifestPath) != "pom.xml" {
		return false
	}
	if strings.HasPrefix(dep.PURL, "pkg:maven/") {
		return true
	}
	return strings.EqualFold(dep.Ecosystem, "maven")
}

func resolveLocalPOMDependencies(pomPath, srcRoot string, emit func(Event)) map[string]mavenpom.ResolvedDep {
	if !localPOMParentsStayUnderRoot(pomPath, srcRoot) {
		return nil
	}
	ep, err := mavenpom.ResolveLocal(context.Background(), pomPath, mavenpom.Options{})
	if err != nil {
		emit(Event{Kind: KindText, Text: "maven pom resolver skipped " + pomPath + ": " + err.Error()})
		return nil
	}
	deps := make(map[string]mavenpom.ResolvedDep, len(ep.Dependencies))
	for _, dep := range ep.Dependencies {
		deps[dep.GroupID+":"+dep.ArtifactID] = dep
	}
	return deps
}

func markRequirementUnresolved(dep *dependencyReportRow, resolution string) {
	dep.RequirementUnresolved = true
	if dep.RequirementResolution == "" {
		dep.RequirementResolution = resolution
	}
}

func fallbackRequirementResolution(requirement string) string {
	if strings.Contains(requirement, "${env.") {
		return string(mavenpom.UnresolvedEnv)
	}
	if strings.Contains(requirement, "${") {
		return string(mavenpom.UnresolvedProperty)
	}
	return string(mavenpom.UnresolvedMissing)
}

func containedPOMPath(srcRoot, manifestPath string) (string, bool) {
	if manifestPath == "" || filepath.IsAbs(manifestPath) || !filepath.IsLocal(manifestPath) {
		return "", false
	}
	if filepath.Base(manifestPath) != "pom.xml" {
		return "", false
	}
	srcRootAbs, err := filepath.Abs(srcRoot)
	if err != nil {
		return "", false
	}
	pomPath := filepath.Join(srcRootAbs, filepath.Clean(manifestPath))
	if !pathUnderRoot(pomPath, srcRootAbs) || !realPathUnderRoot(pomPath, srcRootAbs) {
		return "", false
	}
	return pomPath, true
}

const maxLocalPOMParentDepth = 32

func localPOMParentsStayUnderRoot(rootPath, srcRoot string) bool {
	seen := map[string]bool{}
	path := rootPath
	for range maxLocalPOMParentDepth {
		if seen[path] || !realPathUnderRoot(path, srcRoot) {
			return false
		}
		seen[path] = true
		info, err := os.Lstat(path)
		if err != nil {
			return true
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return true
		}
		p, err := mavenpom.ParsePOM(data)
		if err != nil || p.Parent == nil {
			return true
		}
		rel := p.Parent.LocalPath()
		if rel == "" {
			return true
		}
		if filepath.IsAbs(rel) {
			return false
		}
		next := filepath.Clean(filepath.Join(filepath.Dir(path), rel))
		if info, err := os.Lstat(next); err == nil && info.IsDir() {
			next = filepath.Join(next, "pom.xml")
		}
		if !pathUnderRoot(next, srcRoot) || !realPathUnderRoot(next, srcRoot) {
			return false
		}
		path = next
	}
	return false
}

func pathUnderRoot(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func realPathUnderRoot(path, root string) bool {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		realPath, err = filepath.Abs(path)
		if err != nil {
			return false
		}
	}
	return pathUnderRoot(realPath, realRoot)
}

// parseSubprojectsOutput replaces Subproject rows for the scan's
// repository. Subprojects are a projection of the repo layout produced
// by the subprojects skill; a fresh run reflects the current clone and
// replaces any prior set.
func (w *Worker) parseSubprojectsOutput(scan *db.Scan, report string, emit func(Event)) error {
	var result struct {
		Subprojects []struct {
			Path        string `json:"path"`
			Name        string `json:"name"`
			Kind        string `json:"kind"`
			Description string `json:"description"`
		} `json:"subprojects"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		return fmt.Errorf("parse subprojects: %w", err)
	}
	rows := make([]db.Subproject, 0, len(result.Subprojects))
	for _, sp := range result.Subprojects {
		path := strings.Trim(sp.Path, "/ \t\n")
		if path == "" {
			continue
		}
		rows = append(rows, db.Subproject{
			RepositoryID: scan.RepositoryID,
			Path:         path,
			Name:         sp.Name,
			Kind:         sp.Kind,
			Description:  sp.Description,
		})
	}
	// Replace the prior row set atomically so a failed insert can't leave
	// the repository with zero subprojects.
	if err := w.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("repository_id = ?", scan.RepositoryID).Delete(&db.Subproject{}).Error; err != nil {
			return fmt.Errorf("delete old subprojects: %w", err)
		}
		if len(rows) > 0 {
			if err := tx.CreateInBatches(&rows, insertBatchSize).Error; err != nil {
				return fmt.Errorf("save subprojects: %w", err)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("saved %d subproject(s)", len(rows))})
	return nil
}

// parseRepoOverviewOutput reads `brief`'s structured output and writes
// the detected fields onto the Repository row. Brief wins over
// ecosyste.ms for the fields it produces (languages, default branch,
// license) — the detection is typically more accurate than the upstream
// API for self-hosted or sparsely-populated repos. Fields brief leaves
// empty are left alone, so ecosyste.ms still fills gaps.
func (w *Worker) parseRepoOverviewOutput(scan *db.Scan, report string, emit func(Event)) error {
	var result struct {
		Git struct {
			DefaultBranch string `json:"default_branch"`
		} `json:"git"`
		Languages []struct {
			Name     string `json:"name"`
			Category string `json:"category"`
		} `json:"languages"`
		Resources struct {
			LicenseType string `json:"license_type"`
		} `json:"resources"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		emit(Event{Kind: KindText, Text: "repo-overview: skipping backfill, unparseable JSON"})
		return nil
	}
	updates := map[string]any{}
	var names []string
	for _, l := range result.Languages {
		if l.Category != "" && l.Category != "language" {
			continue
		}
		if l.Name != "" {
			names = append(names, l.Name)
		}
	}
	if len(names) > 0 {
		updates["languages"] = strings.Join(names, ", ")
	}
	if result.Git.DefaultBranch != "" {
		updates["default_branch"] = result.Git.DefaultBranch
	}
	if result.Resources.LicenseType != "" {
		updates["license"] = result.Resources.LicenseType
	}
	if len(updates) == 0 {
		return nil
	}
	if err := w.DB.Model(&db.Repository{}).Where("id = ?", scan.RepositoryID).Updates(updates).Error; err != nil {
		return fmt.Errorf("update repo: %w", err)
	}
	keys := make([]string, 0, len(updates))
	for k := range updates {
		keys = append(keys, k)
	}
	emit(Event{Kind: KindText, Text: "repo-overview: wrote " + strings.Join(keys, ", ")})
	return nil
}

// parsePostureOutput writes the disclosure-readiness tier and summary onto
// the Repository row. The full check list stays in scan.Report; only the
// tier and one-line summary are promoted to columns so the repo list can
// sort and filter on them.
func (w *Worker) parsePostureOutput(scan *db.Scan, report string, emit func(Event)) error {
	var result struct {
		Tier    string `json:"tier"`
		Summary string `json:"summary"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		return fmt.Errorf("parse posture: %w", err)
	}
	tier := strings.TrimSpace(result.Tier)
	switch tier {
	case "ready", "partial", "unprepared":
	case "":
		emit(Event{Kind: KindText, Text: "posture: no tier in report, leaving repository unchanged"})
		return nil
	default:
		return fmt.Errorf("posture tier %q is not one of ready|partial|unprepared", tier)
	}
	updates := map[string]any{
		"posture":         tier,
		"posture_summary": strings.TrimSpace(result.Summary),
	}
	if err := w.DB.Model(&db.Repository{}).Where("id = ?", scan.RepositoryID).Updates(updates).Error; err != nil {
		return fmt.Errorf("update posture: %w", err)
	}
	emit(Event{Kind: KindText, Text: "posture: " + tier})
	return nil
}

// parseVerifyOutput records the outcome of a finding-scoped verification
// run. Reproducer, evidence and notes become a FindingNote; the status
// transition is written via WriteFindingField with source=model_suggested so
// the audit trail on the finding page shows the skill as the author.
func (w *Worker) parseVerifyOutput(scan *db.Scan, report string, emit func(Event)) error {
	if scan.FindingID == nil {
		return fmt.Errorf("verify scan has no finding_id")
	}
	var result struct {
		Status    string `json:"status"`
		Preflight struct {
			Classification string `json:"classification"`
			Justification  string `json:"justification"`
		} `json:"preflight"`
		Reproducer string `json:"reproducer"`
		Evidence   string `json:"evidence"`
		Notes      string `json:"notes"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		return fmt.Errorf("parse verify report: %w", err)
	}
	var f db.Finding
	if err := w.DB.First(&f, *scan.FindingID).Error; err != nil {
		return fmt.Errorf("load finding %d: %w", *scan.FindingID, err)
	}

	var nextStatus db.FindingLifecycle
	switch result.Status {
	case "confirmed":
		if f.Status == db.FindingNew {
			nextStatus = db.FindingEnriched
		}
	case "fixed":
		// Only a verify against the default branch (empty Ref) moves the
		// finding to fixed. A "fixed" verdict on an explicit fix ref — the
		// validate-fix pipeline points verify at a candidate ref, often an
		// unmerged PR branch — means the fix works there, not that a release
		// carries it; the note below and the fix-validation report still
		// capture the per-ref verdict.
		if scan.Ref == "" {
			nextStatus = db.FindingFixed
		}
	case "inconclusive":
		// Leave status alone: the reproduction could not be run or its
		// outcome was unclassifiable.
	case "deferred":
		// Leave status alone: preflight found the reproduction reaches an
		// external host or credential file and it was not run at all — a
		// human must run it somewhere the callback can land. deferred is
		// meaningless without the preflight that decided it, so an empty
		// classification or justification is a hard error rather than a
		// note that quietly loses the offending lines.
		if result.Preflight.Classification == "" || strings.TrimSpace(result.Preflight.Justification) == "" {
			return fmt.Errorf("verify status \"deferred\" requires preflight.classification and preflight.justification")
		}
	default:
		return fmt.Errorf("verify status %q is not one of confirmed|fixed|inconclusive|deferred", result.Status)
	}
	if nextStatus != "" {
		if err := db.WriteFindingField(w.DB, f.ID, "status", string(nextStatus), db.SourceModel, "verify"); err != nil {
			return fmt.Errorf("update status: %w", err)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "verify: %s\n", result.Status)
	if result.Preflight.Classification != "" {
		fmt.Fprintf(&b, "preflight: %s\n", result.Preflight.Classification)
		if j := strings.TrimSpace(result.Preflight.Justification); j != "" {
			fmt.Fprintf(&b, "\n%s\n", j)
		}
	}
	if result.Reproducer != "" {
		fmt.Fprintf(&b, "\n%s\n", strings.TrimSpace(result.Reproducer))
	}
	if result.Evidence != "" {
		fmt.Fprintf(&b, "\n%s\n", strings.TrimSpace(result.Evidence))
	}
	if result.Notes != "" {
		fmt.Fprintf(&b, "\n%s\n", strings.TrimSpace(result.Notes))
	}
	if _, err := db.AddFindingNote(w.DB, f.ID, b.String(), "verify"); err != nil {
		return fmt.Errorf("record verify note: %w", err)
	}

	emit(Event{Kind: KindText, Text: "finding " + fmt.Sprint(f.ID) + " -> " + result.Status})
	return nil
}

// parseBreakingChangeOutput records the breaking-change verdict on a
// finding from a static analysis of the suggested-fix diff. The verdict
// goes into Finding.BreakingChange (with the change recorded in finding
// history via WriteFindingField); the prose rationale and the
// affected_dependents list become the human-readable body in
// Finding.BreakingChangeRationale.
func (w *Worker) parseBreakingChangeOutput(scan *db.Scan, report string, emit func(Event)) error {
	if scan.FindingID == nil {
		return fmt.Errorf("breaking-change scan has no finding_id")
	}
	var result struct {
		Verdict    string `json:"verdict"`
		Rationale  string `json:"rationale"`
		APIChanges []struct {
			Kind      string `json:"kind"`
			Symbol    string `json:"symbol"`
			Before    string `json:"before"`
			After     string `json:"after"`
			DiffLines string `json:"diff_lines"`
		} `json:"api_changes"`
		AffectedDependents []struct {
			Name     string `json:"name"`
			Registry string `json:"registry"`
			Reason   string `json:"reason"`
		} `json:"affected_dependents"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		return fmt.Errorf("parse breaking-change report: %w", err)
	}
	switch result.Verdict {
	case "breaking", "non_breaking", "unknown":
	default:
		return fmt.Errorf("breaking-change verdict %q is not one of breaking|non_breaking|unknown", result.Verdict)
	}

	if err := db.WriteFindingField(w.DB, *scan.FindingID, "breaking_change", result.Verdict, db.SourceModel, "breaking-change"); err != nil {
		return fmt.Errorf("update breaking_change: %w", err)
	}

	var b strings.Builder
	if reason := strings.TrimSpace(result.Rationale); reason != "" {
		b.WriteString(reason)
		b.WriteString("\n")
	}
	if len(result.AffectedDependents) > 0 {
		b.WriteString("\nAffected dependents:\n")
		for _, d := range result.AffectedDependents {
			name := d.Name
			if d.Registry != "" {
				name = d.Registry + ":" + name
			}
			if r := strings.TrimSpace(d.Reason); r != "" {
				fmt.Fprintf(&b, "- %s — %s\n", name, r)
			} else {
				fmt.Fprintf(&b, "- %s\n", name)
			}
		}
	}
	if len(result.APIChanges) > 0 {
		b.WriteString("\nAPI changes:\n")
		for _, c := range result.APIChanges {
			fmt.Fprintf(&b, "- %s %s", c.Kind, c.Symbol)
			if c.DiffLines != "" {
				fmt.Fprintf(&b, " (%s)", c.DiffLines)
			}
			b.WriteString("\n")
		}
	}
	if err := db.WriteFindingField(w.DB, *scan.FindingID, "breaking_change_rationale", strings.TrimRight(b.String(), "\n"), db.SourceModel, "breaking-change"); err != nil {
		return fmt.Errorf("update breaking_change_rationale: %w", err)
	}

	emit(Event{Kind: KindText, Text: "finding " + fmt.Sprint(*scan.FindingID) + " -> " + result.Verdict})
	return nil
}

// parseMitigationOutput stores the operational mitigation guidance and
// the optional semgrep rule the mitigate skill emits. Both go to the
// finding through WriteFindingField so analyst edits and re-runs both
// land in FindingHistory. An empty guidance body is a hard error: the
// skill is meant to produce something or write nothing at all.
func (w *Worker) parseMitigationOutput(scan *db.Scan, report string, emit func(Event)) error {
	if scan.FindingID == nil {
		return fmt.Errorf("mitigate scan has no finding_id")
	}
	var result struct {
		Guidance    string `json:"guidance"`
		SemgrepRule string `json:"semgrep_rule"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		return fmt.Errorf("parse mitigation report: %w", err)
	}
	guidance := strings.TrimSpace(result.Guidance)
	if guidance == "" {
		return fmt.Errorf("mitigate report has empty guidance")
	}
	if err := db.WriteFindingField(w.DB, *scan.FindingID, "mitigation", guidance, db.SourceModel, "mitigate"); err != nil {
		return fmt.Errorf("update mitigation: %w", err)
	}
	rule := strings.TrimSpace(result.SemgrepRule)
	if err := db.WriteFindingField(w.DB, *scan.FindingID, "mitigation_semgrep", rule, db.SourceModel, "mitigate"); err != nil {
		return fmt.Errorf("update mitigation_semgrep: %w", err)
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("finding %d mitigation drafted (%d bytes, semgrep=%v)", *scan.FindingID, len(guidance), rule != "")})
	return nil
}

// parseDiscloseOutput posts a FindingNote summarising a disclose run so the
// finding's Notes panel records that a draft was prepared, alongside the
// verify/revalidate/patch entries (#482). The draft itself is on
// Finding.DisclosureDraft (PATCHed by the skill via the API); this note is
// the audit trail pointing at it: the GHSA summary, which fields were
// patched/preserved, references added, and the report's notes prose. An
// error-only report records why the skill refused to draft.
func (w *Worker) parseDiscloseOutput(scan *db.Scan, report string, emit func(Event)) error {
	if scan.FindingID == nil {
		return fmt.Errorf("disclose scan has no finding_id")
	}
	var result struct {
		GHSA struct {
			Summary string `json:"summary"`
		} `json:"ghsa"`
		Patched           []string `json:"patched"`
		Preserved         []string `json:"preserved"`
		ReferencesAdded   int      `json:"references_added"`
		ReferencesSkipped int      `json:"references_skipped"`
		Notes             string   `json:"notes"`
		Error             string   `json:"error"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		return fmt.Errorf("parse disclose report: %w", err)
	}

	var b strings.Builder
	if result.Error != "" {
		fmt.Fprintf(&b, "disclose: refused\n\n%s\n", strings.TrimSpace(result.Error))
	} else {
		b.WriteString("disclose: drafted")
		if result.GHSA.Summary != "" {
			fmt.Fprintf(&b, " %q", result.GHSA.Summary)
		}
		b.WriteString("\n\n")
		if len(result.Patched) > 0 {
			fmt.Fprintf(&b, "Patched: %s\n", strings.Join(result.Patched, ", "))
		}
		if len(result.Preserved) > 0 {
			fmt.Fprintf(&b, "Preserved: %s\n", strings.Join(result.Preserved, ", "))
		}
		if result.ReferencesAdded > 0 || result.ReferencesSkipped > 0 {
			fmt.Fprintf(&b, "References: %d added, %d skipped\n",
				result.ReferencesAdded, result.ReferencesSkipped)
		}
		if result.Notes != "" {
			fmt.Fprintf(&b, "\n%s\n", strings.TrimSpace(result.Notes))
		}
	}
	if _, err := db.AddFindingNote(w.DB, *scan.FindingID, b.String(), "disclose"); err != nil {
		return fmt.Errorf("record disclose note: %w", err)
	}

	emit(Event{Kind: KindText, Text: fmt.Sprintf("finding %d disclosure draft note posted", *scan.FindingID)})
	return nil
}

// parseReleaseWatchOutput records whether the upstream has cut a
// release containing the fix. When released=true, the tag, URL, and
// timestamp go to the finding's release_tag / release_url / released_at
// columns through WriteFindingField (history recorded), and a
// FindingReference row tagged `upstream-release` makes the link visible
// in the references panel. A released=false run is also fine: it just
// records a short note and waits for the next run to check again.
func (w *Worker) parseReleaseWatchOutput(scan *db.Scan, report string, emit func(Event)) error {
	if scan.FindingID == nil {
		return fmt.Errorf("release-watch scan has no finding_id")
	}
	var result struct {
		Released   bool   `json:"released"`
		ReleaseTag string `json:"release_tag"`
		ReleaseURL string `json:"release_url"`
		ReleaseAt  string `json:"release_at"`
		Notes      string `json:"notes"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		return fmt.Errorf("parse release-watch report: %w", err)
	}
	// Validate the report shape before touching the DB so a malformed
	// run fails fast and the rejection paths can be tested without a
	// backing database.
	var releaseAt time.Time
	if result.Released {
		if strings.TrimSpace(result.ReleaseTag) == "" || strings.TrimSpace(result.ReleaseURL) == "" {
			return fmt.Errorf("release-watch report claims released=true but is missing release_tag or release_url")
		}
		parsed, err := time.Parse(time.RFC3339, result.ReleaseAt)
		if err != nil {
			return fmt.Errorf("parse release_at %q: %w", result.ReleaseAt, err)
		}
		releaseAt = parsed
	}
	var f db.Finding
	if err := w.DB.First(&f, *scan.FindingID).Error; err != nil {
		return fmt.Errorf("load finding %d: %w", *scan.FindingID, err)
	}

	if !result.Released {
		// Negative observations get a note row so the operator can see
		// what the latest run said without trawling scan logs.
		if reason := strings.TrimSpace(result.Notes); reason != "" {
			if _, err := db.AddFindingNote(w.DB, f.ID, "release-watch: not released\n\n"+reason, "release-watch"); err != nil {
				return fmt.Errorf("record release-watch note: %w", err)
			}
		}
		emit(Event{Kind: KindText, Text: fmt.Sprintf("finding %d: no release yet", f.ID)})
		return nil
	}

	if err := db.WriteFindingField(w.DB, f.ID, "release_tag", result.ReleaseTag, db.SourceModel, "release-watch"); err != nil {
		return fmt.Errorf("update release_tag: %w", err)
	}
	if err := db.WriteFindingField(w.DB, f.ID, "release_url", result.ReleaseURL, db.SourceModel, "release-watch"); err != nil {
		return fmt.Errorf("update release_url: %w", err)
	}
	if err := db.WriteFindingTimeField(w.DB, f.ID, "released_at", releaseAt, db.SourceModel, "release-watch"); err != nil {
		return fmt.Errorf("update released_at: %w", err)
	}

	// Dedupe the references row so re-runs that re-confirm the same
	// release (the skill's idempotency contract) do not pile up identical
	// rows in the references panel. Match on (finding, tag, URL); a
	// different URL for the same finding would still be a separate row.
	var existingRef int64
	if err := w.DB.Model(&db.FindingReference{}).
		Where("finding_id = ? AND tags = ? AND url = ?", f.ID, "upstream-release", result.ReleaseURL).
		Count(&existingRef).Error; err != nil {
		return fmt.Errorf("check existing release reference: %w", err)
	}
	if existingRef == 0 {
		if _, err := db.AddFindingReference(w.DB, f.ID, result.ReleaseURL, "upstream-release",
			"Upstream release "+result.ReleaseTag+" containing the fix"); err != nil {
			return fmt.Errorf("record release reference: %w", err)
		}
	}

	emit(Event{Kind: KindText, Text: fmt.Sprintf("finding %d released as %s (%s)", f.ID, result.ReleaseTag, releaseAt.UTC().Format(time.RFC3339))})
	return nil
}

// parseRevalidateOutput records the cheap classifier verdict for a
// finding. The verdict and reason become a FindingNote; an adjusted
// severity overwrites the finding's severity (with the change recorded
// in finding history via WriteFindingField); status transitions
// new -> enriched only on true_positive. Rejection of false positives
// stays a human act, so false_positive does not transition status.
func (w *Worker) parseRevalidateOutput(scan *db.Scan, report string, emit func(Event)) error {
	if scan.FindingID == nil {
		return fmt.Errorf("revalidate scan has no finding_id")
	}
	var result struct {
		Verdict                string `json:"verdict"`
		Reason                 string `json:"reason"`
		AdjustedSeverity       string `json:"adjusted_severity"`
		AdjustedSeverityReason string `json:"adjusted_severity_reason"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		return fmt.Errorf("parse revalidate report: %w", err)
	}
	switch result.Verdict {
	case "true_positive", "false_positive", "already_fixed", "uncertain":
	default:
		return fmt.Errorf("revalidate verdict %q is not one of true_positive|false_positive|already_fixed|uncertain", result.Verdict)
	}
	var f db.Finding
	if err := w.DB.First(&f, *scan.FindingID).Error; err != nil {
		return fmt.Errorf("load finding %d: %w", *scan.FindingID, err)
	}

	// Skip findings that have left the active funnel. A concurrent
	// finding-dedup pass (or an analyst) may have closed this finding
	// between enqueue and run; revalidating it would promote new->enriched,
	// cache a verdict, and chain a verify run on a finding nobody will look
	// at — wasted spend, and the promotion would clobber a just-applied
	// duplicate status back to enriched.
	if f.Status.Closed() {
		emit(Event{Kind: KindText, Text: fmt.Sprintf("finding %d is %s; skipping revalidate", f.ID, f.Status)})
		return nil
	}

	// Cache the verdict on the finding so the audit queue can filter
	// without scanning finding_notes (#362). Written before the status
	// transition so a true_positive promotion sits on top of the verdict
	// row in finding history.
	if err := db.WriteFindingField(w.DB, f.ID, "last_revalidate_verdict", result.Verdict, db.SourceModel, "revalidate"); err != nil {
		return fmt.Errorf("update last_revalidate_verdict: %w", err)
	}

	// Status transition: only true_positive promotes new -> enriched.
	// false_positive does not auto-reject; the analyst owns rejection.
	if result.Verdict == "true_positive" && f.Status == db.FindingNew {
		if err := db.WriteFindingField(w.DB, f.ID, "status", string(db.FindingEnriched), db.SourceModel, "revalidate"); err != nil {
			return fmt.Errorf("update status: %w", err)
		}
	}

	// Severity adjustment, with history. WriteFindingField is a no-op
	// when the value is unchanged, so an "adjusted" severity that
	// matches the original leaves the audit trail clean.
	if result.AdjustedSeverity != "" {
		switch result.AdjustedSeverity {
		case "Critical", "High", "Medium", "Low":
		default:
			return fmt.Errorf("revalidate adjusted_severity %q is not one of Critical|High|Medium|Low", result.AdjustedSeverity)
		}
		if err := db.WriteFindingField(w.DB, f.ID, "severity", result.AdjustedSeverity, db.SourceModel, "revalidate"); err != nil {
			return fmt.Errorf("update severity: %w", err)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "revalidate: %s\n", result.Verdict)
	if reason := strings.TrimSpace(result.Reason); reason != "" {
		fmt.Fprintf(&b, "\n%s\n", reason)
	}
	if result.AdjustedSeverity != "" {
		fmt.Fprintf(&b, "\nseverity %s -> %s", f.Severity, result.AdjustedSeverity)
		if r := strings.TrimSpace(result.AdjustedSeverityReason); r != "" {
			fmt.Fprintf(&b, ": %s", r)
		}
		b.WriteString("\n")
	}
	if _, err := db.AddFindingNote(w.DB, f.ID, b.String(), "revalidate"); err != nil {
		return fmt.Errorf("record revalidate note: %w", err)
	}

	emit(Event{Kind: KindText, Text: "finding " + fmt.Sprint(f.ID) + " -> " + result.Verdict})

	// Hand the verdict to the web layer for downstream chaining. The
	// post-adjustment severity is what the chain reads: when revalidate
	// downgrades a High to Medium, the chain to verify must respect that,
	// not the original claim.
	finalSeverity := f.Severity
	if result.AdjustedSeverity != "" {
		finalSeverity = result.AdjustedSeverity
	}
	if w.OnRevalidateVerdict != nil {
		w.OnRevalidateVerdict(scan, &f, result.Verdict, finalSeverity)
	}
	return nil
}

func (w *Worker) parseFindingDedupOutput(scan *db.Scan, report string, emit func(Event)) error {
	var result struct {
		Duplicates []struct {
			CanonicalID  uint   `json:"canonical_id"`
			DuplicateIDs []uint `json:"duplicate_ids"`
			Reason       string `json:"reason"`
		} `json:"duplicates"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		return fmt.Errorf("parse finding_dedup report: %w", err)
	}
	if len(result.Duplicates) == 0 {
		emit(Event{Kind: KindText, Text: "finding-dedup: no duplicates reported"})
		return nil
	}

	marked, skipped := 0, 0
	for _, group := range result.Duplicates {
		canonical, ok := w.dedupFinding(scan.RepositoryID, group.CanonicalID)
		if !ok || !dedupCandidateOpen(canonical.Status) {
			skipped += len(group.DuplicateIDs)
			continue
		}
		for _, duplicateID := range group.DuplicateIDs {
			if duplicateID == 0 || duplicateID == canonical.ID {
				skipped++
				continue
			}
			duplicate, ok := w.dedupFinding(scan.RepositoryID, duplicateID)
			if !ok || !dedupCandidateOpen(duplicate.Status) {
				skipped++
				continue
			}
			if err := db.WriteFindingField(w.DB, duplicate.ID, "status", string(db.FindingDuplicate), db.SourceModel, findingDedupSkill); err != nil {
				return fmt.Errorf("mark finding %d duplicate: %w", duplicate.ID, err)
			}
			if err := w.addDedupNote(duplicate.ID, canonical.ID, group.Reason); err != nil {
				return err
			}
			marked++
		}
	}

	emit(Event{Kind: KindText, Text: fmt.Sprintf("finding-dedup: marked %d duplicate(s), skipped %d", marked, skipped)})
	return nil
}

func (w *Worker) dedupFinding(repoID, findingID uint) (db.Finding, bool) {
	if findingID == 0 {
		return db.Finding{}, false
	}
	var f db.Finding
	if err := w.DB.First(&f, findingID).Error; err != nil {
		return db.Finding{}, false
	}
	if f.RepositoryID != repoID {
		return db.Finding{}, false
	}
	return f, true
}

// dedupCandidateOpen reports whether a finding is still in the active funnel
// and so eligible to be marked (or kept as) a duplicate. The complement of
// db.FindingLifecycle.Closed.
func dedupCandidateOpen(status db.FindingLifecycle) bool {
	return !status.Closed()
}

func (w *Worker) addDedupNote(duplicateID, canonicalID uint, reason string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "finding-dedup: duplicates finding #%d", canonicalID)
	if strings.TrimSpace(reason) != "" {
		fmt.Fprintf(&b, "\n\n%s", strings.TrimSpace(reason))
	}
	if _, err := db.AddFindingNote(w.DB, duplicateID, b.String(), findingDedupSkill); err != nil {
		return fmt.Errorf("record dedup note for finding %d: %w", duplicateID, err)
	}
	return nil
}

// parseTime accepts RFC3339 or date-only strings. Empty input is not an
// error; the caller decides whether to omit the field.
func parseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// parseTimeField wraps parseTime and emits a transcript line when a non-empty
// value matches none of the accepted layouts, so a model emitting timestamps
// in an unexpected format is visible in the scan log instead of silently
// dropping the field.
func parseTimeField(emit func(Event), field, s string) (time.Time, bool) {
	t, ok := parseTime(s)
	if !ok && s != "" {
		emit(Event{Kind: KindText, Text: fmt.Sprintf("ignoring unparseable %s value %q (want RFC3339 or YYYY-MM-DD)", field, s)})
	}
	return t, ok
}
