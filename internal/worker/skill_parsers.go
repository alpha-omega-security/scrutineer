package worker

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"scrutineer/internal/db"
)

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
	if t, ok := parseTime(m.PushedAt); ok {
		updates["pushed_at"] = t
	}
	if m.HTMLURL != "" {
		updates["html_url"] = m.HTMLURL
	}
	if m.IconURL != "" {
		updates["icon_url"] = m.IconURL
	}
	if err := w.DB.Model(&db.Repository{}).Where("id = ?", scan.RepositoryID).Updates(updates).Error; err != nil {
		return fmt.Errorf("update repository: %w", err)
	}
	emit(Event{Kind: KindText, Text: "updated repository metadata"})
	return nil
}

// parsePackagesOutput replaces Package rows for the scan's repository. We
// delete all existing rows and insert whatever the skill produced, mirroring
// the old Go handler which did the same: packages are a projection of the
// upstream registry state, not an incrementally grown set.
func (w *Worker) parsePackagesOutput(scan *db.Scan, report string, emit func(Event)) error {
	var result struct {
		Packages []struct {
			Name                 string  `json:"name"`
			Ecosystem            string  `json:"ecosystem"`
			PURL                 string  `json:"purl"`
			Licenses             string  `json:"licenses"`
			LatestVersion        string  `json:"latest_version"`
			VersionsCount        int     `json:"versions_count"`
			Downloads            int64   `json:"downloads"`
			DependentPackages    int     `json:"dependent_packages"`
			DependentRepos       int     `json:"dependent_repos"`
			RegistryURL          string  `json:"registry_url"`
			LatestReleaseAt      string  `json:"latest_release_at"`
			DependentPackagesURL string  `json:"dependent_packages_url"`
			Metadata             any     `json:"metadata"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		return fmt.Errorf("parse packages: %w", err)
	}
	if err := w.DB.Where("repository_id = ?", scan.RepositoryID).Delete(&db.Package{}).Error; err != nil {
		return fmt.Errorf("delete old packages: %w", err)
	}
	rows := make([]db.Package, 0, len(result.Packages))
	for _, p := range result.Packages {
		row := db.Package{
			RepositoryID:         scan.RepositoryID,
			Name:                 p.Name,
			Ecosystem:            p.Ecosystem,
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
		if t, ok := parseTime(p.LatestReleaseAt); ok {
			row.LatestReleaseAt = &t
		}
		if p.Metadata != nil {
			if b, err := json.Marshal(p.Metadata); err == nil {
				row.Metadata = string(b)
			}
		}
		rows = append(rows, row)
	}
	if len(rows) > 0 {
		if err := w.DB.Create(&rows).Error; err != nil {
			return fmt.Errorf("save packages: %w", err)
		}
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
	if err := w.DB.Where("repository_id = ?", scan.RepositoryID).Delete(&db.Advisory{}).Error; err != nil {
		return fmt.Errorf("delete old advisories: %w", err)
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
		if t, ok := parseTime(a.PublishedAt); ok {
			row.PublishedAt = &t
		}
		if t, ok := parseTime(a.WithdrawnAt); ok {
			row.WithdrawnAt = &t
		}
		rows = append(rows, row)
	}
	if len(rows) > 0 {
		if err := w.DB.Create(&rows).Error; err != nil {
			return fmt.Errorf("save advisories: %w", err)
		}
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("saved %d advisor(ies)", len(rows))})
	return nil
}

// parseDependentsOutput replaces Dependent rows for the scan's repository.
func (w *Worker) parseDependentsOutput(scan *db.Scan, report string, emit func(Event)) error {
	var result struct {
		Dependents []struct {
			Name           string `json:"name"`
			Ecosystem      string `json:"ecosystem"`
			PURL           string `json:"purl"`
			RepositoryURL  string `json:"repository_url"`
			Downloads      int64  `json:"downloads"`
			DependentRepos int    `json:"dependent_repos"`
			RegistryURL    string `json:"registry_url"`
			LatestVersion  string `json:"latest_version"`
		} `json:"dependents"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		return fmt.Errorf("parse dependents: %w", err)
	}
	if err := w.DB.Where("repository_id = ?", scan.RepositoryID).Delete(&db.Dependent{}).Error; err != nil {
		return fmt.Errorf("delete old dependents: %w", err)
	}
	rows := make([]db.Dependent, 0, len(result.Dependents))
	for _, d := range result.Dependents {
		rows = append(rows, db.Dependent{
			RepositoryID:   scan.RepositoryID,
			Name:           d.Name,
			Ecosystem:      d.Ecosystem,
			PURL:           d.PURL,
			RepositoryURL:  d.RepositoryURL,
			Downloads:      d.Downloads,
			DependentRepos: d.DependentRepos,
			RegistryURL:    d.RegistryURL,
			LatestVersion:  d.LatestVersion,
		})
	}
	if len(rows) > 0 {
		if err := w.DB.Create(&rows).Error; err != nil {
			return fmt.Errorf("save dependents: %w", err)
		}
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("saved %d dependent(s)", len(rows))})
	return nil
}

// parseDependenciesOutput replaces Dependency rows for the scan's repository.
// Dependencies come from a git-pkgs-style manifest scan: one row per
// (name, ecosystem, manifest_path) tuple.
func (w *Worker) parseDependenciesOutput(scan *db.Scan, report string, emit func(Event)) error {
	var result struct {
		Dependencies []struct {
			Name           string `json:"name"`
			Ecosystem      string `json:"ecosystem"`
			PURL           string `json:"purl"`
			Requirement    string `json:"requirement"`
			Type           string `json:"type"`
			DependencyType string `json:"dependency_type"`
			ManifestPath   string `json:"manifest_path"`
			ManifestKind   string `json:"manifest_kind"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		return fmt.Errorf("parse dependencies: %w", err)
	}
	if err := w.DB.Where("repository_id = ?", scan.RepositoryID).Delete(&db.Dependency{}).Error; err != nil {
		return fmt.Errorf("delete old dependencies: %w", err)
	}
	rows := make([]db.Dependency, 0, len(result.Dependencies))
	for _, d := range result.Dependencies {
		depType := d.Type
		if depType == "" {
			depType = d.DependencyType
		}
		rows = append(rows, db.Dependency{
			RepositoryID:   scan.RepositoryID,
			Name:           d.Name,
			Ecosystem:      d.Ecosystem,
			PURL:           d.PURL,
			Requirement:    d.Requirement,
			DependencyType: depType,
			ManifestPath:   d.ManifestPath,
			ManifestKind:   d.ManifestKind,
		})
	}
	if len(rows) > 0 {
		if err := w.DB.Create(&rows).Error; err != nil {
			return fmt.Errorf("save dependencies: %w", err)
		}
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("saved %d dependenc(ies)", len(rows))})
	return nil
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
	if err := w.DB.Where("repository_id = ?", scan.RepositoryID).Delete(&db.Subproject{}).Error; err != nil {
		return fmt.Errorf("delete old subprojects: %w", err)
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
	if len(rows) > 0 {
		if err := w.DB.Create(&rows).Error; err != nil {
			return fmt.Errorf("save subprojects: %w", err)
		}
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("saved %d subproject(s)", len(rows))})
	return nil
}

// parseRepoOverviewOutput reads `brief`'s structured output and backfills
// fields on the Repository row that the metadata skill left empty. Only
// empty fields are touched — a value coming from ecosyste.ms (via the
// metadata skill) is considered authoritative and won't be overwritten
// by brief's heuristic detection.
func (w *Worker) parseRepoOverviewOutput(scan *db.Scan, report string, emit func(Event)) error {
	var result struct {
		Languages []struct {
			Name     string `json:"name"`
			Category string `json:"category"`
		} `json:"languages"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		// brief output may be wrapped or errored; don't fail the scan
		// over a backfill pass.
		emit(Event{Kind: KindText, Text: "repo-overview: skipping backfill, unparseable JSON"})
		return nil
	}
	var names []string
	for _, l := range result.Languages {
		if l.Category != "" && l.Category != "language" {
			continue
		}
		if l.Name != "" {
			names = append(names, l.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	var repo db.Repository
	if err := w.DB.First(&repo, scan.RepositoryID).Error; err != nil {
		return fmt.Errorf("load repo: %w", err)
	}
	if strings.TrimSpace(repo.Languages) != "" {
		return nil
	}
	joined := strings.Join(names, ", ")
	if err := w.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
		Update("languages", joined).Error; err != nil {
		return fmt.Errorf("update languages: %w", err)
	}
	emit(Event{Kind: KindText, Text: "repo-overview: backfilled languages = " + joined})
	return nil
}

// parseVerifyOutput records the outcome of a finding-scoped verification
// run. Evidence and notes become a FindingNote; the status transition is
// written via WriteFindingField with source=model_suggested so the audit
// trail on the finding page shows the skill as the author.
func (w *Worker) parseVerifyOutput(scan *db.Scan, report string, emit func(Event)) error {
	if scan.FindingID == nil {
		return fmt.Errorf("verify scan has no finding_id")
	}
	var result struct {
		Status   string `json:"status"`
		Evidence string `json:"evidence"`
		Notes    string `json:"notes"`
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
		nextStatus = db.FindingFixed
	case "inconclusive":
		// Leave status alone.
	default:
		return fmt.Errorf("verify status %q is not one of confirmed|fixed|inconclusive", result.Status)
	}
	if nextStatus != "" {
		if err := db.WriteFindingField(w.DB, f.ID, "status", string(nextStatus), db.SourceModel, "verify"); err != nil {
			return fmt.Errorf("update status: %w", err)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "verify: %s\n", result.Status)
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
