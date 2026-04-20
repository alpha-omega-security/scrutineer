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
