package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"scrutineer/internal/db"
)

const filePerm = 0o644

// skillContext is the JSON document scrutineer writes to ./context.json in
// every skill workspace before invoking claude. Skills that need to know who
// they are scanning (or need to call back into scrutineer) read this file.
type skillContext struct {
	Repository skillContextRepo  `json:"repository"`
	Commit     string            `json:"commit,omitempty"`
	Packages   []skillContextPkg `json:"packages,omitempty"`
	// Scrutineer lets a skill call back into the host app: list prior scans,
	// enqueue further skills, read reports. The schema is openapi.yaml at
	// the repo root.
	Scrutineer skillContextScrutineer `json:"scrutineer"`
}

type skillContextScrutineer struct {
	APIBase   string `json:"api_base"`             // e.g. http://127.0.0.1:8080/api
	ScanID    uint   `json:"scan_id"`              // the scan that owns this run
	Token     string `json:"token"`                // bearer for api_base
	RepoID    uint   `json:"repository_id"`        // convenience for URL building
	SkillID   uint   `json:"skill_id,omitempty"`   // the running skill
	FindingID uint   `json:"finding_id,omitempty"` // set for finding-scoped scans
	// ScanSubPath scopes code analysis to a sub-folder of ./src (monorepo
	// support). Empty means the repo root. Skills that walk files honour
	// this; skills that query external APIs ignore it.
	ScanSubPath string `json:"scan_subpath,omitempty"`
}

type skillContextRepo struct {
	URL           string `json:"url"`
	HTMLURL       string `json:"html_url,omitempty"`
	Name          string `json:"name,omitempty"`
	FullName      string `json:"full_name,omitempty"`
	DefaultBranch string `json:"default_branch,omitempty"`
}

type skillContextPkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem,omitempty"`
	PURL      string `json:"purl,omitempty"`
}

// doSkill stages the referenced skill under the scan's workspace and invokes
// claude-code, which discovers project-level skills at ./.claude/skills and
// follows the body of the selected SKILL.md. If the skill declares an output
// file in its frontmatter metadata, the contents land in Scan.Report and,
// when output_kind is "findings", parse into Finding rows.
func (w *Worker) doSkill(ctx context.Context, scan *db.Scan, emit func(Event)) (string, error) {
	if scan.SkillID == nil {
		return "", fmt.Errorf("scan %d has no skill id", scan.ID)
	}
	var skill db.Skill
	if err := w.DB.First(&skill, *scan.SkillID).Error; err != nil {
		return "", fmt.Errorf("load skill %d: %w", *scan.SkillID, err)
	}
	scan.SkillName = skill.Name
	scan.SkillVersion = skill.Version
	w.DB.Model(scan).Updates(map[string]any{
		"skill_name":    skill.Name,
		"skill_version": skill.Version,
	})

	// Per-scan workspace keeps concurrent skills on the same repo from
	// clobbering each other's src/ and report.json. wrap() removes it on
	// successful completion; failed/cancelled dirs are left so the
	// operator can inspect what the skill saw.
	workRoot := w.workRoot(scan.ID)
	skillDir := filepath.Join(workRoot, ".claude", "skills", skill.Name)
	if err := stageSkill(&skill, skillDir); err != nil {
		return "", fmt.Errorf("stage skill: %w", err)
	}
	if err := stageContext(workRoot, w.APIBase, scan, &scan.Repository); err != nil {
		return "", fmt.Errorf("stage context: %w", err)
	}

	prompt := buildSkillPrompt(skill.Name, skill.OutputFile)
	scan.Prompt = prompt
	w.DB.Model(scan).Update("prompt", prompt)

	sj := SkillJob{
		Repo:       scan.Repository,
		WorkRoot:   workRoot,
		Model:      scan.Model,
		Name:       skill.Name,
		SkillDir:   skillDir,
		OutputFile: skill.OutputFile,
	}
	res, err := w.Runner.RunSkill(ctx, sj, emit)
	scan.Commit = res.Commit
	if err != nil {
		return res.Report, err
	}

	if res.Report == "" {
		return res.Report, nil
	}
	switch skill.OutputKind {
	case "findings":
		if err := w.parseFindingsOutput(scan, res.Report, emit); err != nil {
			return res.Report, err
		}
	case "maintainers":
		if err := w.parseMaintainersOutput(scan, res.Report, emit); err != nil {
			return res.Report, err
		}
	case "repo_metadata":
		if err := w.parseRepoMetadataOutput(scan, res.Report, emit); err != nil {
			return res.Report, err
		}
	case "packages":
		if err := w.parsePackagesOutput(scan, res.Report, emit); err != nil {
			return res.Report, err
		}
	case "advisories":
		if err := w.parseAdvisoriesOutput(scan, res.Report, emit); err != nil {
			return res.Report, err
		}
	case "dependents":
		if err := w.parseDependentsOutput(scan, res.Report, emit); err != nil {
			return res.Report, err
		}
	case "dependencies":
		if err := w.parseDependenciesOutput(scan, res.Report, emit); err != nil {
			return res.Report, err
		}
	case "verify":
		if err := w.parseVerifyOutput(scan, res.Report, emit); err != nil {
			return res.Report, err
		}
	case "subprojects":
		if err := w.parseSubprojectsOutput(scan, res.Report, emit); err != nil {
			return res.Report, err
		}
	case "repo_overview":
		if err := w.parseRepoOverviewOutput(scan, res.Report, emit); err != nil {
			return res.Report, err
		}
	}
	return res.Report, nil
}

// parseFindingsOutput feeds the existing spec-deep parser so skill-driven
// audits surface in the Findings tab alongside the legacy claude job.
// Findings are deduped against prior scans of the same repository by
// fingerprint: a match bumps last-seen on the existing row instead of
// creating a duplicate, so analyst triage state survives a rescan (#75).
func (w *Worker) parseFindingsOutput(scan *db.Scan, report string, emit func(Event)) error {
	rep, err := parseReport([]byte(report))
	if err != nil {
		return err
	}
	findings := rep.toFindings(scan.ID, scan.RepositoryID, scan.Commit, scan.SubPath)
	scan.FindingsCount = len(findings)

	created, observed := 0, 0
	seenThisScan := map[string]bool{}
	for i := range findings {
		f := &findings[i]
		f.Fingerprint = db.FingerprintFinding(scan.SkillName, f.SubPath, f.CWE, f.Location, f.Title)
		f.LastSeenScanID = scan.ID
		f.LastSeenCommit = scan.Commit
		f.SeenCount = 1

		if seenThisScan[f.Fingerprint] {
			continue
		}
		seenThisScan[f.Fingerprint] = true

		var existing db.Finding
		err := w.DB.Where("repository_id = ? AND fingerprint = ?", scan.RepositoryID, f.Fingerprint).
			Order("id").First(&existing).Error
		if err == nil {
			if uerr := w.DB.Model(&db.Finding{}).Where("id = ?", existing.ID).Updates(map[string]any{
				"last_seen_scan_id": scan.ID,
				"last_seen_commit":  scan.Commit,
				"seen_count":        existing.SeenCount + 1,
			}).Error; uerr != nil {
				return fmt.Errorf("update finding %d: %w", existing.ID, uerr)
			}
			_ = w.DB.Create(&db.FindingHistory{
				FindingID: existing.ID,
				Field:     "observed",
				NewValue:  fmt.Sprintf("scan %d @ %s", scan.ID, scan.Commit),
				Source:    db.SourceTool,
				By:        scan.SkillName,
			}).Error
			observed++
			continue
		}
		if cerr := w.DB.Create(f).Error; cerr != nil {
			return fmt.Errorf("save finding: %w", cerr)
		}
		created++
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("parsed %d finding(s): %d new, %d re-observed",
		len(findings), created, observed)})
	return nil
}

// parseMaintainersOutput upserts Maintainer rows and links them to the
// scanned repo. Mirrors the legacy doMaintainerAnalysis logic so the
// maintainers skill and the old Go handler stay interchangeable.
func (w *Worker) parseMaintainersOutput(scan *db.Scan, report string, emit func(Event)) error {
	var result struct {
		Maintainers []struct {
			Login    string `json:"login"`
			Name     string `json:"name"`
			Email    string `json:"email"`
			Role     string `json:"role"`
			Status   string `json:"status"`
			Evidence string `json:"evidence"`
		} `json:"maintainers"`
		DisclosureChannel string `json:"disclosure_channel"`
	}
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		return fmt.Errorf("parse maintainers report: %w", err)
	}
	var repo db.Repository
	if err := w.DB.First(&repo, scan.RepositoryID).Error; err != nil {
		return err
	}
	if strings.TrimSpace(result.DisclosureChannel) != "" {
		if err := w.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
			Update("disclosure_channel", result.DisclosureChannel).Error; err != nil {
			return fmt.Errorf("update disclosure channel: %w", err)
		}
	}
	var linked []db.Maintainer
	for _, rm := range result.Maintainers {
		if rm.Login == "" {
			continue
		}
		var m db.Maintainer
		w.DB.Where(db.Maintainer{Login: rm.Login}).FirstOrCreate(&m)
		if rm.Name != "" {
			m.Name = rm.Name
		}
		if validEmail(rm.Email) {
			m.Email = rm.Email
		}
		switch rm.Status {
		case "active":
			m.Status = db.MaintainerActive
		case "inactive":
			m.Status = db.MaintainerInactive
		}
		if rm.Evidence != "" {
			m.Notes = rm.Role + ": " + rm.Evidence
		}
		w.DB.Save(&m)
		linked = append(linked, m)
	}
	if len(linked) > 0 {
		_ = w.DB.Model(&repo).Association("Maintainers").Replace(linked)
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("identified %d maintainer(s)", len(result.Maintainers))})
	return nil
}

// stageSkill writes the skill's files into dst so claude-code discovers them
// at ./.claude/skills/{name}. Only SKILL.md and schema.json are reconstructed
// from the DB; supplementary files (scripts/, references/, assets/) are
// copied from SourcePath when the skill was loaded from disk.
func stageSkill(skill *db.Skill, dst string) error {
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	if err := os.MkdirAll(dst, dirPerm); err != nil {
		return err
	}
	skillMD := renderSkillMD(skill)
	if err := os.WriteFile(filepath.Join(dst, "SKILL.md"), []byte(skillMD), filePerm); err != nil {
		return err
	}
	if skill.SchemaJSON != "" {
		if err := os.WriteFile(filepath.Join(dst, "schema.json"), []byte(skill.SchemaJSON), filePerm); err != nil {
			return err
		}
	}
	if skill.SourcePath != "" && skill.Source != "ui" {
		if err := copyAux(skill.SourcePath, dst); err != nil {
			return fmt.Errorf("copy aux files: %w", err)
		}
	}
	return nil
}

// renderSkillMD rebuilds a SKILL.md from the stored fields. The frontmatter
// is re-serialised rather than preserved verbatim so UI edits round-trip
// cleanly; order is not preserved but the spec doesn't require it.
func renderSkillMD(skill *db.Skill) string {
	var b strings.Builder
	b.WriteString("---\n")
	fmt.Fprintf(&b, "name: %s\n", skill.Name)
	fmt.Fprintf(&b, "description: %s\n", oneLine(skill.Description))
	if skill.License != "" {
		fmt.Fprintf(&b, "license: %s\n", oneLine(skill.License))
	}
	if skill.Compatibility != "" {
		fmt.Fprintf(&b, "compatibility: %s\n", oneLine(skill.Compatibility))
	}
	if skill.AllowedTools != "" {
		fmt.Fprintf(&b, "allowed-tools: %s\n", skill.AllowedTools)
	}
	if skill.Metadata != "" {
		fmt.Fprintf(&b, "metadata_json: %s\n", oneLine(skill.Metadata))
	}
	b.WriteString("---\n\n")
	b.WriteString(skill.Body)
	if !strings.HasSuffix(skill.Body, "\n") {
		b.WriteString("\n")
	}
	return b.String()
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

// stageContext writes the workspace-level context.json that every skill can
// rely on. Kept small and boring on purpose: skills that need more detail
// can read it from the clone. The scrutineer block gives skills enough to
// call back into the host API (list scans, trigger more skills).
func stageContext(workRoot, apiBase string, scan *db.Scan, repo *db.Repository) error {
	if err := os.MkdirAll(workRoot, dirPerm); err != nil {
		return err
	}
	ctx := skillContext{
		Repository: skillContextRepo{
			URL:           repo.URL,
			HTMLURL:       repo.HTMLURL,
			Name:          repo.Name,
			FullName:      repo.FullName,
			DefaultBranch: repo.DefaultBranch,
		},
		Scrutineer: skillContextScrutineer{
			APIBase: apiBase,
			ScanID:  scan.ID,
			Token:   scan.APIToken,
			RepoID:  scan.RepositoryID,
		},
	}
	if scan.SkillID != nil {
		ctx.Scrutineer.SkillID = *scan.SkillID
	}
	if scan.FindingID != nil {
		ctx.Scrutineer.FindingID = *scan.FindingID
	}
	if scan.SubPath != "" {
		ctx.Scrutineer.ScanSubPath = scan.SubPath
	}
	b, err := json.MarshalIndent(ctx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(workRoot, "context.json"), b, filePerm)
}

// copyAux walks src looking for any files other than SKILL.md and schema.json
// (which are staged from the DB row) and copies them into dst at the same
// relative path. This preserves scripts/ and references/ for skills that
// bundle them.
func copyAux(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." || rel == "SKILL.md" || rel == "schema.json" {
			return nil
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, dirPerm)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, info.Mode())
	})
}
