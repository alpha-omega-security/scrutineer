package worker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"scrutineer/internal/db"
)

const filePerm = 0o644

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

	workRoot := filepath.Join(w.DataDir, fmt.Sprintf("repo-%d", scan.RepositoryID))
	skillDir := filepath.Join(workRoot, ".claude", "skills", skill.Name)
	if err := stageSkill(&skill, skillDir); err != nil {
		return "", fmt.Errorf("stage skill: %w", err)
	}

	prompt := buildSkillPrompt(skill.Name, skill.OutputFile)
	scan.Prompt = prompt
	w.DB.Model(scan).Update("prompt", prompt)

	sj := SkillJob{
		Repo:       scan.Repository,
		DataDir:    w.DataDir,
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

	// Findings-shaped output feeds the existing parser so skill-driven audits
	// surface in the Findings tab alongside the legacy claude job.
	if skill.OutputKind == "findings" && res.Report != "" {
		rep, perr := parseReport([]byte(res.Report))
		if perr != nil {
			return res.Report, perr
		}
		findings := rep.toFindings(scan.ID)
		scan.FindingsCount = len(findings)
		if len(findings) > 0 {
			if err := w.DB.Create(&findings).Error; err != nil {
				return res.Report, fmt.Errorf("save findings: %w", err)
			}
		}
		emit(Event{Kind: KindText, Text: fmt.Sprintf("parsed %d finding(s)", len(findings))})
	}
	return res.Report, nil
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
