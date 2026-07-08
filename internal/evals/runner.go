//go:build evals

package evals

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/skills"
	"scrutineer/internal/worker"
)

const (
	dirPerm  = 0o755
	filePerm = 0o644
)

// Runner executes scenarios with a real worker.SkillRunner. It prepares the
// same workspace shape as a skill scan, but keeps database and queue state out
// of the eval loop so prompt changes can be measured quickly.
type Runner struct {
	Runner     worker.SkillRunner
	SkillsRoot string
	EvalsRoot  string
	WorkRoot   string
	Model      string
	Judge      Judge
}

func (r Runner) RunAll(ctx context.Context, scenarios []Scenario) ([]Result, error) {
	results := make([]Result, 0, len(scenarios))
	for _, sc := range scenarios {
		res, err := r.RunScenario(ctx, sc)
		if err != nil {
			return results, err
		}
		results = append(results, res)
	}
	return results, nil
}

func (r Runner) RunScenario(ctx context.Context, sc Scenario) (Result, error) {
	if r.Runner == nil {
		return Result{}, fmt.Errorf("eval runner requires a worker.SkillRunner")
	}
	judge := r.Judge
	if judge == nil {
		judge = HeuristicJudge{}
	}
	work, err := os.MkdirTemp(r.WorkRoot, "scrutineer-eval-*")
	if err != nil {
		return Result{}, fmt.Errorf("create eval workdir: %w", err)
	}
	defer func() { _ = os.RemoveAll(work) }()

	skill, err := r.loadSkill(sc.Skill)
	if err != nil {
		return Result{}, err
	}
	fixture := r.fixturePath(sc)
	if err := copyDir(fixture, filepath.Join(work, "src")); err != nil {
		return Result{}, fmt.Errorf("stage fixture %s: %w", fixture, err)
	}
	if err := r.stageWorkspace(work, skill); err != nil {
		return Result{}, err
	}

	var cost Cost
	emit := func(e worker.Event) {
		if e.Kind == worker.KindResult {
			cost.USD += e.CostUSD
			cost.Turns += e.Turns
			cost.InputTokens += e.Usage.InputTokens
			cost.OutputTokens += e.Usage.OutputTokens
			cost.CacheReadTokens += e.Usage.CacheReadTokens
			cost.CacheWriteTokens += e.Usage.CacheWriteTokens
		}
	}
	res, err := r.Runner.RunSkill(ctx, worker.SkillJob{
		Repo:       evalRepository(sc, fixture),
		WorkRoot:   work,
		Model:      r.Model,
		Name:       skill.Name,
		SkillDir:   r.Runner.SkillDir(work, skill.Name),
		OutputFile: skill.OutputFile,
		MaxTurns:   skill.MaxTurns,
		SrcReady:   true,
	}, emit)
	if err != nil {
		return Result{}, fmt.Errorf("%s: run %s: %w", sc.Path, sc.Skill, err)
	}
	matches, err := judge.Judge(sc, res.Report)
	if err != nil {
		return Result{}, fmt.Errorf("%s: judge: %w", sc.Path, err)
	}
	result := Result{
		Scenario:       sc,
		Commit:         res.Commit,
		Report:         res.Report,
		AssertionTotal: len(matches),
		Matches:        matches,
		Cost:           cost,
	}
	for _, m := range matches {
		switch {
		case !m.Matched && m.Kind == assertionShouldFind && m.Required:
			result.FailedRequired++
		case !m.Matched && m.Kind == assertionShouldFind:
			result.OptionalMisses++
		case !m.Matched && m.Kind == assertionShouldNotFind:
			result.Unexpected++
		}
	}
	return result, nil
}

func (r Runner) loadSkill(name string) (*db.Skill, error) {
	root := r.SkillsRoot
	if root == "" {
		root = "skills"
	}
	parsed, err := skills.ParseFile(filepath.Join(root, name, "SKILL.md"))
	if err != nil {
		return nil, err
	}
	model, err := parsed.ToModel("eval")
	if err != nil {
		return nil, err
	}
	model.Active = true
	model.Version = 1
	return model, nil
}

func (r Runner) fixturePath(sc Scenario) string {
	if filepath.IsAbs(sc.Fixture) {
		return sc.Fixture
	}
	root := r.EvalsRoot
	if root == "" {
		root = "evals"
	}
	return filepath.Join(root, sc.Fixture)
}

func (r Runner) stageWorkspace(work string, skill *db.Skill) error {
	ctx := map[string]any{
		"repository": map[string]any{
			"url":  "file://" + filepath.Join(work, "src"),
			"name": filepath.Base(filepath.Join(work, "src")),
		},
		"scrutineer": map[string]any{
			"api_base":      "http://127.0.0.1:0/api",
			"scan_id":       0,
			"token":         "eval-token",
			"repository_id": 0,
			"metadata_dir":  ".scrutineer/",
		},
	}
	b, err := json.MarshalIndent(ctx, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(work, "context.json"), b, filePerm); err != nil {
		return err
	}

	dst := r.Runner.SkillDir(work, skill.Name)
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	if err := copyDir(skill.SourcePath, dst); err != nil {
		return fmt.Errorf("stage skill dir: %w", err)
	}
	if skill.SchemaJSON != "" {
		if err := os.WriteFile(filepath.Join(work, "schema.json"), []byte(skill.SchemaJSON), filePerm); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(dst, "context.json"), b, filePerm); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(skill.SourcePath, "scripts")); err == nil {
		if err := copyDir(filepath.Join(skill.SourcePath, "scripts"), filepath.Join(work, "scripts")); err != nil {
			return fmt.Errorf("stage skill scripts: %w", err)
		}
	}
	return nil
}

func evalRepository(sc Scenario, fixture string) db.Repository {
	name := strings.TrimSuffix(filepath.Base(sc.Fixture), string(filepath.Separator))
	if name == "." || name == "" {
		name = filepath.Base(fixture)
	}
	return db.Repository{
		URL:  "file://" + fixture,
		Name: name,
	}
}

func copyDir(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", src)
	}
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return os.MkdirAll(dst, dirPerm)
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, dirPerm)
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		link, err := os.Readlink(src)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), dirPerm); err != nil {
			return err
		}
		return os.Symlink(link, dst)
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), dirPerm); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	_, err = io.Copy(out, in)
	return err
}
