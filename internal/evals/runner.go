//go:build evals

package evals

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/findingnorm"
	"scrutineer/internal/skills"
	"scrutineer/internal/worker"
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
	var errs []error
	for _, sc := range scenarios {
		res, err := r.RunScenario(ctx, sc)
		if err != nil {
			res = Result{Scenario: sc, Error: err.Error()}
			errs = append(errs, err)
		}
		results = append(results, res)
	}
	return results, errors.Join(errs...)
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
	fixture, err := r.fixturePath(sc)
	if err != nil {
		return Result{}, err
	}
	src := filepath.Join(work, "src")
	if err := worker.CopyTree(fixture, src); err != nil {
		return Result{}, fmt.Errorf("stage fixture %s: %w", fixture, err)
	}
	if err := ensureFixtureGitRepo(ctx, src); err != nil {
		return Result{}, fmt.Errorf("stage fixture git repo: %w", err)
	}
	repo := evalRepository(sc, fixture)
	if err := r.stageWorkspace(work, skill, repo); err != nil {
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
		Repo:       repo,
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
	if detail := worker.ValidateReportSchema(skill.SchemaJSON, res.Report); detail != "" {
		return Result{}, fmt.Errorf("%s: %s failed schema validation: %s", sc.Path, skill.OutputFile, detail)
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
	if err := worker.ValidateSkillPaths(model.Name, model.OutputFile); err != nil {
		return nil, err
	}
	return model, nil
}

func (r Runner) fixturePath(sc Scenario) (string, error) {
	raw := strings.TrimSpace(strings.ReplaceAll(sc.Fixture, "\\", "/"))
	if path.IsAbs(raw) || hasWindowsVolume(raw) || findingnorm.HasParentPathSegment(raw) {
		return "", fmt.Errorf("%s: fixture must be relative to evals root", sc.Path)
	}
	root := r.EvalsRoot
	if root == "" {
		root = "evals"
	}
	return filepath.Join(root, filepath.FromSlash(raw)), nil
}

func hasWindowsVolume(p string) bool {
	return len(p) >= 2 && p[1] == ':'
}

func ensureFixtureGitRepo(ctx context.Context, src string) error {
	if err := runGit(ctx, src, "rev-parse", "--verify", "HEAD"); err == nil {
		return nil
	}
	if err := runGit(ctx, src, "init"); err != nil {
		return err
	}
	if err := runGit(ctx, src, "add", "-A"); err != nil {
		return err
	}
	return runGit(ctx, src,
		"-c", "commit.gpgsign=false",
		"-c", "gpg.format=openpgp",
		"-c", "user.name=Scrutineer Eval",
		"-c", "user.email=evals@scrutineer.local",
		"commit", "-m", "eval fixture",
	)
}

func runGit(ctx context.Context, dir string, args ...string) error {
	cmdArgs := append([]string{"-C", dir}, args...)
	cmd := exec.CommandContext(ctx, "git", cmdArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (r Runner) stageWorkspace(work string, skill *db.Skill, repo db.Repository) error {
	scan := db.Scan{
		Repository: repo,
		APIToken:   "eval-token",
	}
	return worker.StageWorkspace(
		work,
		r.Runner.SkillDir(work, skill.Name),
		"http://127.0.0.1:0/api",
		"",
		worker.DefaultMetadataDir,
		&scan,
		skill,
	)
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
