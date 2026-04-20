package worker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"scrutineer/internal/db"
)

// ClaudeRunner is split out so tests and future docker-based execution can
// substitute the process launch without touching the queue plumbing.
type ClaudeRunner interface {
	Prompt(repo db.Repository, spec string) string
	Run(ctx context.Context, job Job, emit func(Event)) (Result, error)
	RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error)
}

// SkillJob is a scan driven by an on-disk claude-code skill. The runner
// clones the repo, stages the skill under .claude/skills/{Name}/ next to
// the clone, and invokes `claude -p` with a short activation prompt that
// tells the agent which skill to load. OutputFile (when set) is the path
// the skill writes to; the runner reads it back as the report.
type SkillJob struct {
	Repo      db.Repository
	DataDir   string
	Model     string
	Name      string
	SkillDir  string // host absolute path to the staged skill directory
	OutputFile string // relative to the scan workspace, e.g. "report.json"
}

type SkillResult struct {
	Commit string
	Report string // contents of OutputFile, or "" if none declared/written
}

// Job is everything the runner needs for one invocation. Model and Prompt
// come from the Scan row so the choice made in the UI is what actually runs.
type Job struct {
	Repo    db.Repository
	DataDir string
	Model   string
	Prompt  string
}

type Result struct {
	Commit string
	Report string
}

type LocalClaude struct {
	Effort string
}

// Prompt assembles the full text handed to claude. The spec supplies the
// audit methodology; we append the output contract so any spec produces the
// same machine-readable shape.
func (l LocalClaude) Prompt(repo db.Repository, spec string) string {
	return fmt.Sprintf(
		"The repository %s is cloned at ./src.\n\n"+
			"%s\n\n"+
			"---\n\n"+
			"Write your results as JSON to ./report.json conforming to the report schema below. "+
			"The report schema references defs.schema.json for shared vocabulary (severity, sink_class, etc). "+
			"Use an empty findings array if you found nothing. Do not write any other output file.\n\n"+
			"### defs.schema.json (shared vocabulary)\n```json\n%s```\n\n"+
			"### spec-json.schema.json (report format)\n```json\n%s```\n",
		repo.URL, strings.TrimSpace(spec), DefsSchema, FindingsSchema)
}

func (l LocalClaude) Run(ctx context.Context, job Job, emit func(Event)) (Result, error) {
	src, err := ensureClone(ctx, job.Repo, job.DataDir, emit)
	if err != nil {
		return Result{}, err
	}
	commit := gitHead(src)
	work := filepath.Dir(src)

	reportPath := filepath.Join(work, "report.json")
	_ = os.Remove(reportPath)

	args := []string{
		"-p",
		"--output-format", "stream-json",
		"--verbose",
		"--permission-mode", "bypassPermissions",
		"--model", job.Model,
	}
	if l.Effort != "" {
		args = append(args, "--effort", l.Effort)
	}
	args = append(args, job.Prompt)

	cmd := exec.CommandContext(ctx, "claude", args...)
	cmd.Dir = work
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, err
	}
	cmd.Stderr = cmd.Stdout

	emit(Event{Kind: KindText, Text: "$ claude " + strings.Join(args[:len(args)-1], " ") + " <prompt>"})
	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("start claude: %w", err)
	}

	ParseStream(stdout, emit)
	waitErr := cmd.Wait()

	// Reap anything claude spawned (repro scripts have outlived the parent
	// before; see mythos/harness readme).
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}

	report, _ := os.ReadFile(reportPath)
	res := Result{Commit: commit, Report: string(report)}
	if waitErr != nil && len(report) == 0 {
		return res, fmt.Errorf("claude exited: %w", waitErr)
	}
	if len(report) == 0 {
		return res, fmt.Errorf("claude exited 0 but wrote no report")
	}
	return res, nil
}

// RunSkill runs claude against a staged skill in a local workspace. The
// workspace layout is:
//   {DataDir}/repo-{id}/src/                clone (read-only in docker)
//   {DataDir}/repo-{id}/.claude/skills/NAME staged skill (read by claude-code)
//   {DataDir}/repo-{id}/OutputFile          where the skill writes, if any
func (l LocalClaude) RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	src, err := ensureClone(ctx, sj.Repo, sj.DataDir, emit)
	if err != nil {
		return SkillResult{}, err
	}
	commit := gitHead(src)
	work := filepath.Dir(src)

	var outPath string
	if sj.OutputFile != "" {
		outPath = filepath.Join(work, sj.OutputFile)
		_ = os.Remove(outPath)
	}

	prompt := buildSkillPrompt(sj.Name, sj.OutputFile)
	args := []string{
		"-p",
		"--output-format", "stream-json",
		"--verbose",
		"--permission-mode", "bypassPermissions",
		"--model", sj.Model,
	}
	if l.Effort != "" {
		args = append(args, "--effort", l.Effort)
	}
	args = append(args, prompt)

	cmd := exec.CommandContext(ctx, "claude", args...)
	cmd.Dir = work
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return SkillResult{}, err
	}
	cmd.Stderr = cmd.Stdout

	emit(Event{Kind: KindText, Text: "$ claude -p <skill:" + sj.Name + ">"})
	if err := cmd.Start(); err != nil {
		return SkillResult{}, fmt.Errorf("start claude: %w", err)
	}

	ParseStream(stdout, emit)
	waitErr := cmd.Wait()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}

	res := SkillResult{Commit: commit}
	if outPath != "" {
		b, _ := os.ReadFile(outPath)
		res.Report = string(b)
	}
	if waitErr != nil {
		return res, fmt.Errorf("claude exited: %w", waitErr)
	}
	return res, nil
}

// buildSkillPrompt is the activation prompt handed to claude. It's a thin
// wrapper: the skill's SKILL.md holds the actual instructions, we just tell
// claude which skill to use and where the repo lives.
func buildSkillPrompt(name, outputFile string) string {
	p := fmt.Sprintf("Use the %q skill on the repository cloned at ./src.", name)
	if outputFile != "" {
		p += fmt.Sprintf(" Write your structured output to ./%s as the skill specifies.", outputFile)
	}
	return p
}

