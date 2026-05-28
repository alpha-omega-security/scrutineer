package worker

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"scrutineer/internal/db"
)

// DefaultSkillMaxTurns is the turn cap applied when neither the skill's
// metadata nor the global config set a value.
const DefaultSkillMaxTurns = 30

// MaxTurnsReachedError is returned when claude-code exits after hitting the
// --max-turns cap. The caller should treat this as a soft completion.
type MaxTurnsReachedError struct{}

func (MaxTurnsReachedError) Error() string { return "hit max turns cap" }

// SkillRunner executes one skill scan. Tests and the docker-backed runner
// substitute the process launch without touching the queue plumbing.
type SkillRunner interface {
	RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error)
}

// SkillJob is a scan driven by an on-disk claude-code skill. The runner
// clones the repo, stages the skill under .claude/skills/{Name}/ next to
// the clone, and invokes `claude -p` with a short activation prompt that
// tells the agent which skill to load. OutputFile (when set) is the path
// the skill writes to; the runner reads it back as the report.
//
// WorkRoot is the per-scan host directory scrutineer created for this
// run. Keeping it per-scan (scan-{id}) instead of per-repo means two
// parallel skills on the same repository do not share src or
// report.json, so neither clobbers the other's output.
type SkillJob struct {
	Repo         db.Repository
	WorkRoot     string
	Model        string
	Name         string
	SkillDir     string // host absolute path to the staged skill directory
	OutputFile   string // relative to the scan workspace, e.g. "report.json"
	Ref          string // git ref to checkout; empty = default branch
	MaxTurns     int    // per-skill cap; 0 = use runner default
	AllowedTools string // comma-separated; "" = full tool set under bypassPermissions
	// SrcReady declares that WorkRoot/src is already populated by the
	// caller (e.g. by the exposure handler copying from a dependent
	// cache). When true the runner skips its own clone and reads HEAD
	// from the existing tree.
	SrcReady bool
	// Profile names a runner profile (docker/profiles/<name>/). Empty
	// means "auto-detect from the clone"; "default" forces the default
	// runner image. Only the docker runner honours this; the local
	// runner ignores it (no per-profile image to swap to).
	Profile string
	// RequiresProfile pins the skill to a named profile. When set, the
	// runner fails the scan if the resolved profile does not match.
	// Empty means no constraint. Mirrors db.Skill.RequiresProfile.
	RequiresProfile string
}

type SkillResult struct {
	Commit string
	Report string // contents of OutputFile, or "" if none declared/written
	// Profile is the runner profile actually used. Empty when the
	// default runner image ran. The worker persists this on the scan
	// so retries and the UI can show what was picked.
	Profile string
}

type LocalClaude struct {
	Effort    string
	FullClone bool
	MaxTurns  int
}

// RunSkill runs claude against a staged skill in a local workspace. The
// workspace layout is:
//
//	{DataDir}/scan-{id}/src/                clone (read-only in docker)
//	{DataDir}/scan-{id}/.claude/skills/NAME staged skill (read by claude-code)
//	{DataDir}/scan-{id}/OutputFile          where the skill writes, if any
func (l LocalClaude) RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	var src string
	if sj.SrcReady {
		src = filepath.Join(sj.WorkRoot, "src")
	} else {
		var err error
		src, err = ensureClone(ctx, sj.Repo, sj.WorkRoot, l.FullClone, sj.Ref, emit)
		if err != nil {
			return SkillResult{}, err
		}
	}
	commit := gitHead(src)
	work := sj.WorkRoot

	if sj.RequiresProfile != "" {
		return SkillResult{Commit: commit}, fmt.Errorf("skill %q requires profile %q, not supported by the local runner", sj.Name, sj.RequiresProfile)
	}

	var outPath string
	if sj.OutputFile != "" {
		outPath = filepath.Join(work, sj.OutputFile)
		_ = os.Remove(outPath)
	}

	args := buildClaudeArgs(sj, l.Effort, l.MaxTurns)
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

	hitMaxTurns := false
	wrappedEmit := func(e Event) {
		if e.Kind == KindError && e.Text == "hit max turns" {
			hitMaxTurns = true
		}
		emit(e)
	}
	ParseStream(stdout, wrappedEmit)
	waitErr := cmd.Wait()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}

	res := SkillResult{Commit: commit}
	if outPath != "" {
		res.Report = readCappedReport(outPath, emit)
	}
	if waitErr != nil {
		if hitMaxTurns {
			return res, &MaxTurnsReachedError{}
		}
		return res, fmt.Errorf("claude exited: %w", waitErr)
	}
	return res, nil
}

// maxReportBytes caps how much of a skill's report.json scrutineer will
// read back into memory. The report lands in Scan.Report (sqlite TEXT
// column) and is rendered unescaped in the UI, so an unbounded skill
// output is a trivial DoS vector for the local worker. 50 MB is well
// above any reasonable skill output — the largest legitimate report
// we've seen in practice is ~500 KB.
const maxReportBytes = 50 << 20

// readCappedReport returns the first maxReportBytes bytes of the file
// at path, or an empty string if the file doesn't exist. Oversize files
// are truncated and a log line is emitted to the scan so the operator
// knows the report was clipped.
func readCappedReport(path string, emit func(Event)) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return ""
	}
	if info.Size() > maxReportBytes {
		emit(Event{Kind: KindText, Text: fmt.Sprintf("report.json is %d bytes, truncating to %d", info.Size(), maxReportBytes)})
	}
	b, err := io.ReadAll(io.LimitReader(f, maxReportBytes))
	if err != nil {
		return ""
	}
	return string(b)
}

// buildClaudeArgs assembles the `claude -p` argv shared by the local and
// docker runners. When the skill declares an allowed-tools list the agent
// is held to it under acceptEdits (writes to report.json still go through
// unprompted, arbitrary Bash does not); otherwise it falls back to the
// historical bypassPermissions behaviour.
func buildClaudeArgs(sj SkillJob, effort string, globalMaxTurns int) []string {
	args := []string{
		"-p",
		"--output-format", "stream-json",
		"--verbose",
		"--model", sj.Model,
	}
	if sj.AllowedTools != "" {
		args = append(args,
			"--permission-mode", "acceptEdits",
			"--allowedTools", sj.AllowedTools,
		)
	} else {
		args = append(args, "--permission-mode", "bypassPermissions")
	}
	if effort != "" {
		args = append(args, "--effort", effort)
	}
	args = append(args, "--max-turns", strconv.Itoa(effectiveMaxTurns(sj.MaxTurns, globalMaxTurns)))
	args = append(args, buildSkillPrompt(sj.Name, sj.OutputFile))
	return args
}

// effectiveMaxTurns resolves the turn cap: per-skill wins, then global, then
// the built-in default of 30.
func effectiveMaxTurns(perSkill, global int) int {
	if perSkill > 0 {
		return perSkill
	}
	if global > 0 {
		return global
	}
	return DefaultSkillMaxTurns
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
