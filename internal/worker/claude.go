package worker

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"scrutineer/internal/db"
)

// DefaultSkillMaxTurns is the turn cap applied when neither the skill's
// metadata nor the global config set a value.
const DefaultSkillMaxTurns = 30

const resumePromptNoFreshFallbackText = "not restarting repair prompt fresh"

// MaxTurnsReachedError is returned when claude-code exits after hitting the
// --max-turns cap. The caller should treat this as a soft completion.
type MaxTurnsReachedError struct{}

func (MaxTurnsReachedError) Error() string { return "hit max turns cap" }

// SkillRunner executes one skill scan. Tests and the container-backed runner
// substitute the process launch without touching the queue plumbing.
type SkillRunner interface {
	RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error)
	// SkillDir is where the worker stages SKILL.md/schema.json before
	// calling RunSkill, so the runner's harness discovers it. The path
	// varies per harness (.claude/skills/{name}, skills/{name},
	// .opencode/skill/{name}); the staged content does not.
	SkillDir(workRoot, name string) string
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
	Repo db.Repository
	// ScanID identifies the scan that owns this job. Required when the
	// runner is hardened: it disambiguates the per-scan network so
	// concurrent scans can never share one. A zero value collapses
	// distinct scans onto a single network and defeats the isolation, so
	// the container runner refuses to start hardened with ScanID == 0.
	ScanID       uint
	WorkRoot     string
	SubPath      string
	Model        string
	Name         string
	SkillDir     string // host absolute path to the staged skill directory
	OutputFile   string // relative to the scan workspace, e.g. "report.json"
	Ref          string // git ref to checkout; empty = default branch
	MaxTurns     int    // per-skill cap; 0 = use runner default
	Effort       string // per-scan claude --effort; "" = use runner default
	AllowedTools string // comma-separated; "" = full tool set under bypassPermissions
	// SrcReady declares that WorkRoot/src is already populated by the
	// caller (e.g. by the exposure handler copying from a dependent
	// cache). When true the runner skips its own clone and reads HEAD
	// from the existing tree.
	SrcReady bool
	// Profile names a runner profile (docker/profiles/<name>/). Empty
	// means "auto-detect from the clone"; "default" forces the default
	// runner image. Only the container runner honours this; the local
	// runner ignores it (no per-profile image to swap to).
	Profile string
	// RequiresProfile pins the skill to a named profile. When set, the
	// runner fails the scan if the resolved profile does not match.
	// Empty means no constraint. Mirrors db.Skill.RequiresProfile.
	RequiresProfile string
	// ResumeSessionID, when non-empty, makes the runner invoke
	// `claude -p --resume <id>` so a retried scan continues the previous
	// conversation with full history instead of restarting from turn 0.
	// The runner falls back to a fresh run if the session can't be found.
	ResumeSessionID string
	// ResumePrompt, when non-empty, replaces the default generic resume
	// prompt. It lets callers resume the same conversation with targeted
	// corrective instructions, such as rewriting an invalid report.json.
	ResumePrompt string
	// ClaudeConfigDir is a host directory the container runner mounts as the
	// container's CLAUDE_CONFIG_DIR so the resumable session store persists
	// across container restarts. Empty disables the mount (the local runner
	// ignores it and relies on the host's own ~/.claude).
	ClaudeConfigDir string
}

type SkillResult struct {
	Commit string
	Report string // contents of OutputFile, or "" if none declared/written
	// Profile is the runner profile actually used. Empty when the
	// default runner image ran. The worker persists this on the scan
	// so retries and the UI can show what was picked.
	Profile string
	// SessionID is the claude session this run belonged to, as seen in the
	// stream. The worker already persists it live via the emit callback;
	// this is a backstop so the final save reflects the latest value (e.g.
	// after a resume-fallback started a fresh session).
	SessionID string
}

type LocalClaude struct {
	Effort    string
	FullClone bool
	MaxTurns  int
}

// SkillDir is fixed at claude's discovery path: the no-container
// fallback is claude-only by design.
func (LocalClaude) SkillDir(workRoot, name string) string {
	return ClaudeHarness{}.SkillDir(workRoot, name)
}

// RunSkill runs claude against a staged skill in a local workspace. The
// workspace layout is:
//
//	{DataDir}/scan-{id}/src/                clone (read-only in the container)
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

	emit(Event{Kind: KindText, Text: "$ claude -p <skill:" + sj.Name + ">"})
	accountErrText := ""
	wrappedEmit := func(e Event) {
		if accountErrText == "" {
			accountErrText = claudeAccountErrorText(e.Text)
		}
		emit(e)
	}
	args := buildClaudeArgs(sj, l.Effort, l.MaxTurns)
	hitMaxTurns, sessionID, waitErr := l.runClaudeOnce(ctx, args, work, wrappedEmit)

	if waitErr != nil && sj.ResumeSessionID != "" && sessionID == "" && accountErrText == "" {
		if sj.ResumePrompt != "" {
			emit(Event{Kind: KindText, Text: "resume of session " + sj.ResumeSessionID + " failed; " + resumePromptNoFreshFallbackText})
			return SkillResult{Commit: commit}, fmt.Errorf("claude exited: %w", waitErr)
		}
		// The resume never produced a session event, so claude could not
		// load the saved conversation (expired or pruned). Restart fresh in
		// the same workspace so the retry lineage isn't permanently wedged
		// on a dead session id.
		emit(Event{Kind: KindText, Text: "resume of session " + sj.ResumeSessionID + " failed; restarting fresh"})
		fresh := sj
		fresh.ResumeSessionID = ""
		args = buildClaudeArgs(fresh, l.Effort, l.MaxTurns)
		hitMaxTurns, sessionID, waitErr = l.runClaudeOnce(ctx, args, work, wrappedEmit)
	}

	res := SkillResult{Commit: commit, SessionID: sessionID}
	if outPath != "" {
		res.Report = readCappedReport(outPath, emit)
	}
	if waitErr != nil {
		if hitMaxTurns {
			return res, &MaxTurnsReachedError{}
		}
		if accountErrText != "" {
			return res, &ClaudeAccountError{Detail: accountErrText}
		}
		return res, fmt.Errorf("claude exited: %w", waitErr)
	}
	return res, nil
}

// runClaudeOnce starts one `claude -p` invocation in work, streams its
// output through emit, and reports the wait error, whether the run hit the
// max-turns cap, and the session id from the init event (empty when no init
// event arrived, e.g. a --resume that could not find the conversation).
func (l LocalClaude) runClaudeOnce(ctx context.Context, args []string, work string, emit func(Event)) (hitMaxTurns bool, sessionID string, waitErr error) {
	cmd := exec.CommandContext(ctx, "claude", args...)
	cmd.Dir = work
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false, "", err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return false, "", fmt.Errorf("start claude: %w", err)
	}

	wrappedEmit := func(e Event) {
		switch {
		case e.Kind == KindError && e.Text == "hit max turns":
			hitMaxTurns = true
		case e.Kind == KindSession && e.SessionID != "":
			sessionID = e.SessionID
		}
		emit(e)
	}
	ParseStream(stdout, wrappedEmit)
	waitErr = cmd.Wait()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
	return hitMaxTurns, sessionID, waitErr
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
// container runners. When the skill declares an allowed-tools list the agent
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
			"--allowedTools", sj.AllowedTools+",Skill",
		)
	} else {
		args = append(args, "--permission-mode", "bypassPermissions")
	}
	if e := effectiveEffort(sj.Effort, effort); e != "" {
		args = append(args, "--effort", e)
	}
	if sj.ResumeSessionID != "" {
		args = append(args, "--resume", sj.ResumeSessionID)
	}
	args = append(args, "--max-turns", strconv.Itoa(effectiveMaxTurns(sj.MaxTurns, globalMaxTurns)))
	if sj.ResumeSessionID != "" {
		if sj.ResumePrompt != "" {
			args = append(args, sj.ResumePrompt)
		} else {
			args = append(args, buildResumePrompt(sj.Name, sj.OutputFile))
		}
	} else {
		args = append(args, buildSkillPrompt(sj.Name, sj.OutputFile))
	}
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

// effectiveEffort resolves the claude --effort level: the per-scan value
// snapshotted at enqueue wins, then the runner's configured default.
func effectiveEffort(perScan, runnerDefault string) string {
	if perScan != "" {
		return perScan
	}
	return runnerDefault
}

// buildSkillPrompt is the activation prompt handed to claude. It's a thin
// wrapper: the skill's SKILL.md holds the actual instructions, we just tell
// claude which skill to use and where the repo lives.
func buildSkillPrompt(name, outputFile string) string {
	p := fmt.Sprintf("Use the %q skill on the repository cloned at ./src.", name)
	if outputFile != "" {
		p += fmt.Sprintf(" Write your structured output to ./%s as the skill specifies.", outputFile)
		p += schemaValidationHint(outputFile)
	}
	return p
}

// schemaValidationHint tells claude to validate its JSON output against the
// skill's schema via scrutineer's API instead of installing a JSON Schema
// library inside the runner container. The package-install route wastes turns
// (the container has no pip/gem) and is unreliable (Ruby's json_schemer chokes
// on contentMediaType annotations); the endpoint reuses the harness's own
// validator, so a pass here means the post-scan check will also pass. Only
// emitted for JSON outputs, since the endpoint validates against schema.json.
func schemaValidationHint(outputFile string) string {
	if !strings.HasSuffix(outputFile, ".json") {
		return ""
	}
	return fmt.Sprintf(" To check ./%s against ./schema.json, POST it to {scrutineer.api_base}/scans/{scrutineer.scan_id}/validate-report (header \"Authorization: Bearer {scrutineer.token}\", values in ./context.json); {\"valid\":true} means it conforms. Don't install a schema validator.", outputFile)
}

// buildLoggedPrompt is what scrutineer records on scan.Prompt for the UI. It
// pairs the activation invocation with the rendered SKILL.md so the Prompt
// tab shows the actual instructions Claude executed (#308), not just the
// "use the X skill" wrapper.
func buildLoggedPrompt(skill *db.Skill) string {
	return buildSkillPrompt(skill.Name, skill.OutputFile) +
		"\n\n--- SKILL.md ---\n\n" + renderSkillMD(skill)
}

// buildResumePrompt is the nudge handed to a `--resume`d run. The prior
// turns are already in context, so this just tells the agent to carry on and
// restates the deliverable — the report file is the whole point of the run,
// and a resumed agent should not forget to write it.
func buildResumePrompt(name, outputFile string) string {
	p := fmt.Sprintf("Continue the %q skill on the repository at ./src from where you left off.", name)
	if outputFile != "" {
		p += fmt.Sprintf(" Write your structured output to ./%s as the skill specifies.", outputFile)
	}
	return p
}
