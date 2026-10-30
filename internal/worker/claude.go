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

	"github.com/alpha-omega-security/harness"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

// DefaultSkillMaxTurns is the turn cap applied when neither the skill's
// metadata nor the global config set a value.
const DefaultSkillMaxTurns = 30

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

// BackendReporter is an optional SkillRunner extension: a runner that
// knows which harness it drives reports it here so wrap() can stamp the
// scan row before RunSkill starts. That closes the window where a server
// restart mid-run leaves a scan with a session_id but no backend, which
// resumeOpts then misreads as a claude session and refuses to resume.
type BackendReporter interface {
	Backend() string
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
	// the container runner refuses to start hardened unless ScanID or
	// IsolationKey is set.
	ScanID uint
	// IsolationKey overrides ScanID when naming the hardened network and
	// egress sidecar. A job with no scan row (a chat turn) sets it to its own
	// namespaced id so it neither lands on the shared "0" namespace nor
	// collides with the scan whose id happens to match.
	IsolationKey string
	WorkRoot     string
	SubPath      string
	FocusArea    string
	Model        string
	Name         string
	SkillDir     string // host absolute path to the staged skill directory
	OutputFile   string // relative to the scan workspace, e.g. "report.json"
	Ref          string // git ref to checkout; empty = default branch
	MaxTurns     int    // per-skill cap; 0 = use runner default
	Effort       string // per-scan claude --effort; "" = use runner default
	// AllowedTools is comma-separated; "" = full tool set under
	// bypassPermissions. claude-only: the other harnesses have no equivalent
	// switch, so a tool restriction is enforced there by the container and the
	// prompt, not by the agent CLI.
	AllowedTools string
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
	// EgressPolicy is the operator-selected scan_egress_policies name for this
	// scan, copied from the scan row. Empty means none. Only the container
	// runner can enforce it, so the local runner refuses a job that has one.
	EgressPolicy string
	// RequiresProfile pins the skill to a named profile. When set, the
	// runner fails the scan if the resolved profile does not match.
	// Empty means no constraint. Mirrors db.Skill.RequiresProfile.
	RequiresProfile  string
	RequiresCommands []string
	RequiresFeatures []string
	DegradedMode     bool
	// RecordPreflight persists worker-owned evidence before the first model turn.
	RecordPreflight func(coverage.Preflight) error
	// Shared by job copies used for whole-tree fallback and repair runs.
	preflight    *capabilityPreflightState
	checkBackend func(context.Context, []byte, func(context.Context) coverage.BackendProbe) error
	// ResumeSessionID, when non-empty, makes the runner invoke
	// `claude -p --resume <id>` so a retried scan continues the previous
	// conversation with full history instead of restarting from turn 0.
	// The runner falls back to a fresh run if the session can't be found.
	ResumeSessionID string
	// ResumePrompt, when non-empty, replaces the default generic resume
	// prompt. It lets callers resume the same conversation with targeted
	// corrective instructions, such as rewriting an invalid report.json.
	ResumePrompt string
	// Prompt, when non-empty, replaces the default skill-activation prompt on
	// a fresh (non-resume) run, letting a caller drive the agent with an
	// arbitrary instruction instead of "use the <skill> skill": the chat
	// runner passes the user's message and the conversation framing here.
	// Unused on a resume, where ResumePrompt applies, except as the fallback
	// when that resume finds no session: a caller that sets both gets a fresh
	// restart in place instead of a hard failure.
	Prompt string
	// StateDir is a host directory the container runner mounts at
	// /harness-state and points the harness at via Harness.StateEnv, so
	// the resumable session store persists across container restarts.
	// Empty disables the mount (the local runner ignores it and relies on
	// the host's own ~/.claude).
	StateDir string
}

// toJob resolves the runner-level defaults into a harness.Job so the module's
// Args() (which takes only resolved values) receives what buildClaudeArgs used
// to compute. ValidationHint carries scrutineer's API-endpoint instruction so
// the module's generic default hint is replaced with the exact wording the
// bundled skills already expect.
func (sj SkillJob) toJob(effort string, maxTurns int, baseURL string) harness.Job {
	return harness.Job{
		Workspace:       sj.WorkRoot,
		SkillName:       sj.Name,
		Prompt:          sj.Prompt,
		Model:           sj.Model,
		Effort:          effectiveEffort(sj.Effort, effort),
		MaxTurns:        effectiveMaxTurns(sj.MaxTurns, maxTurns),
		OutputFile:      sj.OutputFile,
		ValidationHint:  scrutineerValidationHint(sj.OutputFile, sj.AllowedTools),
		AllowedTools:    sj.AllowedTools,
		BaseURL:         baseURL,
		ResumeSessionID: sj.ResumeSessionID,
		ResumePrompt:    sj.ResumePrompt,
	}
}

// isolationKey names this job's hardened network and egress sidecar. Scans key
// on their scan id; a job without one supplies IsolationKey instead.
func (sj SkillJob) isolationKey() string {
	if sj.IsolationKey != "" {
		return sj.IsolationKey
	}
	return strconv.FormatUint(uint64(sj.ScanID), 10)
}

type SkillResult struct {
	Commit string
	Report string // contents of OutputFile, or "" if none declared/written
	// Profile is the runner profile actually used. Empty when the
	// default runner image ran. The worker persists this on the scan
	// so retries and the UI can show what was picked.
	Profile string
	// Backend is the harness that ran this scan (HarnessName). Persisted on
	// the scan so a retry after switching -backend knows the SessionID
	// belongs to a different agent CLI and starts fresh instead of passing
	// e.g. a codex thread id to claude --resume.
	Backend string
	// Provider is the provider prefix selected from an OpenCode model id.
	// RunnerImage and RunnerImageDigest identify the provider base image before
	// any repository language profile is layered on it.
	Provider          string
	RunnerImage       string
	RunnerImageDigest string
	// SessionID is the harness session this run belonged to, as seen in
	// the stream. The worker already persists it live via the emit callback;
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

func (LocalClaude) Backend() string { return HarnessName(ClaudeHarness{}) }

// RunSkill runs claude against a staged skill in a local workspace. The
// workspace layout is:
//
//	{DataDir}/scan-{id}/src/                clone (read-only in the container)
//	{DataDir}/scan-{id}/.claude/skills/NAME staged skill (read by claude-code)
//	{DataDir}/scan-{id}/OutputFile          where the skill writes, if any
func (l LocalClaude) RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	if sj.EgressPolicy != "" {
		return SkillResult{}, fmt.Errorf("scan egress policy %q cannot be enforced by the local runner (no container to confine)", sj.EgressPolicy)
	}
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

	if err := sj.checkCapabilities(ctx, nil, true, emit); err != nil {
		return SkillResult{Commit: commit}, err
	}
	if err := l.checkBackendPreflight(ctx, sj); err != nil {
		return SkillResult{Commit: commit}, err
	}

	var outPath string
	if sj.OutputFile != "" {
		outPath = filepath.Join(work, sj.OutputFile)
		_ = os.Remove(outPath)
	}

	emit(Event{Kind: KindText, Text: "$ claude -p <skill:" + sj.Name + ">"})
	accountErrText := ""
	var rateLimitReset *RateLimitInfo
	wrappedEmit := func(e Event) {
		accountErrText = preferAccountErrText(accountErrText, ClaudeHarness{}.AccountErrorText(e.Text))
		if e.Kind == KindRateLimit && e.RateLimit != nil {
			rateLimitReset = preferRateLimitReset(rateLimitReset, e.RateLimit)
		}
		emit(e)
	}
	run := func(ctx context.Context, j harness.Job, emit func(Event)) error {
		err := l.runClaudeOnce(ctx, ClaudeHarness{}.Args(j), work, emit)
		if err != nil && accountErrText != "" {
			return &harness.AccountError{Detail: accountErrText}
		}
		return err
	}
	session, waitErr := harness.RunSession(ctx, run, sj.toJob(l.Effort, l.MaxTurns, ""), wrappedEmit)

	res := SkillResult{Commit: commit, SessionID: session.ID}
	if outPath != "" {
		res.Report = readCappedReport(outPath, emit)
	}
	if waitErr != nil {
		if session.MaxTurns {
			return res, &MaxTurnsReachedError{}
		}
		if accountErrText != "" {
			return res, &AccountError{Detail: accountErrText, ResetAt: resumableReset(accountErrText, rateLimitReset)}
		}
		return res, fmt.Errorf("claude exited: %w", waitErr)
	}
	return res, nil
}

// runClaudeOnce starts one `claude -p` invocation in work, streams its
// output through emit, and returns the wait error.
func (l LocalClaude) runClaudeOnce(ctx context.Context, args []string, work string, emit func(Event)) error {
	cmd := exec.CommandContext(ctx, "claude", args...)
	cmd.Dir = work

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	terminate, err := startSupervised(cmd)
	if err != nil {
		return fmt.Errorf("start claude: %w", err)
	}
	defer terminate()

	ClaudeHarness{}.ParseStream(stdout, emit)
	return cmd.Wait()
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
//
// The report is whatever the agent left under that name in a workspace it
// controls, so the read goes through a root opened at the parent directory
// and accepts only a regular file: a link to a host file, or to the
// context.json beside it, yields no report rather than that file's contents.
// The parent is the workspace root itself — validateSkillPaths keeps
// output_file to a bare name — which the agent cannot replace from inside its
// bind mount.
func readCappedReport(path string, emit func(Event)) string {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return ""
	}
	defer func() { _ = root.Close() }()
	name := filepath.Base(path)
	entryInfo, err := root.Lstat(name)
	if err != nil || !entryInfo.Mode().IsRegular() {
		return ""
	}
	f, err := root.Open(name)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(entryInfo, info) {
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

// toolsAllowShell reports whether a skill's allowed-tools list lets the agent
// run shell commands, which is what the API validation route needs. An empty
// list is the unrestricted case (see Job.AllowedTools), so it allows Bash.
// Entries may carry a scope qualifier ("Bash(git:*)"), so only the tool name
// in front of the parenthesis is compared.
func toolsAllowShell(allowedTools string) bool {
	if strings.TrimSpace(allowedTools) == "" {
		return true
	}
	for _, tool := range strings.Split(allowedTools, ",") {
		name, _, _ := strings.Cut(tool, "(")
		if strings.EqualFold(strings.TrimSpace(name), "Bash") {
			return true
		}
	}
	return false
}

// scrutineerValidationHint is the ValidationHint scrutineer supplies on every
// harness.Job so the agent validates its JSON output via scrutineer's API
// instead of installing a JSON Schema library inside the runner container.
// The package-install route wastes turns (the container has no pip/gem) and
// is unreliable (Ruby's json_schemer chokes on contentMediaType annotations);
// the endpoint reuses scrutineer's own validator, so a pass here means the
// post-scan check will also pass. The harness module appends this after the
// OutputFile clause when OutputFile ends in .json.
//
// The POST route needs Bash, so a skill whose allowed-tools omits it gets the
// read-based wording instead (#834): recon was told to POST on every run and
// burned its turn budget failing to. Returning "" for those skills is not an
// option -- the harness substitutes its own generic "Validate ./x against
// ./schema.json before finishing" for an empty hint on any .json output, which
// is the same unexecutable instruction minus the don't-install guard.
func scrutineerValidationHint(outputFile, allowedTools string) string {
	if outputFile == "" {
		return ""
	}
	if !toolsAllowShell(allowedTools) {
		return fmt.Sprintf("To check ./%s against ./schema.json, read both files and compare them yourself; your tool set has no shell, so don't install a schema validator.", outputFile)
	}
	return fmt.Sprintf("To check ./%s against ./schema.json, POST it to {scrutineer.api_base}/scans/{scrutineer.scan_id}/validate-report (header \"Authorization: Bearer {scrutineer.token}\", values in ./context.json); {\"valid\":true} means it conforms. Don't install a schema validator.", outputFile)
}

// buildLoggedPrompt is what scrutineer records on scan.Prompt for the UI. It
// pairs the selected harness's activation invocation with the rendered
// SKILL.md so the Prompt tab shows the instructions the agent received (#308),
// not just an activation wrapper.
func buildLoggedPrompt(skill *db.Skill, backend string) string {
	h, err := HarnessByName(backend)
	if err != nil {
		h = ClaudeHarness{}
	}
	prompt := h.Prompt(harness.Job{
		SkillName:      skill.Name,
		OutputFile:     skill.OutputFile,
		ValidationHint: scrutineerValidationHint(skill.OutputFile, skill.AllowedTools),
	})
	return prompt +
		"\n\n--- SKILL.md ---\n\n" + renderSkillMD(skill)
}
