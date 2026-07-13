package worker

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
)

// harnesses is the -backend registry. Add a new harness here and
// nothing else in the runner needs to change: the container, egress
// proxy and workspace plumbing all go through the Harness interface.
// The empty string and "claude" both resolve to ClaudeHarness so an
// unset backend keeps the historical default.
var harnesses = map[string]Harness{
	"":         ClaudeHarness{},
	"claude":   ClaudeHarness{},
	"codex":    CodexHarness{},
	"opencode": OpencodeHarness{},
}

// HarnessByName resolves a -backend value to its Harness, or returns
// an error listing the valid names. Used both to validate the flag at
// startup and to construct the runner's harness once.
//
//nolint:ireturn // registry; the concrete type is the registrant's choice
func HarnessByName(name string) (Harness, error) {
	if h, ok := harnesses[strings.ToLower(name)]; ok {
		return h, nil
	}
	return nil, fmt.Errorf("backend: unknown %q, must be one of %s", name, HarnessNames())
}

// HarnessName returns the canonical registry name for h — the value the
// -backend flag would take to select it. Persisted on Scan.Backend so a
// retry knows which harness a session id belongs to. Reverse-looks-up
// the harnesses map rather than adding a Name() method so a new harness
// only registers in one place. Compares by concrete type, not interface
// equality, so a future harness whose struct carries a non-comparable
// field (slice, map) does not panic here.
func HarnessName(h Harness) string {
	ht := reflect.TypeOf(h)
	for name, hh := range harnesses {
		if name != "" && reflect.TypeOf(hh) == ht {
			return name
		}
	}
	// Unregistered harness (a test double); Binary() is the closest
	// stable identifier.
	return h.Binary()
}

// HarnessNames lists the registered backends (excluding the
// empty-string default alias) for the README and the -backend flag's
// help text.
func HarnessNames() string {
	names := make([]string, 0, len(harnesses))
	for n := range harnesses {
		if n != "" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// A Harness is the agent CLI the container runner execs to drive a skill.
// It owns everything that varies between claude-code and an alternative
// agent (codex, opencode, ...): the binary name, the argv it takes, the
// output format it streams, the project-memory filename it auto-loads,
// and the model-API hosts it must reach. The container, egress proxy and
// workspace layout stay the same regardless of harness; only what runs
// inside the container changes.
//
// To add a harness: implement this interface in its own
// harness_<name>.go, add one entry to the harnesses registry above, and
// ship its binary in Dockerfile.runner. Nothing else in the runner or
// UI changes.
type Harness interface {
	// Binary is the executable on the runner image's PATH.
	Binary() string
	// Args is the argv (without the binary) for one skill run. effort is
	// the runner's configured default; globalMaxTurns is the runner's
	// -max-turns flag. Per-scan overrides on sj win over both. baseURL is
	// the operator's model-API base URL override; harnesses that do not
	// pass it as an env var can translate it into CLI/config arguments.
	Args(sj SkillJob, effort string, globalMaxTurns int, baseURL string) []string
	// ParseStream reads the harness's combined stdout/stderr and emits one
	// Event per logical line. The Event vocabulary (KindText, KindTool,
	// KindSession, KindError, ...) is harness-neutral; this method maps
	// the harness's own output format onto it so the scan log, session
	// capture and max-turns detection work the same regardless of agent.
	ParseStream(r io.Reader, emit func(Event))
	// SkillDir is the directory under workRoot where stageSkill writes
	// SKILL.md, schema.json, and the skill's auxiliary files so this
	// harness's own discovery picks them up. All three current harnesses
	// look for a file literally named SKILL.md and follow symlinks, so
	// only the directory differs: claude reads .claude/skills/{name},
	// codex reads skills/{name}, opencode reads .opencode/skill/{name}.
	// The activation prompt that points the agent at the skill is the
	// harness's own concern, inside Args.
	SkillDir(workRoot, name string) string
	// GuideFilename is the workspace-relative path the harness auto-loads
	// as project memory, where injectProfileGuide writes the profile's
	// PROFILE.md. claude-code reads CLAUDE.md; codex and opencode read
	// AGENTS.md.
	GuideFilename() string
	// EgressHosts is the model-API hostnames the harness must reach, in
	// the same wildcard form as DefaultEgressAllow. They are appended to
	// the egress proxy's allowlist at startup so the agent inside the
	// container can talk to its provider; the static allowlists are
	// harness-neutral and contain none of these.
	EgressHosts() []string
	// Env returns the harness-specific environment for the container, in
	// docker -e form: a bare "KEY" passes the host value through, and
	// "KEY=VALUE" sets it explicitly. Covers the model-API credential and
	// the harness's own telemetry / autoupdate suppressors. baseURL is the
	// operator's model-API base-URL override (-model-base-url);
	// "" means none. Harness-neutral env (HOME, the proxy vars, semgrep)
	// stays in buildRunArgs.
	Env(baseURL string) []string
	// StateEnv returns the env entries (KEY=VALUE) that point the harness
	// at containerPath as its persistent state/config directory. The
	// runner bind-mounts a per-scan host directory there so the session
	// store survives the container, letting a retry resume the agent
	// loop. claude reads CLAUDE_CONFIG_DIR; codex reads CODEX_HOME;
	// opencode reads OPENCODE_CONFIG_DIR and OPENCODE_DB.
	StateEnv(containerPath string) []string
	// AccountErrorText returns s when it looks like an account-level
	// failure from the harness's provider (a usage/rate/plan limit, or
	// access disabled/revoked) and "" otherwise. The runner consults it
	// only after the harness exited non-zero, so a stray phrase in
	// normal output never triggers. A non-empty match becomes an
	// AccountError that pauses the queue, since retrying cannot succeed
	// until the account recovers.
	AccountErrorText(s string) string
	// DefaultModels is the model pick list a fresh install of this
	// harness offers when the operator has not set models: in config.
	// The first entry is the default; Tier tags each entry as the
	// mid/high/max default so tier resolution needs no heuristic.
	DefaultModels() []ModelDefault
}

// scanJSONL is the shared ParseStream loop: it reads r line-by-line via
// bufio.ReadBytes (so an oversize line does not stall the reader the way
// bufio.Scanner would), hands each non-empty line to the harness's own
// per-line parser, and terminates on EOF or emits a single KindError on any
// other read failure. All three harnesses stream JSONL, so only the per-line
// mapping differs.
func scanJSONL(r io.Reader, emit func(Event), line func([]byte, func(Event))) {
	br := bufio.NewReader(r)
	for {
		raw, readErr := br.ReadBytes('\n')
		if len(raw) > 0 {
			line(raw, emit)
		}
		if readErr == io.EOF {
			return
		}
		if readErr != nil {
			emit(Event{Kind: KindError, Text: "stream read: " + readErr.Error()})
			return
		}
	}
}

// passthroughEnv returns each key that is set in the host environment as a
// bare "KEY" entry — the docker -e form that forwards the host value into
// the container without embedding it in the argv. Used by every harness's
// Env for its provider credential(s); the T1/T13 residual (in-container code
// can read the forwarded credential) applies uniformly.
func passthroughEnv(keys ...string) []string {
	var out []string
	for _, k := range keys {
		if os.Getenv(k) != "" {
			out = append(out, k)
		}
	}
	return out
}

// explicitSkillPrompt is the activation prompt for harnesses that discover
// SKILL.md but do not auto-invoke it (codex, opencode): it points at the
// staged skill by path, restates the deliverable, and appends the
// schema-validation hint for JSON outputs. Returns sj.ResumePrompt verbatim
// when a resume carries an explicit override (e.g. the schema-repair nudge).
// claude has native slash-style skill invocation and uses buildSkillPrompt
// instead.
func explicitSkillPrompt(sj SkillJob, skillPath string) string {
	resume := sj.ResumeSessionID != ""
	if resume && sj.ResumePrompt != "" {
		return sj.ResumePrompt
	}
	verb := "Follow"
	if resume {
		verb = "Continue following"
	}
	p := verb + " the instructions in " + skillPath + "/SKILL.md against the repository cloned at ./src."
	if sj.OutputFile != "" {
		p += " Write your structured output to ./" + sj.OutputFile + " as the skill specifies."
		p += schemaValidationHint(sj.OutputFile)
	}
	return p
}

// ModelDefault is one entry a harness contributes to the model pick
// list. Tier is one of "mid", "high", "max", or "" for entries that
// are selectable but not a tier default.
type ModelDefault struct {
	Name string
	ID   string
	Tier string
}
