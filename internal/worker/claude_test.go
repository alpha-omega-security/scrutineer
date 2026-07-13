package worker

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestBuildLoggedPrompt_includesActivationAndRenderedSkill(t *testing.T) {
	skill := &db.Skill{
		Name:        "metadata",
		Description: "Identify the repository.",
		Body:        "## Workspace\n\n- `./src` — the cloned repo.",
		OutputFile:  "report.json",
	}
	got := buildLoggedPrompt(skill)
	for _, want := range []string{
		buildSkillPrompt("metadata", "report.json"),
		"--- SKILL.md ---",
		"name: metadata",
		"description: Identify the repository.",
		"## Workspace",
		"./src",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("logged prompt missing %q\nfull prompt:\n%s", want, got)
		}
	}
}

func TestLocalClaude_RunSkill_rejectsProfileRequiringSkill(t *testing.T) {
	work := t.TempDir()
	sj := SkillJob{
		Name:            "php-only",
		WorkRoot:        work,
		SrcReady:        true,
		RequiresProfile: "php",
	}
	_, err := LocalClaude{}.RunSkill(context.Background(), sj, func(Event) {})
	if err == nil {
		t.Fatal("expected requires_profile to be rejected by local runner")
	}
	if !strings.Contains(err.Error(), "php") || !strings.Contains(err.Error(), "local runner") {
		t.Errorf("error %q should mention php and local runner", err)
	}
}

func TestBuildClaudeArgs_NoAllowedTools(t *testing.T) {
	sj := SkillJob{Name: "metadata", Model: "claude-opus-4-7", OutputFile: "report.json"}
	args := buildClaudeArgs(sj, "", 0)

	if got := flagValue(args, "--permission-mode"); got != "bypassPermissions" {
		t.Errorf("permission-mode = %q, want bypassPermissions", got)
	}
	if slices.Contains(args, "--allowedTools") {
		t.Errorf("did not expect --allowedTools in %v", args)
	}
	if got := flagValue(args, "--max-turns"); got != "30" {
		t.Errorf("max-turns = %q, want default 30", got)
	}
	if args[len(args)-1] != buildSkillPrompt("metadata", "report.json") {
		t.Errorf("prompt is not the final arg: %v", args)
	}
}

func TestBuildClaudeArgs_AllowedTools(t *testing.T) {
	sj := SkillJob{
		Name:         "metadata",
		Model:        "claude-sonnet-4-6",
		OutputFile:   "report.json",
		AllowedTools: "Read,Write,WebFetch",
		MaxTurns:     50,
	}
	args := buildClaudeArgs(sj, "high", 0)

	if got := flagValue(args, "--permission-mode"); got != "acceptEdits" {
		t.Errorf("permission-mode = %q, want acceptEdits", got)
	}
	if got := flagValue(args, "--allowedTools"); got != "Read,Write,WebFetch,Skill" {
		t.Errorf("allowedTools = %q, want Read,Write,WebFetch,Skill", got)
	}
	if got := flagValue(args, "--model"); got != "claude-sonnet-4-6" {
		t.Errorf("model = %q", got)
	}
	if got := flagValue(args, "--effort"); got != "high" {
		t.Errorf("effort = %q, want high", got)
	}
	if got := flagValue(args, "--max-turns"); got != "50" {
		t.Errorf("max-turns = %q, want per-skill 50", got)
	}
}

func TestBuildClaudeArgs_EffortPerScanWins(t *testing.T) {
	sj := SkillJob{Name: "security-deep-dive", Model: "claude-opus-4-8", OutputFile: "report.json", Effort: "max"}
	args := buildClaudeArgs(sj, "high", 0)
	if got := flagValue(args, "--effort"); got != "max" {
		t.Errorf("effort = %q, want per-scan max over runner high", got)
	}
}

func TestBuildClaudeArgs_EffortFallsBackToRunner(t *testing.T) {
	sj := SkillJob{Name: "metadata", Model: "claude-opus-4-8", OutputFile: "report.json"}
	args := buildClaudeArgs(sj, "high", 0)
	if got := flagValue(args, "--effort"); got != "high" {
		t.Errorf("effort = %q, want runner default high", got)
	}
}

func TestBuildClaudeArgs_NoEffortWhenUnset(t *testing.T) {
	sj := SkillJob{Name: "metadata", Model: "claude-opus-4-8", OutputFile: "report.json"}
	args := buildClaudeArgs(sj, "", 0)
	if slices.Contains(args, "--effort") {
		t.Errorf("did not expect --effort in %v", args)
	}
}

func TestEffectiveEffort(t *testing.T) {
	if got := effectiveEffort("max", "high"); got != "max" {
		t.Errorf("per-scan should win: got %q", got)
	}
	if got := effectiveEffort("", "high"); got != "high" {
		t.Errorf("empty per-scan falls back to runner: got %q", got)
	}
	if got := effectiveEffort("", ""); got != "" {
		t.Errorf("both empty stays empty: got %q", got)
	}
}

func TestBuildClaudeArgs_Resume(t *testing.T) {
	sj := SkillJob{
		Name:            "security-deep-dive",
		Model:           "claude-opus-4-8",
		OutputFile:      "report.json",
		ResumeSessionID: "abc-123",
	}
	args := buildClaudeArgs(sj, "", 0)

	if got := flagValue(args, "--resume"); got != "abc-123" {
		t.Errorf("--resume = %q, want abc-123", got)
	}
	// A resumed run carries on the prior conversation, so it must not
	// re-send the original activation prompt.
	last := args[len(args)-1]
	if last == buildSkillPrompt(sj.Name, sj.OutputFile) {
		t.Errorf("resume should not reuse the activation prompt, got %q", last)
	}
	if last != buildResumePrompt(sj.Name, sj.OutputFile) {
		t.Errorf("final arg = %q, want the resume prompt", last)
	}
	// The deliverable still has to be restated so a resumed agent writes it.
	if !strings.Contains(last, "report.json") {
		t.Errorf("resume prompt %q should restate the output file", last)
	}
}

func TestBuildClaudeArgs_CustomResumePrompt(t *testing.T) {
	sj := SkillJob{
		Name:            "metadata",
		Model:           "claude-opus-4-8",
		OutputFile:      "report.json",
		ResumeSessionID: "abc-123",
		ResumePrompt:    "repair the schema mismatch",
	}
	args := buildClaudeArgs(sj, "", 0)

	if got := args[len(args)-1]; got != sj.ResumePrompt {
		t.Errorf("final arg = %q, want custom resume prompt", got)
	}
}

func TestBuildClaudeArgs_NoResumeWhenUnset(t *testing.T) {
	sj := SkillJob{Name: "metadata", Model: "claude-opus-4-8", OutputFile: "report.json"}
	args := buildClaudeArgs(sj, "", 0)
	if slices.Contains(args, "--resume") {
		t.Errorf("did not expect --resume in %v", args)
	}
}

// TestLocalClaude_ResumeFallsBackToFresh drives RunSkill against a fake
// claude that fails any --resume (as the real binary does when the session
// is gone: an error line, no init event, exit 1) but succeeds on a fresh
// run. The runner must detect the missing init and restart without --resume
// so a lost session doesn't permanently wedge the retry lineage.
func TestLocalClaude_ResumeFallsBackToFresh(t *testing.T) {
	bin := t.TempDir()
	script := "#!/bin/sh\n" +
		"for a in \"$@\"; do\n" +
		"  if [ \"$a\" = \"--resume\" ]; then\n" +
		"    echo 'No conversation found with session ID: x'\n" +
		"    echo '{\"type\":\"result\",\"subtype\":\"error_during_execution\",\"is_error\":true,\"session_id\":\"throwaway\",\"num_turns\":0}'\n" +
		"    exit 1\n" +
		"  fi\n" +
		"done\n" +
		"echo '{\"type\":\"system\",\"subtype\":\"init\",\"session_id\":\"fresh-sess\"}'\n" +
		"echo '{\"type\":\"result\",\"subtype\":\"success\",\"result\":\"ok\",\"num_turns\":1}'\n" +
		"printf '{\"done\":true}' > report.json\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	sj := SkillJob{
		Name:            "deep",
		Model:           "m",
		WorkRoot:        work,
		SrcReady:        true,
		OutputFile:      "report.json",
		ResumeSessionID: "dead-session",
	}
	var sawFallback bool
	res, err := LocalClaude{}.RunSkill(context.Background(), sj, func(e Event) {
		if e.Kind == KindText && strings.Contains(e.Text, "restarting fresh") {
			sawFallback = true
		}
	})
	if err != nil {
		t.Fatalf("RunSkill: %v", err)
	}
	if !sawFallback {
		t.Error("expected a resume-fallback log line")
	}
	if res.SessionID != "fresh-sess" {
		t.Errorf("SessionID = %q, want the fresh run's id", res.SessionID)
	}
	if res.Report != `{"done":true}` {
		t.Errorf("Report = %q, want the fresh run's output", res.Report)
	}
}

func TestLocalClaude_ResumePromptDoesNotFallbackToFresh(t *testing.T) {
	bin := t.TempDir()
	script := "#!/bin/sh\n" +
		"for a in \"$@\"; do\n" +
		"  if [ \"$a\" = \"--resume\" ]; then\n" +
		"    echo 'No conversation found with session ID: x'\n" +
		"    echo '{\"type\":\"result\",\"subtype\":\"error_during_execution\",\"is_error\":true,\"num_turns\":0}'\n" +
		"    exit 1\n" +
		"  fi\n" +
		"done\n" +
		"printf '{\"fresh\":true}' > report.json\n" +
		"echo '{\"type\":\"system\",\"subtype\":\"init\",\"session_id\":\"fresh-sess\"}'\n" +
		"echo '{\"type\":\"result\",\"subtype\":\"success\",\"result\":\"ok\",\"num_turns\":1}'\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	sj := SkillJob{
		Name:            "deep",
		Model:           "m",
		WorkRoot:        work,
		SrcReady:        true,
		OutputFile:      "report.json",
		ResumeSessionID: "dead-session",
		ResumePrompt:    "repair report.json",
	}
	var sawNoFreshLog bool
	res, err := LocalClaude{}.RunSkill(context.Background(), sj, func(e Event) {
		if e.Kind == KindText && strings.Contains(e.Text, resumePromptNoFreshFallbackText) {
			sawNoFreshLog = true
		}
	})
	if err == nil {
		t.Fatal("RunSkill succeeded, want resume failure without fresh fallback")
	}
	if !sawNoFreshLog {
		t.Error("expected log explaining repair resume was not restarted fresh")
	}
	if res.SessionID != "" {
		t.Errorf("SessionID = %q, want empty", res.SessionID)
	}
	if res.Report != "" {
		t.Errorf("Report = %q, want empty because fresh fallback must not run", res.Report)
	}
	if _, err := os.Stat(filepath.Join(work, "report.json")); !os.IsNotExist(err) {
		t.Fatalf("fresh fallback wrote report.json; stat err = %v", err)
	}
}

func TestAccountErrorText(t *testing.T) {
	for _, text := range []string{
		// usage / rate / quota limits
		"Claude usage limit reached. Your limit will reset later.",
		"API Error: 429 Too Many Requests",
		"quota exceeded for this account",
		// access disabled or revoked (the message a suspended account returns)
		"Your organization has disabled Claude subscription access for Claude Code · Use an Anthropic API key instead, or ask your admin to enable access",
	} {
		if got := claudeAccountErrorText(text); got == "" {
			t.Errorf("claudeAccountErrorText(%q) did not match", text)
		}
	}
	if got := claudeAccountErrorText("syntax error in generated report"); got != "" {
		t.Errorf("claudeAccountErrorText returned false positive %q", got)
	}
}

func flagValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
