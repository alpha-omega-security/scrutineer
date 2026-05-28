package worker

import (
	"context"
	"slices"
	"strings"
	"testing"
)

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
	if got := flagValue(args, "--allowedTools"); got != "Read,Write,WebFetch" {
		t.Errorf("allowedTools = %q, want Read,Write,WebFetch", got)
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

func flagValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
