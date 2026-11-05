package worker

import (
	"slices"
	"testing"
)

// TestCodexArgvCarriesCyberAccessProgram checks the flag lands right after
// exec for fresh runs, resume runs, and runs with a base-URL global.
func TestCodexArgvCarriesCyberAccessProgram(t *testing.T) {
	tests := []struct {
		name   string
		resume string
		base   string
	}{
		{name: "fresh"},
		{name: "resume", resume: "019a0000-0000-7000-8000-000000000000"},
		{name: "base url global stays ahead of exec", base: "https://models.example.test/v1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sj := SkillJob{Name: "demo", WorkRoot: t.TempDir(), OutputFile: "report.json", ResumeSessionID: tc.resume}
			d := ContainerRunner{Harness: CodexHarness{}, ModelBaseURL: tc.base, CodexCyberAccessProgram: "daybreak_blue"}
			args := d.harnessArgv(sj)
			exec := slices.Index(args, "exec")
			if exec < 0 || len(args) < exec+3 {
				t.Fatalf("codex argv has no exec subcommand: %v", args)
			}
			if args[exec+1] != codexCyberAccessProgramFlag || args[exec+2] != "daybreak_blue" {
				t.Errorf("want %s daybreak_blue right after exec, got %v", codexCyberAccessProgramFlag, args)
			}
			if sep := slices.Index(args, "--"); sep < exec {
				t.Errorf("prompt separator moved ahead of exec: %v", args)
			}
		})
	}
}

// TestCyberAccessProgramOnlyForCodex checks the flag is omitted when unset
// and never added to a non-codex harness argv.
func TestCyberAccessProgramOnlyForCodex(t *testing.T) {
	sj := SkillJob{Name: "demo", WorkRoot: t.TempDir(), OutputFile: "report.json"}
	if args := (ContainerRunner{Harness: CodexHarness{}}).harnessArgv(sj); slices.Contains(args, codexCyberAccessProgramFlag) {
		t.Errorf("unset program still emitted: %v", args)
	}
	args := ContainerRunner{Harness: ClaudeHarness{}, CodexCyberAccessProgram: "daybreak_blue"}.harnessArgv(sj)
	if slices.Contains(args, codexCyberAccessProgramFlag) {
		t.Errorf("claude argv carries a codex flag: %v", args)
	}
}

// TestValidateCodexCyberAccessProgram checks the empty value and every known
// program are accepted and near-miss values are rejected.
func TestValidateCodexCyberAccessProgram(t *testing.T) {
	for _, ok := range append([]string{""}, CodexCyberAccessPrograms...) {
		if err := ValidateCodexCyberAccessProgram(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"daybreak", "DAYBREAK_BLUE", "standard ", "x\"y"} {
		if err := ValidateCodexCyberAccessProgram(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
