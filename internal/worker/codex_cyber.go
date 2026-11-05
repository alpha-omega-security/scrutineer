package worker

import (
	"fmt"
	"slices"
)

// CodexCyberAccessPrograms are the values the pinned Codex release accepts
// for `codex exec --cyber-access-program`. The CLI forwards the choice as the
// Responses API's access_programs.cyber request field; whether the account
// and model are actually enrolled is decided server-side.
var CodexCyberAccessPrograms = []string{"standard", "daybreak_blue", "daybreak_red"}

const codexCyberAccessProgramFlag = "--cyber-access-program"

// ValidateCodexCyberAccessProgram accepts "" (leave Codex's server default in
// place) or one of CodexCyberAccessPrograms.
func ValidateCodexCyberAccessProgram(program string) error {
	if program == "" || slices.Contains(CodexCyberAccessPrograms, program) {
		return nil
	}
	return fmt.Errorf("codex.cyber_access_program %q: want one of %v", program, CodexCyberAccessPrograms)
}

// withCodexCyberAccessProgram inserts --cyber-access-program right after the
// `exec` subcommand so it applies to both fresh `codex exec` runs and
// `codex exec resume` turns. Any earlier `-c key=value` globals stay ahead of
// `exec`, and the trailing `-- prompt` is untouched.
func withCodexCyberAccessProgram(args []string, program string) []string {
	if program == "" {
		return args
	}
	i := slices.Index(args, "exec")
	if i < 0 {
		return args
	}
	return slices.Insert(args, i+1, codexCyberAccessProgramFlag, program)
}
