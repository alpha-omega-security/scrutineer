package worker

import (
	"cmp"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func codexSessionRunner(t *testing.T, resumeError string) (ContainerRunner, string) {
	t.Helper()
	log := filepath.Join(t.TempDir(), "argv")
	t.Setenv("CODEX_TEST_ARGS", log)
	t.Setenv("CODEX_TEST_RESUME_ERROR", resumeError)
	script := `#!/bin/sh
[ "$1" = run ] || exit 0
for arg in "$@"; do
 case "$arg" in *:/work) work=${arg%:/work};; esac
done
while [ "$1" != -- ]; do shift; done
shift 2
[ "$1" = codex ] || exit 2
printf '%s\n' "$@" '' >> "$CODEX_TEST_ARGS"
session=fresh-session
for arg in "$@"; do
 if [ "$arg" = resume ]; then
  if [ -n "$CODEX_TEST_RESUME_ERROR" ]; then
   printf '%s\n' "$CODEX_TEST_RESUME_ERROR"
   exit 1
  fi
  session=saved-session
 fi
done
printf '{"type":"thread.started","thread_id":"%s"}\n' "$session"
printf '%s\n' '{"type":"turn.completed","usage":{"input_tokens":100,"output_tokens":20}}'
printf '%s' '{"tier":"ready","summary":"ok"}' > "$work/report.json"
`
	bin := writeFakeBin(t, t.TempDir(), "runtime", script)
	return ContainerRunner{Runtime: ContainerRuntime{Bin: bin}, Harness: CodexHarness{}, Effort: "high"}, log
}

func codexSessionCalls(t *testing.T, log, effort string) [][]string {
	t.Helper()
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	for _, call := range strings.Split(strings.TrimSuffix(string(data), "\n\n"), "\n\n") {
		args := strings.Split(call, "\n")
		for _, setting := range []string{
			`model_reasoning_effort="` + effort + `"`,
			"analytics.enabled=false", "features.apps=false", "features.plugins=false",
		} {
			if !hasAdjacent(args, "-c", setting) {
				t.Errorf("Codex invocation missing %q: %q", setting, args)
			}
		}
		calls = append(calls, args)
	}
	return calls
}

func TestRunSkillCodexSessions(t *testing.T) {
	const missing = "no rollout found for thread id saved-session"
	for _, tc := range []struct {
		name, resume, effort, failure, prompt, resumePrompt string
		cancelOnError, wantError                            bool
		wantCalls                                           int
		wantSession                                         string
	}{
		{name: "fresh", wantCalls: 1, wantSession: "fresh-session"},
		{name: "resume", resume: "saved-session", effort: "max", wantCalls: 1, wantSession: "saved-session"},
		{name: "missing session", resume: "saved-session", effort: "xhigh", failure: missing, wantCalls: 2, wantSession: "fresh-session"},
		{name: "chat fallback", resume: "saved-session", failure: missing, prompt: "Full conversation", resumePrompt: "Follow up", wantCalls: 2, wantSession: "fresh-session"},
		{name: "repair only", resume: "saved-session", failure: missing, resumePrompt: "Repair report.json", wantError: true, wantCalls: 1},
		{name: "runtime failure", resume: "saved-session", failure: "cannot connect to container runtime", wantError: true, wantCalls: 1},
		{name: "canceled missing session", resume: "saved-session", failure: missing, cancelOnError: true, wantError: true, wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner, log := codexSessionRunner(t, tc.failure)
			work := t.TempDir()
			if err := os.Mkdir(filepath.Join(work, "src"), 0o755); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result, err := runner.RunSkill(ctx, SkillJob{
				Name: "posture", WorkRoot: work, SrcReady: true, Model: modelGPT6SolID,
				OutputFile: "report.json", Effort: tc.effort, ResumeSessionID: tc.resume,
				Prompt: tc.prompt, ResumePrompt: tc.resumePrompt,
			}, func(e Event) {
				if tc.cancelOnError && strings.Contains(e.Text, missing) {
					cancel()
				}
			})
			if (err != nil) != tc.wantError || result.SessionID != tc.wantSession {
				t.Fatalf("RunSkill = %+v, %v; want session %q, error %v", result, err, tc.wantSession, tc.wantError)
			}
			calls := codexSessionCalls(t, log, cmp.Or(tc.effort, runner.Effort))
			if len(calls) != tc.wantCalls {
				t.Fatalf("got %d invocations, want %d: %q", len(calls), tc.wantCalls, calls)
			}
			if hasAdjacent(calls[0], "resume", "saved-session") != (tc.resume != "") {
				t.Errorf("initial resume arguments: %q", calls[0])
			}
			if len(calls) == 2 && (slices.Contains(calls[1], "resume") || !strings.Contains(calls[1][len(calls[1])-1], tc.prompt)) {
				t.Errorf("fresh fallback arguments: %q", calls[1])
			}
			if !tc.wantError && result.Report != `{"tier":"ready","summary":"ok"}` {
				t.Errorf("report = %q", result.Report)
			}
		})
	}
}

func TestQueuedCodexScanPassesEffortAndPersistsReport(t *testing.T) {
	runner, log := codexSessionRunner(t, "")
	w, repoID, scanID := newQueuedSchemaSkillWorker(t, true, runner)
	if err := w.DB.Model(&db.Scan{}).Where("id = ?", scanID).Updates(map[string]any{
		"model": modelGPT6SolID, "effort": "max",
	}).Error; err != nil {
		t.Fatal(err)
	}
	scan := runQueuedCostScan(t, w, scanID)
	var repo db.Repository
	if err := w.DB.First(&repo, repoID).Error; err != nil {
		t.Fatal(err)
	}
	if repo.Posture != "ready" || scan.Backend != "codex" || scan.InputTokens != 100 || scan.OutputTokens != 20 {
		t.Fatalf("persisted posture=%q scan=%+v", repo.Posture, scan)
	}
	if calls := codexSessionCalls(t, log, "max"); len(calls) != 1 {
		t.Fatalf("got %d Codex invocations, want one", len(calls))
	}
}
