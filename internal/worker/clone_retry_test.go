package worker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These exercise the retry policy through the real exec path rather than an
// injected runner, so they also cover the argv, environment, and cleanup the
// clone and fetch call sites hand to it. A `git` shim ahead of the real one
// on PATH stands in for the remote; body is shell, and reads the invocation
// number from $n and the last argument (the clone destination) from $dst.
type fakeGit struct {
	t   *testing.T
	dir string
}

func fakeGitOnPath(t *testing.T, body string) *fakeGit {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("needs a POSIX shell to stub git")
	}
	f := &fakeGit{t: t, dir: t.TempDir()}
	script := fmt.Sprintf(`#!/bin/sh
echo "$@" >> %q
printf 'GIT_TERMINAL_PROMPT=%%s GIT_PROTOCOL_FROM_USER=%%s\n' \
  "${GIT_TERMINAL_PROMPT-unset}" "${GIT_PROTOCOL_FROM_USER-unset}" >> %q
n=$(wc -l < %q | tr -d ' ')
dst=$(eval echo \${$#})
%s
`, f.callsPath(), f.envPath(), f.callsPath(), body)
	if err := os.WriteFile(filepath.Join(f.dir, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", f.dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return f
}

func (f *fakeGit) callsPath() string { return filepath.Join(f.dir, "calls.log") }
func (f *fakeGit) envPath() string   { return filepath.Join(f.dir, "env.log") }

// calls returns the argv of each invocation, one entry per attempt.
func (f *fakeGit) calls() []string { return f.readLines(f.callsPath()) }

// env returns the hardening variables each invocation actually saw.
func (f *fakeGit) env() []string { return f.readLines(f.envPath()) }

func (f *fakeGit) readLines(path string) []string {
	f.t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		f.t.Fatal(err)
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// fastRetry keeps the real classification and attempt budget but collapses
// the backoff, so these tests cost no wall-clock time.
func fastRetry() gitRetry {
	return gitRetry{sleep: func(context.Context, time.Duration) error { return nil }}
}

// TestCloneOrFetchRetriesTransientCloneFailure is the regression for #630:
// on the unmodified base a single transport hiccup ends the scan, because
// `git clone` was invoked exactly once.
func TestCloneOrFetchRetriesTransientCloneFailure(t *testing.T) {
	git := fakeGitOnPath(t, `if [ "$n" = "1" ]; then
  echo "fatal: unable to access 'https://example.invalid/repo/': Could not resolve host: example.invalid" >&2
  exit 128
fi
exit 0
`)
	dst := filepath.Join(t.TempDir(), "src")

	err := cloneOrFetch(context.Background(), fastRetry(), "https://example.invalid/repo", dst, false, "", func(Event) {})
	if err != nil {
		t.Errorf("cloneOrFetch after one transient failure: %v", err)
	}
	if calls := git.calls(); len(calls) != 2 {
		t.Errorf("git invocations = %d (%v), want 2: the first attempt plus one retry", len(calls), calls)
	}
}

// TestFetchRefRetriesTransientFetchFailure covers the cache-reuse path, and
// pins that the local reset still runs once the fetch succeeds.
func TestFetchRefRetriesTransientFetchFailure(t *testing.T) {
	git := fakeGitOnPath(t, `if [ "$n" = "1" ]; then
  echo "fatal: the remote end hung up unexpectedly" >&2
  exit 128
fi
exit 0
`)

	err := fetchRef(context.Background(), fastRetry(), t.TempDir(), "main", false, func(Event) {})
	if err != nil {
		t.Errorf("fetchRef after one transient failure: %v", err)
	}
	calls := git.calls()
	if len(calls) != 3 {
		t.Fatalf("git invocations = %d (%v), want 3: fetch, fetch retry, reset", len(calls), calls)
	}
	if !strings.Contains(calls[2], "reset") {
		t.Errorf("third invocation = %q, want the local reset", calls[2])
	}
}

// TestFetchRefDoesNotRetryLocalReset keeps the network policy off local
// work: repeating `git reset --hard` cannot fix whatever made it fail.
func TestFetchRefDoesNotRetryLocalReset(t *testing.T) {
	git := fakeGitOnPath(t, `case "$*" in
*reset*)
  echo "fatal: unable to access: Connection reset by peer" >&2
  exit 128
  ;;
esac
exit 0
`)

	if err := fetchRef(context.Background(), fastRetry(), t.TempDir(), "main", false, func(Event) {}); err == nil {
		t.Error("expected the failing reset to surface")
	}
	if calls := git.calls(); len(calls) != 2 {
		t.Errorf("git invocations = %d (%v), want 2: fetch then a single reset", len(calls), calls)
	}
}

// TestCloneOrFetchDoesNotRetryPermanentFailure guards the other side of the
// policy: a settled answer about the repository costs exactly one attempt,
// as it did before.
func TestCloneOrFetchDoesNotRetryPermanentFailure(t *testing.T) {
	git := fakeGitOnPath(t, `echo "remote: Repository not found." >&2
echo "fatal: repository 'https://example.invalid/repo/' not found" >&2
exit 128
`)
	dst := filepath.Join(t.TempDir(), "src")

	err := cloneOrFetch(context.Background(), fastRetry(), "https://example.invalid/repo", dst, false, "", func(Event) {})
	if err == nil {
		t.Error("cloneOrFetch on a missing repository should fail")
	}
	if calls := git.calls(); len(calls) != 1 {
		t.Errorf("git invocations = %d (%v), want 1: no retry for a permanent failure", len(calls), calls)
	}
}

// TestCloneOrFetchClearsPartialDestinationBeforeRetry covers the cleanup a
// retried clone needs: the stub leaves a half-written destination behind on
// its first attempt and rejects a non-empty target on the second, exactly as
// git does.
func TestCloneOrFetchClearsPartialDestinationBeforeRetry(t *testing.T) {
	git := fakeGitOnPath(t, `if [ "$n" = "1" ]; then
  mkdir -p "$dst/.git"
  echo partial > "$dst/partial"
  echo "fatal: unable to access 'https://example.invalid/repo/': Connection reset by peer" >&2
  exit 128
fi
if [ -e "$dst" ] && [ -n "$(ls -A "$dst" 2>/dev/null)" ]; then
  echo "fatal: destination path '$dst' already exists and is not an empty directory." >&2
  exit 128
fi
exit 0
`)
	dst := filepath.Join(t.TempDir(), "src")

	err := cloneOrFetch(context.Background(), fastRetry(), "https://example.invalid/repo", dst, false, "", func(Event) {})
	if err != nil {
		t.Errorf("cloneOrFetch should clear the partial clone and retry cleanly: %v", err)
	}
	if calls := git.calls(); len(calls) != 2 {
		t.Errorf("git invocations = %d (%v), want 2", len(calls), calls)
	}
}

// TestRemoteGitKeepsEnvironmentHardening pins the environment each remote
// invocation runs with, on the retry as well as the first attempt. Both
// variables used to sit in the positional argument list; moving them into an
// optional struct field makes dropping one much easier to miss in review.
//
// Each case first sets the variable to the *wrong* value. That is not
// decoration: `go test` runs the test binary with GIT_TERMINAL_PROMPT=0
// already exported (cmd/go sets it for module fetches), so a child process
// inherits the desired value whether or not the call site asks for it, and
// an assertion without this override would hold even if the call site
// dropped the variable entirely.
func TestRemoteGitKeepsEnvironmentHardening(t *testing.T) {
	t.Run("clone refuses a user-supplied protocol", func(t *testing.T) {
		t.Setenv("GIT_PROTOCOL_FROM_USER", "1")
		git := fakeGitOnPath(t, `if [ "$n" = "1" ]; then
  echo "fatal: unable to access 'https://example.invalid/repo/': Connection reset by peer" >&2
  exit 128
fi
exit 0
`)
		dst := filepath.Join(t.TempDir(), "src")
		if err := cloneOrFetch(context.Background(), fastRetry(), "https://example.invalid/repo", dst, false, "", func(Event) {}); err != nil {
			t.Fatalf("cloneOrFetch: %v", err)
		}
		env := git.env()
		if len(env) != 2 {
			t.Fatalf("recorded %d environments (%v), want 2", len(env), env)
		}
		for i, line := range env {
			if !strings.Contains(line, "GIT_PROTOCOL_FROM_USER=0") {
				t.Errorf("attempt %d ran with %q, want GIT_PROTOCOL_FROM_USER=0", i+1, line)
			}
		}
	})

	t.Run("ls-remote refuses a credential prompt", func(t *testing.T) {
		t.Setenv("GIT_TERMINAL_PROMPT", "1")
		git := fakeGitOnPath(t, `if [ "$n" = "1" ]; then
  echo "fatal: unable to access 'https://example.invalid/repo/': Connection reset by peer" >&2
  exit 128
fi
printf 'deadbeef\trefs/heads/main\n'
exit 0
`)
		if _, err := ListRemoteBranches(context.Background(), "https://example.invalid/repo"); err != nil {
			t.Fatalf("ListRemoteBranches: %v", err)
		}
		env := git.env()
		if len(env) != 2 {
			t.Fatalf("recorded %d environments (%v), want 2", len(env), env)
		}
		for i, line := range env {
			if !strings.Contains(line, "GIT_TERMINAL_PROMPT=0") {
				t.Errorf("attempt %d ran with %q, want GIT_TERMINAL_PROMPT=0", i+1, line)
			}
		}
	})
}

// TestCloneDestResetKeepsCallerContent is the safety bound on that cleanup:
// a destination that already holds files is never removed. git rejects it as
// a permanent error anyway, so the retry policy never reaches this state --
// but the guard is what makes removing an empty destination provably safe.
func TestCloneDestResetKeepsCallerContent(t *testing.T) {
	occupied := t.TempDir()
	keep := filepath.Join(occupied, "keep")
	if err := os.WriteFile(keep, []byte("caller content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if reset := cloneDestReset(occupied); reset != nil {
		t.Fatal("cloneDestReset must not offer to remove a non-empty destination")
	}

	empty := t.TempDir()
	reset := cloneDestReset(empty)
	if reset == nil {
		t.Fatal("cloneDestReset should clean an empty destination")
	}
	if err := reset(); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, err := os.Stat(empty); !os.IsNotExist(err) {
		t.Errorf("empty destination still present after reset: %v", err)
	}

	absent := filepath.Join(t.TempDir(), "missing")
	if reset := cloneDestReset(absent); reset == nil {
		t.Error("cloneDestReset should clean an absent destination")
	}
}

// TestListRemoteBranchesRetriesTransientFailure covers the branch picker:
// the add-repo form loses its suggestions on a single hiccup otherwise. It
// runs on the real (tight) picker policy, so it also demonstrates the added
// latency a person can actually see.
func TestListRemoteBranchesRetriesTransientFailure(t *testing.T) {
	git := fakeGitOnPath(t, `if [ "$n" = "1" ]; then
  echo "fatal: unable to access 'https://example.invalid/repo/': Failed to connect to example.invalid port 443: Connection refused" >&2
  exit 128
fi
printf 'deadbeef\trefs/heads/main\n'
exit 0
`)

	branches, err := ListRemoteBranches(context.Background(), "https://example.invalid/repo")
	if err != nil {
		t.Fatalf("ListRemoteBranches after one transient failure: %v", err)
	}
	if len(branches) != 1 || branches[0] != "main" {
		t.Errorf("branches = %v, want [main]", branches)
	}
	calls := git.calls()
	if len(calls) != 2 {
		t.Fatalf("git invocations = %d (%v), want 2", len(calls), calls)
	}
	// Every attempt, retry included, must keep disarming the user's
	// credential helper -- dropping `-c credential.helper=` would let an
	// ambient helper answer for an arbitrary URL typed into the add-repo box.
	for i, call := range calls {
		if !strings.Contains(call, "-c credential.helper= ls-remote --heads") {
			t.Errorf("attempt %d argv = %q, want it to disarm the credential helper", i+1, call)
		}
	}
}

// TestBranchPickerPolicyResolvesToItsOwnDelay guards the footgun resolved()
// hides: a zero delay is read as "unset" and replaced by the scan default,
// so the picker must be built with a positive delay to stay tight. Pinning
// the resolved value keeps a future edit from silently inheriting the slower
// scan backoff inside the user-facing request deadline.
func TestBranchPickerPolicyResolvesToItsOwnDelay(t *testing.T) {
	resolved := gitRetry{
		attempts:  branchPickerAttempts,
		baseDelay: branchPickerDelay,
		maxDelay:  branchPickerDelay,
	}.resolved()
	if resolved.baseDelay != branchPickerDelay || resolved.maxDelay != branchPickerDelay {
		t.Errorf("resolved picker delay = (%v, %v), want (%v, %v): a zero constant would inherit the scan default %v",
			resolved.baseDelay, resolved.maxDelay, branchPickerDelay, branchPickerDelay, gitRetryBaseDelay)
	}
	if resolved.attempts != branchPickerAttempts {
		t.Errorf("resolved picker attempts = %d, want %d", resolved.attempts, branchPickerAttempts)
	}
}

// TestListRemoteBranchesFailsFastOnPrivateRepo keeps the picker's fail-fast
// behaviour for the case it was built around: credentials are unavailable,
// which is an answer, not a hiccup.
func TestListRemoteBranchesFailsFastOnPrivateRepo(t *testing.T) {
	git := fakeGitOnPath(t, `echo "fatal: could not read Username for 'https://example.invalid': terminal prompts disabled" >&2
exit 128
`)

	if _, err := ListRemoteBranches(context.Background(), "https://example.invalid/repo"); err == nil {
		t.Error("expected an error for a repository needing credentials")
	}
	if calls := git.calls(); len(calls) != 1 {
		t.Errorf("git invocations = %d (%v), want 1", len(calls), calls)
	}
}

// TestGitWithEnvBoundsLingeringChild pins that "stop immediately on
// cancellation" is real even when git's transport child keeps the output
// pipe open after git itself is gone. The shim exits at once but leaves a
// background sleeper holding stdout; without WaitDelay, CombinedOutput would
// block on that sleeper for its full lifetime.
func TestGitWithEnvBoundsLingeringChild(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("needs a POSIX shell to stub git")
	}
	bin := t.TempDir()
	// The parent exits immediately; `sleep 30 &` inherits and holds stdout.
	script := "#!/bin/sh\nsleep 30 &\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	prev := gitWaitDelay
	gitWaitDelay = 200 * time.Millisecond
	defer func() { gitWaitDelay = prev }()

	done := make(chan struct{})
	go func() {
		_, _ = gitWithEnv(context.Background(), "", nil, "clone", "https://example.invalid/repo")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("gitWithEnv blocked on a lingering child instead of bounding it with WaitDelay")
	}
}
