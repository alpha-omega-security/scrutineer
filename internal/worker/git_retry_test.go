package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var errGitExit = errors.New("exit status 128")

// scriptedGit is a gitRunner whose outcomes are fixed up front: call i gets
// outcome i, and the last outcome repeats for any further call. It records
// every invocation so a test can assert how many attempts were made.
type scriptedGit struct {
	outcomes []gitOutcome
	calls    [][]string
}

type gitOutcome struct {
	out string
	err error
}

func (g *scriptedGit) run(_ context.Context, _ string, _ []string, args ...string) (string, error) {
	g.calls = append(g.calls, args)
	i := len(g.calls) - 1
	if i >= len(g.outcomes) {
		i = len(g.outcomes) - 1
	}
	return g.outcomes[i].out, g.outcomes[i].err
}

// recordedSleep stands in for the backoff wait: it records the delays it was
// asked for and never actually sleeps, so the retry suite is instant. err,
// when set, simulates a context that ends during the wait.
type recordedSleep struct {
	delays []time.Duration
	err    error
}

func (s *recordedSleep) sleep(_ context.Context, d time.Duration) error {
	s.delays = append(s.delays, d)
	return s.err
}

func transientOutcome() gitOutcome {
	return gitOutcome{out: "fatal: unable to access 'https://host/r/': Connection reset by peer\n", err: errGitExit}
}

// TestGitRetryAttemptBudget pins the whole outcome matrix of the policy in
// one place: how many times git is invoked, whether the caller sees an
// error, and how many backoff waits happened.
func TestGitRetryAttemptBudget(t *testing.T) {
	ok := gitOutcome{out: "", err: nil}
	permanent := gitOutcome{out: "remote: Repository not found.\nfatal: repository 'https://host/r/' not found\n", err: errGitExit}
	unknown := gitOutcome{out: "fatal: a failure this policy has never seen\n", err: errGitExit}

	cases := []struct {
		name       string
		outcomes   []gitOutcome
		wantCalls  int
		wantSleeps int
		wantErr    bool
	}{
		{"succeeds first time", []gitOutcome{ok}, 1, 0, false},
		{"transient then success", []gitOutcome{transientOutcome(), ok}, 2, 1, false},
		{"transient twice then success", []gitOutcome{transientOutcome(), transientOutcome(), ok}, 3, 2, false},
		{"budget exhausted", []gitOutcome{transientOutcome()}, gitRetryAttempts, gitRetryAttempts - 1, true},
		{"permanent failure is final", []gitOutcome{permanent}, 1, 0, true},
		{"unrecognised failure is final", []gitOutcome{unknown}, 1, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			git := &scriptedGit{outcomes: c.outcomes}
			sleeper := &recordedSleep{}
			retry := gitRetry{run: git.run, sleep: sleeper.sleep}

			_, err := retry.do(context.Background(), gitCommand{label: "fetch", args: []string{"fetch"}}, func(Event) {})

			if gotErr := err != nil; gotErr != c.wantErr {
				t.Errorf("error = %v, want error: %v", err, c.wantErr)
			}
			if len(git.calls) != c.wantCalls {
				t.Errorf("git invocations = %d, want %d", len(git.calls), c.wantCalls)
			}
			if len(sleeper.delays) != c.wantSleeps {
				t.Errorf("backoff waits = %d, want %d", len(sleeper.delays), c.wantSleeps)
			}
		})
	}
}

// TestGitRetryReturnsLastFailure keeps the exhausted-budget error identical
// in shape to the single-attempt error callers already handle: the combined
// output of the final attempt, wrapping git's own error.
func TestGitRetryReturnsLastFailure(t *testing.T) {
	last := gitOutcome{out: "fatal: unable to access 'https://host/r/': Connection timed out\n", err: errGitExit}
	git := &scriptedGit{outcomes: []gitOutcome{transientOutcome(), last}}
	retry := gitRetry{attempts: 2, run: git.run, sleep: (&recordedSleep{}).sleep}

	out, err := retry.do(context.Background(), gitCommand{label: "clone", args: []string{"clone"}}, func(Event) {})
	if !errors.Is(err, errGitExit) {
		t.Errorf("error = %v, want it to wrap git's exit error", err)
	}
	if out != last.out {
		t.Errorf("output = %q, want the final attempt's output %q", out, last.out)
	}
}

// TestGitRetryStopsWhenContextEnds covers both ways the caller can give up:
// the context ending while git runs (its own kill makes the failure look
// transient, which must not be retried) and the context ending during the
// backoff wait. In each case the returned error must carry the context's
// cancellation, not git's, so ensureClone can tell a cancelled scan from an
// unreachable repository instead of recording a spurious clone_error.
func TestGitRetryStopsWhenContextEnds(t *testing.T) {
	t.Run("during the git invocation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		git := &scriptedGit{outcomes: []gitOutcome{
			{out: "fatal: the remote end hung up unexpectedly\n", err: errGitExit},
		}}
		sleeper := &recordedSleep{}
		retry := gitRetry{run: git.run, sleep: sleeper.sleep}

		_, err := retry.do(ctx, gitCommand{label: "fetch", args: []string{"fetch"}}, func(Event) {})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want it to carry context.Canceled", err)
		}
		if len(git.calls) != 1 {
			t.Errorf("git invocations = %d, want 1: a cancelled context must not be retried", len(git.calls))
		}
		if len(sleeper.delays) != 0 {
			t.Errorf("backoff waits = %d, want 0", len(sleeper.delays))
		}
	})

	t.Run("during the backoff wait", func(t *testing.T) {
		git := &scriptedGit{outcomes: []gitOutcome{transientOutcome()}}
		sleeper := &recordedSleep{err: context.DeadlineExceeded}
		retry := gitRetry{run: git.run, sleep: sleeper.sleep}

		_, err := retry.do(context.Background(), gitCommand{label: "clone", args: []string{"clone"}}, func(Event) {})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v, want it to carry context.DeadlineExceeded", err)
		}
		if len(git.calls) != 1 {
			t.Errorf("git invocations = %d, want 1: an interrupted wait ends the sequence", len(git.calls))
		}
	})
}

// TestGitRetryResetRunsBeforeEachRetry pins when the cleanup hook fires: not
// before the first attempt, and once before every retry.
func TestGitRetryResetRunsBeforeEachRetry(t *testing.T) {
	git := &scriptedGit{outcomes: []gitOutcome{transientOutcome()}}
	var resetsBeforeCall []int
	retry := gitRetry{run: git.run, sleep: (&recordedSleep{}).sleep}
	cmd := gitCommand{
		label: "clone",
		args:  []string{"clone"},
		reset: func() error {
			resetsBeforeCall = append(resetsBeforeCall, len(git.calls))
			return nil
		},
	}

	if _, err := retry.do(context.Background(), cmd, func(Event) {}); err == nil {
		t.Fatal("expected the exhausted budget to fail")
	}
	// One reset after attempt 1 and one after attempt 2; none before attempt 1.
	want := []int{1, 2}
	if len(resetsBeforeCall) != len(want) {
		t.Fatalf("reset ran %d times (after attempts %v), want %d", len(resetsBeforeCall), resetsBeforeCall, len(want))
	}
	for i, got := range resetsBeforeCall {
		if got != want[i] {
			t.Errorf("reset %d ran after %d attempts, want %d", i+1, got, want[i])
		}
	}
}

// TestGitRetryStopsWhenResetFails keeps a failed cleanup from turning one
// transport failure into a different, misleading one: the next attempt would
// hit a destination it could not prepare, so the sequence ends here. Both
// errors are surfaced -- the transport failure that triggered the retry and
// the local fault that stopped it -- because the local one (a read-only
// filesystem, say) is usually the more actionable and must not be swallowed.
func TestGitRetryStopsWhenResetFails(t *testing.T) {
	git := &scriptedGit{outcomes: []gitOutcome{transientOutcome()}}
	retry := gitRetry{run: git.run, sleep: (&recordedSleep{}).sleep}
	resetErr := errors.New("remove dst: read-only file system")
	cmd := gitCommand{
		label: "clone",
		args:  []string{"clone"},
		reset: func() error { return resetErr },
	}

	out, err := retry.do(context.Background(), cmd, func(Event) {})
	if !errors.Is(err, errGitExit) {
		t.Errorf("error = %v, want it to carry the original git failure", err)
	}
	if !errors.Is(err, resetErr) {
		t.Errorf("error = %v, want it to also carry the cleanup failure", err)
	}
	if !strings.Contains(out, "Connection reset by peer") {
		t.Errorf("output = %q, want the original git output", out)
	}
	if len(git.calls) != 1 {
		t.Errorf("git invocations = %d, want 1", len(git.calls))
	}
}

// TestGitRetryLogLineOmitsCommandDetail keeps credentials out of the scan
// log. A clone URL may carry a token, and git's output repeats it, so the
// retry notice must mention neither.
func TestGitRetryLogLineOmitsCommandDetail(t *testing.T) {
	const secretURL = "https://ghp_secrettoken@host/owner/repo"
	git := &scriptedGit{outcomes: []gitOutcome{
		{out: "fatal: unable to access '" + secretURL + "': Connection reset by peer\n", err: errGitExit},
	}}
	var logged []string
	retry := gitRetry{attempts: 2, run: git.run, sleep: (&recordedSleep{}).sleep}

	_, _ = retry.do(context.Background(), gitCommand{label: "clone", args: []string{"clone", "--", secretURL}},
		func(e Event) { logged = append(logged, e.Text) })

	if len(logged) != 1 {
		t.Fatalf("emitted %d lines (%v), want 1 retry notice", len(logged), logged)
	}
	line := logged[0]
	for _, banned := range []string{"ghp_secrettoken", secretURL, "Connection reset by peer"} {
		if strings.Contains(line, banned) {
			t.Errorf("retry notice %q must not contain %q", line, banned)
		}
	}
	if !strings.Contains(line, "clone") || !strings.Contains(line, "1/2") {
		t.Errorf("retry notice %q should name the operation and the attempt", line)
	}
}

// TestGitRetryToleratesNilEmit covers ListRemoteBranches, which has no scan
// log to write to.
func TestGitRetryToleratesNilEmit(t *testing.T) {
	git := &scriptedGit{outcomes: []gitOutcome{transientOutcome(), {}}}
	retry := gitRetry{run: git.run, sleep: (&recordedSleep{}).sleep}

	if _, err := retry.do(context.Background(), gitCommand{label: "ls-remote", args: []string{"ls-remote"}}, nil); err != nil {
		t.Fatalf("retry with a nil emit: %v", err)
	}
	if len(git.calls) != 2 {
		t.Errorf("git invocations = %d, want 2", len(git.calls))
	}
}

func TestTransientGitFailure(t *testing.T) {
	transient := []string{
		"fatal: unable to access 'https://h/r/': Could not resolve host: h",
		"ssh: Could not resolve hostname h: Temporary failure in name resolution",
		"fatal: unable to access 'https://h/r/': Could not resolve proxy: proxy.invalid",
		"fatal: unable to access 'https://h/r/': Failed to connect to h port 443: Connection refused",
		"fatal: unable to access 'https://h/r/': Recv failure: Connection reset by peer",
		"fatal: unable to access 'https://h/r/': Operation timed out after 30000 milliseconds",
		"error: RPC failed; curl 92 HTTP/2 stream 5 was not closed cleanly\nfatal: early EOF",
		"fatal: the remote end hung up unexpectedly",
		"error: RPC failed; curl 56 GnuTLS recv error (-54): Error in the pull function.",
		"fetch-pack: unexpected disconnect while reading sideband packet",
		"fatal: unable to access 'https://h/r/': The requested URL returned error: 503",
		"fatal: unable to access 'https://h/r/': The requested URL returned error: 429",
		"remote: Internal Server Error",
		"error: RPC failed; HTTP 502 curl 22 The requested URL returned error: 502 Bad Gateway",
		// nginx phrases 503 as "Service Temporarily Unavailable".
		"error: RPC failed; HTTP 503 curl 22 The requested URL returned error: 503 Service Temporarily Unavailable",
		// Cloudflare origin-side timeouts, which the base gave up on after one try.
		"fatal: unable to access 'https://h/r/': The requested URL returned error: 522",
		"fatal: unable to access 'https://h/r/': The requested URL returned error: 524",
	}
	for _, out := range transient {
		if !transientGitFailure(out) {
			t.Errorf("transientGitFailure(%q) = false, want true", out)
		}
	}

	permanent := []string{
		"",
		"remote: Repository not found.\nfatal: repository 'https://h/r/' not found",
		"remote: HTTP Basic: Access denied\nfatal: Authentication failed for 'https://h/r/'",
		"fatal: could not read Username for 'https://h': terminal prompts disabled",
		"fatal: couldn't find remote ref does-not-exist",
		"fatal: 'https://h/r' does not appear to be a git repository",
		"fatal: destination path 'src' already exists and is not an empty directory.",
		"fatal: unable to access 'https://h/r/': The requested URL returned error: 404",
		"fatal: could not create work tree dir 'src': Permission denied",
		// A local EAGAIN reported as "Resource temporarily unavailable": no
		// amount of retrying frees a thread, and re-cloning wastes a full
		// download onto a machine that is already out of headroom.
		"fatal: unable to create thread: Resource temporarily unavailable",
		// A push rejected for size, in git's older result=/HTTP-code phrasing.
		"error: RPC failed; HTTP 413 curl 22 The requested URL returned error: 413",
		"fatal: a failure message nobody has classified yet",
	}
	for _, out := range permanent {
		if transientGitFailure(out) {
			t.Errorf("transientGitFailure(%q) = true, want false", out)
		}
	}
}

// TestTransientGitFailureMixedOutput covers the cases the ordering exists
// for: git reports a settled answer *wrapped in* transport noise, so reading
// only the noise would spend the whole budget re-asking a question that is
// already answered -- or, worse, re-downloading a pack onto a full disk.
func TestTransientGitFailureMixedOutput(t *testing.T) {
	settled := []struct{ name, out string }{
		{"repository is gone", "" +
			"fatal: unable to access 'https://h/r/': Connection reset by peer\n" +
			"remote: Repository not found."},
		{"disk is full", "" +
			"fatal: write error: No space left on device\n" +
			"fatal: the remote end hung up unexpectedly\n" +
			"fatal: index-pack failed"},
		{"quota is exhausted", "" +
			"error: RPC failed; curl 18 transfer closed with outstanding read data remaining\n" +
			"fatal: write error: Disk quota exceeded"},
		{"credentials rejected, older git phrasing", "" +
			"error: RPC failed; result=22, HTTP code = 401\n" +
			"fatal: The remote end hung up unexpectedly"},
		{"repository missing, older git phrasing", "" +
			"error: RPC failed; result=22, HTTP code = 404\n" +
			"fatal: The remote end hung up unexpectedly"},
		{"server-side size limit", "" +
			"remote: fatal: pack exceeds maximum allowed size (2.00 GiB)\n" +
			"fatal: the remote end hung up unexpectedly"},
	}
	for _, c := range settled {
		if transientGitFailure(c.out) {
			t.Errorf("%s: classified transient, want permanent", c.name)
		}
	}

	// The mirror image: a connect(2) refusal reported as EACCES by a
	// firewall is a network condition that can clear, so the permanent
	// markers must be narrow enough not to swallow it.
	blocked := "fatal: unable to access 'https://h/r/': Failed to connect to h port 443: Permission denied"
	if !transientGitFailure(blocked) {
		t.Error("a firewall-refused connection should stay retryable")
	}
}

// TestGitBackoffDelayBounds pins the shape of the wait: each step at least
// the geometric delay and never past the cap plus its jitter.
func TestGitBackoffDelayBounds(t *testing.T) {
	const (
		base    = 100 * time.Millisecond
		ceiling = 400 * time.Millisecond
	)
	want := []time.Duration{base, 2 * base, ceiling, ceiling, ceiling}
	for attempt, floor := range want {
		got := gitBackoffDelay(attempt+1, base, ceiling)
		limit := floor + floor/gitRetryJitterDivisor
		if got < floor || got >= limit {
			t.Errorf("gitBackoffDelay(%d) = %v, want [%v, %v)", attempt+1, got, floor, limit)
		}
	}
}

// TestGitBackoffDelayIsJittered is what actually keeps the jitter alive:
// bounds alone are satisfied by a constant delay, which is exactly the
// lockstep behaviour the spread exists to prevent when several workers fail
// against one forge at the same moment.
func TestGitBackoffDelayIsJittered(t *testing.T) {
	const (
		base    = 100 * time.Millisecond
		ceiling = time.Second
		samples = 200
	)
	lowest, highest := time.Duration(1<<62), time.Duration(0)
	for range samples {
		delay := gitBackoffDelay(1, base, ceiling)
		if delay < base || delay >= base+base/gitRetryJitterDivisor {
			t.Fatalf("jittered delay %v outside [%v, %v)", delay, base, base+base/gitRetryJitterDivisor)
		}
		lowest = min(lowest, delay)
		highest = max(highest, delay)
	}
	// A token spread would satisfy "not constant" while still sending every
	// worker back at effectively the same moment, so require the observed
	// range to be a real fraction of the delay.
	if spread := highest - lowest; spread < base/20 {
		t.Errorf("%d samples spanned only %v (%v..%v); the backoff is effectively unjittered",
			samples, spread, lowest, highest)
	}
}

// TestRetryBudgetsStaySmall guards the production constants themselves. The
// policy's value depends on staying far below the deadlines it runs inside:
// a scan's worker slot, and -- for the branch picker -- the request timeout
// in internal/web. Nothing else in the suite would notice these growing.
func TestRetryBudgetsStaySmall(t *testing.T) {
	const (
		scanBudget   = 3 * time.Second
		pickerBudget = 500 * time.Millisecond
		capBudget    = 5 * time.Second
	)

	// A zero base delay would retry with no backoff at all -- the lockstep
	// hammering the policy exists to avoid -- and nothing else notices,
	// because gitBackoffDelay(_, 0, _) is a valid (if pointless) zero.
	if gitRetryBaseDelay <= 0 {
		t.Errorf("gitRetryBaseDelay = %v, want a positive backoff", gitRetryBaseDelay)
	}
	if gitRetryMaxDelay < gitRetryBaseDelay {
		t.Errorf("gitRetryMaxDelay = %v, want >= base %v", gitRetryMaxDelay, gitRetryBaseDelay)
	}
	// A zero picker delay is worse than it looks: resolved() reads it as
	// "unset" and substitutes the scan default, silently making the
	// user-facing path slower than either constant suggests.
	if branchPickerDelay <= 0 {
		t.Errorf("branchPickerDelay = %v, want a positive backoff", branchPickerDelay)
	}
	if branchPickerAttempts < 1 || gitRetryAttempts < 1 {
		t.Errorf("attempt budgets must be >= 1, got picker=%d scan=%d", branchPickerAttempts, gitRetryAttempts)
	}

	var scanWorst time.Duration
	for attempt := 1; attempt < gitRetryAttempts; attempt++ {
		scanWorst += gitBackoffDelay(attempt, gitRetryBaseDelay, gitRetryMaxDelay)
	}
	if scanWorst > scanBudget {
		t.Errorf("scan retries can wait %v in total, want at most %v", scanWorst, scanBudget)
	}

	var pickerWorst time.Duration
	for attempt := 1; attempt < branchPickerAttempts; attempt++ {
		pickerWorst += gitBackoffDelay(attempt, branchPickerDelay, branchPickerDelay)
	}
	if pickerWorst > pickerBudget {
		t.Errorf("branch-picker retries can wait %v in total, want at most %v", pickerWorst, pickerBudget)
	}

	// The cap is unreachable at today's attempt count -- the waits are 500ms
	// and 1s -- so only this keeps a future increase from turning it into a
	// minutes-long wait.
	if gitRetryMaxDelay > capBudget {
		t.Errorf("gitRetryMaxDelay = %v, want at most %v", gitRetryMaxDelay, capBudget)
	}
}

func TestGitSleepReturnsOnContextEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := gitSleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("gitSleep on a cancelled context = %v, want context.Canceled", err)
	}
	if err := gitSleep(context.Background(), time.Nanosecond); err != nil {
		t.Errorf("gitSleep for a tiny delay = %v, want nil", err)
	}
}
