package gitx

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestRetryConfirmRecognizesAmbiguousSuccess(t *testing.T) {
	calls := 0
	retry := Retry{
		Attempts: 2,
		Run: func(context.Context, string, []string, ...string) (string, error) {
			calls++
			return "fatal: the remote end hung up unexpectedly", errors.New("exit status 128")
		},
		Sleep: func(context.Context, time.Duration) error { return nil },
	}
	confirmed := 0
	_, err := retry.Do(context.Background(), Command{
		Label: "push",
		Args:  []string{"push"},
		Confirm: func(context.Context) (bool, error) {
			confirmed++
			return true, nil
		},
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if calls != 1 || confirmed != 1 {
		t.Fatalf("calls = %d, confirmations = %d, want 1 each", calls, confirmed)
	}
}

func TestRetryConfirmErrorFallsBackToRetry(t *testing.T) {
	calls := 0
	retry := Retry{
		Attempts: 2,
		Run: func(context.Context, string, []string, ...string) (string, error) {
			calls++
			if calls == 1 {
				return "fatal: the remote end hung up unexpectedly", errors.New("exit status 128")
			}
			return "", nil
		},
		Sleep: func(context.Context, time.Duration) error { return nil },
	}
	confirmations := 0
	_, err := retry.Do(context.Background(), Command{
		Label: "push",
		Args:  []string{"push"},
		Confirm: func(context.Context) (bool, error) {
			confirmations++
			return false, errors.New("confirmation unavailable")
		},
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if calls != 2 || confirmations != 1 {
		t.Fatalf("calls = %d, confirmations = %d, want 2 and 1", calls, confirmations)
	}
}

func TestRetryResetsAfterEveryFailedAttempt(t *testing.T) {
	runErr := errors.New("exit status 128")
	resets := 0
	retry := Retry{
		Attempts: 2,
		Run: func(context.Context, string, []string, ...string) (string, error) {
			return "fatal: the remote end hung up unexpectedly", runErr
		},
		Sleep: func(context.Context, time.Duration) error { return nil },
	}

	_, err := retry.Do(context.Background(), Command{
		Label: "clone",
		Args:  []string{"clone"},
		Reset: func() error {
			resets++
			return nil
		},
	})
	if !errors.Is(err, runErr) {
		t.Fatalf("error = %v, want the final Git failure", err)
	}
	if resets != 2 {
		t.Fatalf("resets = %d, want one after each failed attempt", resets)
	}
}

func TestRetryResetsAfterPermanentFailure(t *testing.T) {
	runErr := errors.New("exit status 128")
	calls := 0
	resets := 0
	retry := Retry{
		Attempts: 3,
		Run: func(context.Context, string, []string, ...string) (string, error) {
			calls++
			return "fatal: write error: No space left on device", runErr
		},
		Sleep: func(context.Context, time.Duration) error {
			t.Fatal("permanent failure must not sleep or retry")
			return nil
		},
	}

	_, err := retry.Do(context.Background(), Command{
		Label: "clone",
		Args:  []string{"clone"},
		Reset: func() error {
			resets++
			return nil
		},
	})
	if !errors.Is(err, runErr) {
		t.Fatalf("error = %v, want the Git failure", err)
	}
	if calls != 1 || resets != 1 {
		t.Fatalf("calls = %d, resets = %d, want 1 each", calls, resets)
	}
}

func TestRetryResetsAfterCancellationAndJoinsCleanupError(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		resets := 0
		retry := Retry{
			Run: func(context.Context, string, []string, ...string) (string, error) {
				cancel()
				return "fatal: the remote end hung up unexpectedly", errors.New("exit status 128")
			},
		}
		_, err := retry.Do(ctx, Command{
			Label: "clone",
			Args:  []string{"clone"},
			Reset: func() error {
				resets++
				return nil
			},
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		if resets != 1 {
			t.Fatalf("resets = %d, want 1", resets)
		}
	})

	t.Run("cleanup error", func(t *testing.T) {
		runErr := errors.New("exit status 128")
		resetErr := errors.New("remove destination: read-only file system")
		retry := Retry{
			Attempts: 1,
			Run: func(context.Context, string, []string, ...string) (string, error) {
				return "fatal: the remote end hung up unexpectedly", runErr
			},
		}
		_, err := retry.Do(context.Background(), Command{
			Label: "clone",
			Args:  []string{"clone"},
			Reset: func() error { return resetErr },
		})
		if !errors.Is(err, runErr) || !errors.Is(err, resetErr) {
			t.Fatalf("error = %v, want both Git and cleanup failures", err)
		}
	})
}

func TestTransientFailure(t *testing.T) {
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
		"error: RPC failed; HTTP 503 curl 22 The requested URL returned error: 503 Service Temporarily Unavailable",
		"fatal: unable to access 'https://h/r/': The requested URL returned error: 522",
		"fatal: unable to access 'https://h/r/': The requested URL returned error: 524",
	}
	for _, out := range transient {
		if !TransientFailure(out) {
			t.Errorf("TransientFailure(%q) = false, want true", out)
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
		"fatal: unable to create thread: Resource temporarily unavailable",
		"error: RPC failed; HTTP 413 curl 22 The requested URL returned error: 413",
		"fatal: a failure message nobody has classified yet",
	}
	for _, out := range permanent {
		if TransientFailure(out) {
			t.Errorf("TransientFailure(%q) = true, want false", out)
		}
	}
}

func TestTransientFailureMixedOutput(t *testing.T) {
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
		if TransientFailure(c.out) {
			t.Errorf("%s: classified transient, want permanent", c.name)
		}
	}

	blocked := "fatal: unable to access 'https://h/r/': Failed to connect to h port 443: Permission denied"
	if !TransientFailure(blocked) {
		t.Error("a firewall-refused connection should stay retryable")
	}
}

func TestRunnerWithWaitDelayBoundsLingeringChild(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("needs a POSIX shell to stub git")
	}
	bin := t.TempDir()
	script := "#!/bin/sh\nsleep 30 &\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	done := make(chan struct{})
	go func() {
		_, _ = RunnerWithWaitDelay(200*time.Millisecond)(context.Background(), "", nil, "clone", "https://example.invalid/repo")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runner blocked on a lingering transport child")
	}
}
