// Package gitx runs Git commands and applies a bounded retry policy to
// network-facing invocations.
package gitx

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"

	retryx "scrutineer/internal/retry"
)

const (
	DefaultAttempts  = 3
	DefaultBaseDelay = 500 * time.Millisecond
	DefaultMaxDelay  = 4 * time.Second
	DefaultWaitDelay = 10 * time.Second
)

// Runner runs one Git invocation and returns its combined output.
type Runner func(ctx context.Context, dir string, env []string, args ...string) (string, error)

// Notice describes a transient failure before the next attempt.
type Notice struct {
	Label    string
	Attempt  int
	Attempts int
	Delay    time.Duration
}

// Command is one remote Git invocation plus operation-specific hooks.
type Command struct {
	Label string
	Dir   string
	Env   []string
	Args  []string
	// Reset runs after a failed attempt, before either another attempt or a
	// terminal error return. It must only clean command-owned state.
	Reset func() error
	// Confirm may recognize that an operation succeeded despite an ambiguous
	// transient error. A confirmation error does not replace the original Git
	// error; the normal retry budget continues unless the context ended.
	Confirm func(context.Context) (bool, error)
}

// Retry bounds how a remote Git invocation is retried. Its zero value is the
// production policy; fields are exposed so callers can use a tighter budget
// or deterministic runners and sleepers in tests.
type Retry struct {
	Attempts  int
	BaseDelay time.Duration
	MaxDelay  time.Duration
	Run       Runner
	Sleep     func(context.Context, time.Duration) error
	Notify    func(Notice)
}

// Resolved fills zero-valued options with the production defaults.
func (r Retry) Resolved() Retry {
	if r.Attempts <= 0 {
		r.Attempts = DefaultAttempts
	}
	if r.BaseDelay <= 0 {
		r.BaseDelay = DefaultBaseDelay
	}
	if r.MaxDelay <= 0 {
		r.MaxDelay = DefaultMaxDelay
	}
	if r.Run == nil {
		r.Run = Run
	}
	if r.Sleep == nil {
		r.Sleep = retryx.Sleep
	}
	return r
}

// Do runs cmd, retrying only transient failures while the budget, context,
// cleanup hook, and optional success confirmation allow another attempt.
func (r Retry) Do(ctx context.Context, cmd Command) (string, error) {
	p := r.Resolved()
	finishFailure := func(out string, err error) (string, error) {
		if cmd.Reset == nil {
			return out, err
		}
		if resetErr := cmd.Reset(); resetErr != nil {
			return out, errors.Join(err, resetErr)
		}
		return out, err
	}
	for attempt := 1; ; attempt++ {
		out, err := p.Run(ctx, cmd.Dir, cmd.Env, cmd.Args...)
		if err == nil {
			return out, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return finishFailure(out, ctxErr)
		}
		if !TransientFailure(out) {
			return finishFailure(out, err)
		}
		if cmd.Confirm != nil {
			confirmed, _ := cmd.Confirm(ctx)
			if confirmed {
				return out, nil
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return finishFailure(out, ctxErr)
			}
		}
		if attempt >= p.Attempts {
			return finishFailure(out, err)
		}
		if cmd.Reset != nil {
			if resetErr := cmd.Reset(); resetErr != nil {
				return out, errors.Join(err, resetErr)
			}
		}
		delay := retryx.BackoffDelay(attempt, p.BaseDelay, p.MaxDelay)
		if p.Notify != nil {
			p.Notify(Notice{Label: cmd.Label, Attempt: attempt, Attempts: p.Attempts, Delay: delay})
		}
		if sleepErr := p.Sleep(ctx, delay); sleepErr != nil {
			return out, sleepErr
		}
	}
}

// Run executes Git with the production WaitDelay.
func Run(ctx context.Context, dir string, env []string, args ...string) (string, error) {
	return RunnerWithWaitDelay(DefaultWaitDelay)(ctx, dir, env, args...)
}

// RunnerWithWaitDelay returns a Runner with a bounded wait for transport
// children that retain Git's output pipe after Git itself exits.
func RunnerWithWaitDelay(waitDelay time.Duration) Runner {
	return func(ctx context.Context, dir string, env []string, args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.WaitDelay = waitDelay
		if dir != "" {
			cmd.Dir = dir
		}
		if len(env) > 0 {
			cmd.Env = append(os.Environ(), env...)
		}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
}

// CloneDestReset returns the cleanup to run after a failed clone attempt, or
// nil when there is nothing safe to clean. A clone that dies partway can leave
// the destination behind, and `git clone` refuses a non-empty target, so the
// cleanup is needed both before retries and before a terminal error return.
//
// Removal is offered only when dst is absent or empty at this point. Callers
// reach the clone path exactly when dst holds no .git, so an absent or empty
// dst can only ever gain content this call put there. A non-empty one belongs
// to the caller, and git would reject it as a permanent error that is never
// retried anyway.
func CloneDestReset(dst string) func() error {
	entries, err := os.ReadDir(dst)
	if err != nil && !os.IsNotExist(err) {
		return nil
	}
	if len(entries) > 0 {
		return nil
	}
	return func() error { return os.RemoveAll(dst) }
}

// permanentFailures are answers about the repository, the ref, the local
// destination, or the local machine. Repeating the command cannot change any
// of them, and retrying would only multiply pointless remote traffic.
//
// Several of these matter precisely because git reports them *alongside*
// transport noise. A clone that runs the disk out of space ends with "fatal:
// write error: No space left on device" followed by "fatal: the remote end
// hung up unexpectedly", and a rejected credential can surface as "error: RPC
// failed; result=22, HTTP code = 401", both of which would otherwise be read
// as transient. Permanent markers are therefore checked first and win.
var permanentFailures = []string{
	// The repository, the ref, or the credentials.
	"repository not found",
	"authentication failed",
	"could not read username",
	"could not read password",
	"terminal prompts disabled",
	"permission denied (publickey)",
	"remote: permission denied",
	"access denied",
	"couldn't find remote ref",
	"does not appear to be a git repository",
	"unable to update url base from redirection",
	"returned error: 401",
	"returned error: 403",
	"returned error: 404",
	"returned error: 410",
	"returned error: 413",
	"http code = 401",
	"http code = 403",
	"http code = 404",
	"http code = 413",
	// A server-side hard limit, not a hiccup.
	"pack exceeds maximum allowed size",
	// The local destination and the local machine. These arrive wrapped in
	// transport noise but no amount of retrying frees a disk or a thread.
	"already exists and is not an empty directory",
	"no space left on device",
	"disk quota exceeded",
	"input/output error",
	"read-only file system",
	"cannot allocate memory",
	"unable to create thread",
	"cannot fork",
	"unable to fork",
}

// transientFailures are name-resolution, connection, TLS, and
// remote-availability failures. They say nothing about the repository or the
// ref, so the same command may well succeed a moment later.
var transientFailures = []string{
	"could not resolve host",
	"couldn't resolve host",
	"could not resolve proxy",
	"temporary failure in name resolution",
	"failed to connect",
	"connection refused",
	"connection reset",
	"connection timed out",
	"operation timed out",
	"timeout was reached",
	"network is unreachable",
	"no route to host",
	"the remote end hung up unexpectedly",
	"early eof",
	"rpc failed",
	"unexpected disconnect while reading sideband packet",
	"transfer closed with",
	"recv failure",
	"send failure",
	"empty reply from server",
	"gnutls_handshake() failed",
	"ssl connect error",
	"ssl_read",
	"ssl_write",
	"tls connection was non-properly terminated",
	"returned error: 408",
	"returned error: 429",
	"returned error: 500",
	"returned error: 502",
	"returned error: 503",
	"returned error: 504",
	// Cloudflare's origin-side range: 520 unknown, 521 down, 522/524 timeout,
	// 523 unreachable. All say the edge could not reach the origin right now.
	"returned error: 520",
	"returned error: 521",
	"returned error: 522",
	"returned error: 523",
	"returned error: 524",
	"http code = 500",
	"http code = 502",
	"http code = 503",
	"http code = 504",
	"http code = 520",
	"http code = 521",
	"http code = 522",
	"http code = 523",
	"http code = 524",
	"internal server error",
	"bad gateway",
	"service unavailable",
	// Narrowed from "temporarily unavailable": nginx reports 503 as "Service
	// Temporarily Unavailable", but a bare "Resource temporarily unavailable"
	// is a local EAGAIN (see "unable to create thread" above) and must stay
	// permanent.
	"service temporarily unavailable",
	"too many requests",
}

// TransientFailure reports whether Git's combined output describes a failure
// worth another attempt.
//
// The classification fails closed. A permanent marker wins over a transient
// one, and output matching nothing at all is treated as permanent, so an
// unfamiliar message keeps today's single-attempt behaviour rather than
// turning into repeated remote traffic.
func TransientFailure(out string) bool {
	lower := strings.ToLower(out)
	for _, marker := range permanentFailures {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	for _, marker := range transientFailures {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
