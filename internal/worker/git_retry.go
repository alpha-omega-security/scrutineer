package worker

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"
)

// Bounds for the remote-git retry policy. They are deliberately small: a
// scan that cannot reach a forge after a few seconds should fail and be
// retried as a scan, not hold a worker slot open. At three attempts the
// waits are 500ms and 1s, so gitRetryMaxDelay only binds if the attempt
// count is ever raised.
const (
	gitRetryAttempts      = 3
	gitRetryBaseDelay     = 500 * time.Millisecond
	gitRetryMaxDelay      = 4 * time.Second
	gitRetryBackoffFactor = 2
	gitRetryJitterDivisor = 4
)

// gitRunner runs one git invocation and returns its combined output.
// Production always passes gitWithEnv; tests substitute a deterministic fake
// so the retry policy can be exercised without a network or a real remote.
type gitRunner func(ctx context.Context, dir string, env []string, args ...string) (string, error)

// gitCommand is a single remote git invocation plus the cleanup its retries
// need. label names the operation for the scan log only.
type gitCommand struct {
	label string
	dir   string
	env   []string
	args  []string
	// reset runs before each retry, never before the first attempt. It lets
	// the clone path clear a half-written destination that would otherwise
	// make the next attempt fail for an unrelated reason. nil means the
	// command can simply be repeated.
	reset func() error
}

// gitRetry bounds how a remote git invocation is retried. The zero value is
// the production policy; tests set the fields they need to stay fast and
// deterministic. Only network-facing commands take this path — local work
// such as `git reset --hard` is never retried, because repeating it cannot
// fix anything a retry budget is meant to fix.
type gitRetry struct {
	attempts  int
	baseDelay time.Duration
	maxDelay  time.Duration
	run       gitRunner
	sleep     func(context.Context, time.Duration) error
}

func (r gitRetry) resolved() gitRetry {
	if r.attempts <= 0 {
		r.attempts = gitRetryAttempts
	}
	if r.baseDelay <= 0 {
		r.baseDelay = gitRetryBaseDelay
	}
	if r.maxDelay <= 0 {
		r.maxDelay = gitRetryMaxDelay
	}
	if r.run == nil {
		r.run = gitWithEnv
	}
	if r.sleep == nil {
		r.sleep = gitSleep
	}
	return r
}

// do runs cmd, retrying only while the failure looks transient and the
// budget, the context, and the cleanup hook all allow another attempt. The
// first attempt is always made exactly as before, so a permanent failure
// costs nothing extra. emit may be nil for callers without a scan log.
func (r gitRetry) do(ctx context.Context, cmd gitCommand, emit func(Event)) (string, error) {
	p := r.resolved()
	for attempt := 1; ; attempt++ {
		out, err := p.run(ctx, cmd.dir, cmd.env, cmd.args...)
		if err == nil {
			return out, nil
		}
		// The context is checked before the output is classified: a cancelled
		// or expired context kills git mid-transfer, and the resulting "hung
		// up unexpectedly" reads exactly like a transient network failure.
		// Its own error is returned, not git's, so a caller can tell a
		// cancelled scan from an unreachable repository (errors.Is against
		// context.Canceled / DeadlineExceeded) rather than flagging the repo.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return out, ctxErr
		}
		if attempt >= p.attempts || !transientGitFailure(out) {
			return out, err
		}
		if cmd.reset != nil {
			// A failed cleanup is surfaced, not swallowed: the next attempt
			// cannot proceed, and the reset error (typically a local
			// filesystem fault) is the more actionable of the two.
			if resetErr := cmd.reset(); resetErr != nil {
				return out, errors.Join(err, resetErr)
			}
		}
		delay := gitBackoffDelay(attempt, p.baseDelay, p.maxDelay)
		if emit != nil {
			// Deliberately carries no URL and no git output: the remote URL
			// may embed a credential, and the full output is already on the
			// returned error when every attempt fails.
			emit(Event{Kind: KindText, Text: fmt.Sprintf(
				"git %s failed with a transient error (attempt %d/%d), retrying in %s",
				cmd.label, attempt, p.attempts, delay.Round(time.Millisecond))})
		}
		if sleepErr := p.sleep(ctx, delay); sleepErr != nil {
			return out, sleepErr
		}
	}
}

// permanentGitFailures are answers about the repository, the ref, the local
// destination, or the local machine. Repeating the command cannot change any
// of them, and retrying would only multiply pointless remote traffic.
//
// Several of these matter precisely because git reports them *alongside*
// transport noise. A clone that runs the disk out of space ends with "fatal:
// write error: No space left on device" followed by "fatal: the remote end
// hung up unexpectedly", and a rejected credential can surface as "error: RPC
// failed; result=22, HTTP code = 401" — both would otherwise be read as
// transient. Permanent markers are therefore checked first and win.
var permanentGitFailures = []string{
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

// transientGitFailures are name-resolution, connection, TLS, and
// remote-availability failures. They say nothing about the repository or the
// ref, so the same command may well succeed a moment later.
var transientGitFailures = []string{
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

// transientGitFailure reports whether git's combined output describes a
// failure worth another attempt.
//
// The classification fails closed. A permanent marker wins over a transient
// one, and output matching nothing at all is treated as permanent, so an
// unfamiliar message keeps today's single-attempt behaviour rather than
// turning into repeated remote traffic.
func transientGitFailure(out string) bool {
	lower := strings.ToLower(out)
	for _, marker := range permanentGitFailures {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	for _, marker := range transientGitFailures {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// gitBackoffDelay grows the wait geometrically up to maxDelay and adds
// jitter so several workers failing against the same forge at the same
// moment do not retry in lockstep.
func gitBackoffDelay(attempt int, baseDelay, maxDelay time.Duration) time.Duration {
	delay := baseDelay
	for range attempt - 1 {
		delay *= gitRetryBackoffFactor
		if delay >= maxDelay {
			return gitJitter(maxDelay)
		}
	}
	return gitJitter(delay)
}

func gitJitter(delay time.Duration) time.Duration {
	if delay <= 0 {
		return 0
	}
	spread := delay / gitRetryJitterDivisor
	if spread <= 0 {
		return delay
	}
	return delay + time.Duration(rand.Int64N(int64(spread)))
}

// gitSleep waits for delay, returning early with the context's error when
// the caller gives up first.
func gitSleep(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
