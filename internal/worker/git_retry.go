package worker

import (
	"context"
	"fmt"
	"time"

	"scrutineer/internal/gitx"
	retryx "scrutineer/internal/retry"
)

const (
	gitRetryAttempts  = gitx.DefaultAttempts
	gitRetryBaseDelay = gitx.DefaultBaseDelay
	gitRetryMaxDelay  = gitx.DefaultMaxDelay
)

type gitRunner = gitx.Runner

// gitCommand is the worker-facing form of a remote Git invocation. The
// adapter keeps worker events out of the reusable gitx package.
type gitCommand struct {
	label   string
	dir     string
	env     []string
	args    []string
	reset   func() error
	confirm func(context.Context) (bool, error)
}

// gitRetry retains the worker's compact, zero-value policy while delegating
// classification, retry execution, and timing to reusable internal packages.
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
		r.sleep = retryx.Sleep
	}
	return r
}

func branchPickerRetry(r gitRetry) gitRetry {
	r.attempts = branchPickerAttempts
	r.baseDelay = branchPickerDelay
	r.maxDelay = branchPickerDelay
	return r
}

func (r gitRetry) do(ctx context.Context, cmd gitCommand, emit func(Event)) (string, error) {
	p := r.resolved()
	retry := gitx.Retry{
		Attempts:  p.attempts,
		BaseDelay: p.baseDelay,
		MaxDelay:  p.maxDelay,
		Run:       p.run,
		Sleep:     p.sleep,
	}
	if emit != nil {
		retry.Notify = func(n gitx.Notice) {
			emit(Event{Kind: KindText, Text: fmt.Sprintf(
				"git %s failed with a transient error (attempt %d/%d), retrying in %s",
				n.Label, n.Attempt, n.Attempts, n.Delay.Round(time.Millisecond))})
		}
	}
	return retry.Do(ctx, gitx.Command{
		Label:   cmd.label,
		Dir:     cmd.dir,
		Env:     cmd.env,
		Args:    cmd.args,
		Reset:   cmd.reset,
		Confirm: cmd.confirm,
	})
}

func cloneDestReset(dst string) func() error {
	return gitx.CloneDestReset(dst)
}
