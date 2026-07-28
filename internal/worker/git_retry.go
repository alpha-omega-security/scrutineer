package worker

import (
	"context"
	"fmt"
	"time"

	"github.com/git-pkgs/clone"
)

const (
	gitRetryAttempts  = clone.DefaultAttempts
	gitRetryBaseDelay = clone.DefaultBaseDelay
	gitRetryMaxDelay  = clone.DefaultMaxDelay
)

type gitRunner = clone.Runner

// gitCommand is the worker-facing form of a remote Git invocation. The
// adapter keeps worker events out of the reusable clone package.
type gitCommand struct {
	label   string
	dir     string
	env     []string
	args    []string
	reset   func() error
	confirm func(context.Context) (bool, error)
}

// gitRetry retains the worker's compact, zero-value policy while delegating
// classification, retry execution, and timing to github.com/git-pkgs/clone.
type gitRetry struct {
	attempts  int
	baseDelay time.Duration
	maxDelay  time.Duration
	run       gitRunner
	sleep     func(context.Context, time.Duration) error
}

func (r gitRetry) resolved() gitRetry {
	c := r.toClone().Resolved()
	// Prefer this package's git wrapper (honours the gitWaitDelay var)
	// over clone.Run's fixed default.
	if r.run == nil {
		c.Run = gitWithEnv
	}
	return gitRetry{
		attempts:  c.Attempts,
		baseDelay: c.BaseDelay,
		maxDelay:  c.MaxDelay,
		run:       c.Run,
		sleep:     c.Sleep,
	}
}

func (r gitRetry) toClone() clone.Retry {
	return clone.Retry{
		Attempts:  r.attempts,
		BaseDelay: r.baseDelay,
		MaxDelay:  r.maxDelay,
		Run:       r.run,
		Sleep:     r.sleep,
	}
}

func branchPickerRetry(r gitRetry) gitRetry {
	r.attempts = branchPickerAttempts
	r.baseDelay = branchPickerDelay
	r.maxDelay = branchPickerDelay
	return r
}

func (r gitRetry) do(ctx context.Context, cmd gitCommand, emit func(Event)) (string, error) {
	retry := r.resolved().toClone()
	if emit != nil {
		retry.Notify = func(n clone.Notice) {
			emit(Event{Kind: KindText, Text: fmt.Sprintf(
				"git %s failed with a transient error (attempt %d/%d), retrying in %s",
				n.Label, n.Attempt, n.Attempts, n.Delay.Round(time.Millisecond))})
		}
	}
	return retry.Do(ctx, clone.Command{
		Label:   cmd.label,
		Dir:     cmd.dir,
		Env:     cmd.env,
		Args:    cmd.args,
		Reset:   cmd.reset,
		Confirm: cmd.confirm,
	})
}

func cloneDestReset(dst string) func() error {
	return clone.DestReset(dst)
}
