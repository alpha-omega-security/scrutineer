// Package retry provides the transport-agnostic timing primitives used by
// bounded retry loops. Callers remain responsible for deciding which
// operations and failures are safe to retry.
package retry

import (
	"context"
	"math/rand/v2"
	"time"
)

const (
	BackoffFactor = 2
	JitterDivisor = 4
)

// BackoffDelay grows baseDelay geometrically up to maxDelay, then adds a
// small positive jitter so concurrent callers do not retry in lockstep.
func BackoffDelay(attempt int, baseDelay, maxDelay time.Duration) time.Duration {
	delay := baseDelay
	for range attempt - 1 {
		delay *= BackoffFactor
		if delay >= maxDelay {
			return jitter(maxDelay)
		}
	}
	return jitter(delay)
}

func jitter(delay time.Duration) time.Duration {
	if delay <= 0 {
		return 0
	}
	spread := delay / JitterDivisor
	if spread <= 0 {
		return delay
	}
	return delay + time.Duration(rand.Int64N(int64(spread)))
}

// Sleep waits for delay or returns as soon as ctx ends.
func Sleep(ctx context.Context, delay time.Duration) error {
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
