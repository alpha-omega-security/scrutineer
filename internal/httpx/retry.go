package httpx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	retryx "scrutineer/internal/retry"
)

const (
	defaultAttempts  = 3
	defaultBaseDelay = 200 * time.Millisecond
	defaultMaxDelay  = 2 * time.Second
)

// RetryOptions configures DoRetry. Zero values use small bounded defaults.
type RetryOptions struct {
	Attempts  int
	BaseDelay time.Duration
	MaxDelay  time.Duration
	Sleep     func(context.Context, time.Duration) error
}

// DoRetry performs an idempotent HTTP request with a small retry budget for
// transient upstream failures. It retries network errors and 429/502/503/504
// responses, respects Retry-After when present, and always honors req.Context().
func DoRetry(req *http.Request, opts RetryOptions) (*http.Response, error) {
	if req.Method != http.MethodGet {
		return nil, fmt.Errorf("retry helper only supports GET, got %s", req.Method)
	}
	attempts := defaultedAttempts(opts.Attempts)
	baseDelay := defaultedDuration(opts.BaseDelay, defaultBaseDelay)
	maxDelay := defaultedDuration(opts.MaxDelay, defaultMaxDelay)
	sleep := opts.Sleep
	if sleep == nil {
		sleep = retryx.Sleep
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := req.Context().Err(); err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req.Clone(req.Context()))
		if err == nil && !retryableStatus(resp.StatusCode) {
			return resp, nil
		}
		if attempt == attempts {
			if err != nil {
				return nil, err
			}
			return resp, nil
		}

		delay := retryx.BackoffDelay(attempt, baseDelay, maxDelay)
		if err != nil {
			lastErr = err
		} else {
			delay = retryAfterDelay(resp.Header.Get("Retry-After"), delay, maxDelay)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		if err := sleep(req.Context(), delay); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

func defaultedAttempts(attempts int) int {
	if attempts > 0 {
		return attempts
	}
	return defaultAttempts
}

func defaultedDuration(v, fallback time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return fallback
}

func retryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func retryAfterDelay(header string, fallback, maxDelay time.Duration) time.Duration {
	if header == "" {
		return fallback
	}
	if seconds, err := strconv.Atoi(header); err == nil {
		return capDelay(time.Duration(seconds)*time.Second, maxDelay)
	}
	if at, err := http.ParseTime(header); err == nil {
		delay := time.Until(at)
		if delay > 0 {
			return capDelay(delay, maxDelay)
		}
		return 0
	}
	return fallback
}

func capDelay(delay, maxDelay time.Duration) time.Duration {
	if maxDelay > 0 && delay > maxDelay {
		return maxDelay
	}
	return delay
}
