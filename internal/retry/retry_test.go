package retry

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBackoffDelayBounds(t *testing.T) {
	const (
		base    = 100 * time.Millisecond
		ceiling = 400 * time.Millisecond
	)
	want := []time.Duration{base, 2 * base, ceiling, ceiling, ceiling}
	for attempt, floor := range want {
		got := BackoffDelay(attempt+1, base, ceiling)
		limit := floor + floor/JitterDivisor
		if got < floor || got >= limit {
			t.Errorf("BackoffDelay(%d) = %v, want [%v, %v)", attempt+1, got, floor, limit)
		}
	}
}

func TestBackoffDelayIsJittered(t *testing.T) {
	const (
		base    = 100 * time.Millisecond
		ceiling = time.Second
		samples = 200
	)
	lowest, highest := time.Duration(1<<62), time.Duration(0)
	for range samples {
		delay := BackoffDelay(1, base, ceiling)
		if delay < base || delay >= base+base/JitterDivisor {
			t.Fatalf("jittered delay %v outside [%v, %v)", delay, base, base+base/JitterDivisor)
		}
		lowest = min(lowest, delay)
		highest = max(highest, delay)
	}
	if spread := highest - lowest; spread < base/20 {
		t.Errorf("%d samples spanned only %v (%v..%v); backoff is effectively unjittered",
			samples, spread, lowest, highest)
	}
}

func TestSleepReturnsOnContextEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Sleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("Sleep on a cancelled context = %v, want context.Canceled", err)
	}
	if err := Sleep(context.Background(), time.Nanosecond); err != nil {
		t.Errorf("Sleep for a tiny delay = %v, want nil", err)
	}
}
