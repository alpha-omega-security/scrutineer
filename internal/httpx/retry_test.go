package httpx

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRetryAfterDelay(t *testing.T) {
	const fallback = 3 * time.Second
	// The HTTP-date branch reads time.Now() internally, so those cases assert
	// against a range rather than an exact value. The offsets are large and the
	// window is 30s wide so a slow CI runner cannot flake the assertion; the
	// point is which branch fired and whether the cap applied, not the precise
	// remaining delay.
	now := time.Now().UTC()
	httpDate := func(d time.Duration) string { return now.Add(d).Format(http.TimeFormat) }
	for _, tc := range []struct {
		name, header string
		maxDelay     time.Duration
		wantMin      time.Duration
		wantMax      time.Duration
	}{
		{"empty falls back", "", time.Minute, fallback, fallback},
		{"integer seconds", "5", time.Minute, 5 * time.Second, 5 * time.Second},
		{"integer seconds capped", "90", 30 * time.Second, 30 * time.Second, 30 * time.Second},
		{"http-date future", httpDate(5 * time.Minute), time.Hour, 270 * time.Second, 300 * time.Second},
		{"http-date future capped", httpDate(5 * time.Minute), 30 * time.Second, 30 * time.Second, 30 * time.Second},
		{"http-date past yields zero", httpDate(-time.Minute), time.Hour, 0, 0},
		{"garbage falls back", "not-a-time", time.Minute, fallback, fallback},
	} {
		got := retryAfterDelay(tc.header, fallback, tc.maxDelay)
		if got < tc.wantMin || got > tc.wantMax {
			t.Errorf("%s: retryAfterDelay(%q) = %v, want in [%v, %v]",
				tc.name, tc.header, got, tc.wantMin, tc.wantMax)
		}
	}
}

func TestDoRetrySucceedsAfterTransientStatus(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		if hits == 1 {
			http.Error(w, "temporary", http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := DoRetry(req, testRetryOptions(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if hits != 2 {
		t.Fatalf("hits = %d, want 2", hits)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestDoRetryDoesNotRetryNonTransientClientError(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := DoRetry(req, testRetryOptions(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if hits != 1 {
		t.Fatalf("hits = %d, want 1", hits)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestDoRetryRespectsRetryAfter(t *testing.T) {
	hits := 0
	var delays []time.Duration
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		if hits == 1 {
			w.Header().Set("Retry-After", "2")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	opts := testRetryOptions(func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		return nil
	})
	opts.MaxDelay = 5 * time.Second
	resp, err := DoRetry(req, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if len(delays) != 1 || delays[0] != 2*time.Second {
		t.Fatalf("delays = %v, want [2s]", delays)
	}
}

func TestDoRetryCapsRetryAfter(t *testing.T) {
	hits := 0
	var delays []time.Duration
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		if hits == 1 {
			w.Header().Set("Retry-After", "3600")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := DoRetry(req, testRetryOptions(func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if len(delays) != 1 || delays[0] != time.Millisecond {
		t.Fatalf("delays = %v, want [1ms]", delays)
	}
}

func TestDoRetryHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DoRetry(req, testRetryOptions(nil)); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestDoRetryRetriesNetworkErrors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	attempts := 0
	_, err = DoRetry(req, testRetryOptions(func(_ context.Context, _ time.Duration) error {
		attempts++
		return nil
	}))
	if err == nil {
		t.Fatal("expected network error")
	}
	if attempts != 2 {
		t.Fatalf("sleep attempts = %d, want 2", attempts)
	}
}

func testRetryOptions(sleep func(context.Context, time.Duration) error) RetryOptions {
	return RetryOptions{
		Attempts:  3,
		BaseDelay: time.Millisecond,
		MaxDelay:  time.Millisecond,
		Sleep:     sleep,
	}
}
