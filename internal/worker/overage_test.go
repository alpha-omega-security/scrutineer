package worker

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestWorker_OnOverageAndShouldDowngrade(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	w := &Worker{Now: func() time.Time { return now }}

	var nilW *Worker
	if nilW.OnOverage() || nilW.ShouldDowngradeModel() {
		t.Fatal("nil worker must be false and not panic")
	}
	if w.OnOverage() || w.ShouldDowngradeModel() {
		t.Fatal("no events: not on overage, no downgrade")
	}

	// An allowed window without overage does not trigger.
	w.recordRateLimit(RateLimitInfo{Type: "five_hour", Status: "allowed", ResetsAt: now.Add(time.Hour).Unix()})
	if w.OnOverage() {
		t.Fatal("allowed window is not overage")
	}

	// A window on overage with a future reset is on overage.
	w.recordRateLimit(RateLimitInfo{Type: "seven_day", Status: "allowed", IsUsingOverage: true, ResetsAt: now.Add(24 * time.Hour).Unix()})
	if !w.OnOverage() {
		t.Fatal("overage window with future reset should be on overage")
	}
	if w.ShouldDowngradeModel() {
		t.Fatal("downgrade stays off until the feature is enabled")
	}
	w.DowngradeOnOverage = true
	if !w.ShouldDowngradeModel() {
		t.Fatal("downgrade should be active when enabled and on overage")
	}

	// An expired overage reset no longer counts (stale window).
	w.recordRateLimit(RateLimitInfo{Type: "seven_day", Status: "allowed", IsUsingOverage: true, ResetsAt: now.Add(-time.Minute).Unix()})
	if w.OnOverage() {
		t.Fatal("expired overage window must not count")
	}

	// Overage with no reset timestamp counts (unknown reset -> stay on the cheaper tier).
	w.recordRateLimit(RateLimitInfo{Type: "five_hour", Status: "allowed", IsUsingOverage: true})
	if !w.OnOverage() {
		t.Fatal("overage with no reset should count as active")
	}
}

func TestWorker_recordRateLimitAnnouncesTransition(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	w := &Worker{Now: func() time.Time { return now }, Log: slog.New(slog.NewTextHandler(&buf, nil)), DowngradeOnOverage: true}

	// allowed -> no transition, no log
	w.recordRateLimit(RateLimitInfo{Type: "seven_day", Status: "allowed"})
	if strings.Contains(buf.String(), "overage fallback") {
		t.Fatalf("unexpected transition log: %q", buf.String())
	}
	// crossing into overage logs "engaged"
	w.recordRateLimit(RateLimitInfo{Type: "seven_day", Status: "allowed", IsUsingOverage: true, ResetsAt: now.Add(time.Hour).Unix()})
	if !strings.Contains(buf.String(), "engaged") {
		t.Fatalf("expected 'engaged' log, got: %q", buf.String())
	}
	// leaving overage logs "lifted"
	buf.Reset()
	w.recordRateLimit(RateLimitInfo{Type: "seven_day", Status: "allowed", IsUsingOverage: false})
	if !strings.Contains(buf.String(), "lifted") {
		t.Fatalf("expected 'lifted' log, got: %q", buf.String())
	}
}

func TestWorker_recordRateLimitNoLogWhenDisabled(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	w := &Worker{Now: func() time.Time { return now }, Log: slog.New(slog.NewTextHandler(&buf, nil))} // feature off
	w.recordRateLimit(RateLimitInfo{Type: "seven_day", Status: "allowed", IsUsingOverage: true, ResetsAt: now.Add(time.Hour).Unix()})
	if strings.Contains(buf.String(), "overage fallback") {
		t.Fatalf("must not log the fallback when disabled: %q", buf.String())
	}
}
