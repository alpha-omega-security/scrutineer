package testutil

import (
	"testing"
)

type stopTB struct {
	testing.TB
	stopped string
}

func (t *stopTB) Helper() {}

func (t *stopTB) Fatal(...any) {
	t.stopped = "fatal"
	panic(t)
}

func (t *stopTB) Skip(...any) {
	t.stopped = "skip"
	panic(t)
}

func postgresDSNStop(t *testing.T) (stopped string) {
	t.Helper()
	tb := &stopTB{TB: t}
	defer func() {
		if r := recover(); r != nil && r != tb {
			panic(r)
		}
		stopped = tb.stopped
	}()
	PostgresDSN(tb)
	return tb.stopped
}

func TestPostgresDSNWithoutServer(t *testing.T) {
	t.Setenv("SCRUTINEER_TEST_PG_DSN", "")
	t.Setenv("SCRUTINEER_TEST_PG_REQUIRED", "")
	if got := postgresDSNStop(t); got != "skip" {
		t.Errorf("optional: %q, want skip", got)
	}
	t.Setenv("SCRUTINEER_TEST_PG_REQUIRED", "1")
	if got := postgresDSNStop(t); got != "fatal" {
		t.Errorf("required: %q, want fatal", got)
	}
}
