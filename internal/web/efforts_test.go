package web

import (
	"sync"
	"testing"

	"scrutineer/internal/config"
)

// TestEffortsMatchConfig guards against drift between web.Efforts (the source
// of truth, coupled to display labels) and config.Efforts (the independent
// list config.Load validates against at startup). Add a level to one and this
// fails until the other catches up.
func TestEffortsMatchConfig(t *testing.T) {
	if len(Efforts) != len(config.Efforts) {
		t.Fatalf("len(web.Efforts)=%d, len(config.Efforts)=%d", len(Efforts), len(config.Efforts))
	}
	for i, e := range Efforts {
		if e.Value != config.Efforts[i] {
			t.Errorf("Efforts[%d]=%q, config.Efforts[%d]=%q", i, e.Value, i, config.Efforts[i])
		}
		if err := config.ValidateEffort(e.Value); err != nil {
			t.Errorf("config.ValidateEffort(%q) = %v, want nil", e.Value, err)
		}
	}
}

func TestValidEffort(t *testing.T) {
	for _, e := range []string{"low", "medium", "high", "xhigh", "max"} {
		if !ValidEffort(e) {
			t.Errorf("ValidEffort(%q) = false, want true", e)
		}
	}
	for _, e := range []string{"", "High", "extreme", "garbage"} {
		if ValidEffort(e) {
			t.Errorf("ValidEffort(%q) = true, want false", e)
		}
	}
}

func TestServerDefaultEffort(t *testing.T) {
	var s Server
	if got := s.DefaultEffort(); got != builtinDefaultEffort {
		t.Errorf("DefaultEffort() with no override = %q, want %q", got, builtinDefaultEffort)
	}
	s.SetDefaultEffort("max")
	if got := s.DefaultEffort(); got != "max" {
		t.Errorf("DefaultEffort() with override = %q, want max", got)
	}
}

func TestServerSetDefaultEffort_rejectsInvalid(t *testing.T) {
	var s Server
	s.SetDefaultEffort("xhigh")
	if got := s.DefaultEffort(); got != "xhigh" {
		t.Fatalf("SetDefaultEffort(xhigh) = %q, want xhigh", got)
	}
	// An empty or unknown value must not clobber the current setting.
	s.SetDefaultEffort("")
	s.SetDefaultEffort("garbage")
	if got := s.DefaultEffort(); got != "xhigh" {
		t.Errorf("invalid SetDefaultEffort changed it to %q, want xhigh", got)
	}
}

func TestServerDefaults_concurrentReadWrite(t *testing.T) {
	// Exercises the defaultsMu guard so `go test -race` flags any
	// regression to unguarded package-level state. Both default-model
	// and default-effort share the mutex.
	var s Server
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 100 {
				s.SetDefaultEffort("max")
				s.SetDefaultModel("claude-opus-4-8")
			}
		}()
		go func() {
			defer wg.Done()
			for range 100 {
				_ = s.DefaultEffort()
				_ = s.DefaultModel()
			}
		}()
	}
	wg.Wait()
}
