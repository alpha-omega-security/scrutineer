package web

import "testing"

func withTestModels(t *testing.T, models []Model) {
	t.Helper()
	oldModels := Models
	Models = models
	t.Cleanup(func() { Models = oldModels })
}

func TestServerDefaultModel(t *testing.T) {
	withTestModels(t, []Model{
		{Name: "First", ID: "first-entry"},
		{Name: "Second", ID: "second-entry"},
	})
	var s Server
	if got := s.DefaultModel(); got != "first-entry" {
		t.Errorf("DefaultModel() with no override = %q, want first pick-list entry", got)
	}
	s.SetDefaultModel("second-entry")
	if got := s.DefaultModel(); got != "second-entry" {
		t.Errorf("DefaultModel() with override = %q, want second-entry", got)
	}
	// Empty must not clobber an existing override; main.go calls
	// SetDefaultModel unconditionally with whatever the config held.
	s.SetDefaultModel("")
	if got := s.DefaultModel(); got != "second-entry" {
		t.Errorf("SetDefaultModel(\"\") cleared override to %q", got)
	}
	// An id outside the pick list (e.g. a typo in config's default_model)
	// must be rejected rather than installed as the runtime default.
	s.SetDefaultModel("not-in-pick-list")
	if got := s.DefaultModel(); got != "second-entry" {
		t.Errorf("SetDefaultModel(invalid) changed override to %q, want second-entry", got)
	}
}

func TestModelTiers(t *testing.T) {
	withTestModels(t, []Model{
		{Name: "High", ID: "test-high"},
		{Name: "Sonnet", ID: "test-sonnet"},
		{Name: "Opus A", ID: "test-opus-a"},
		{Name: "Opus B", ID: "test-opus-b"},
	})

	if !ValidModelTier(ModelTierMid) || !ValidModelTier(ModelTierHigh) || !ValidModelTier(ModelTierMax) {
		t.Fatal("built-in model tiers should be valid")
	}
	if ValidModelTier("ultra") {
		t.Fatal("unknown tier should not be valid")
	}
	const fallback = "test-high"
	if got := builtinModelForTier(ModelTierMid, fallback); got != "test-sonnet" {
		t.Errorf("mid tier default = %q, want sonnet", got)
	}
	if got := builtinModelForTier(ModelTierHigh, fallback); got != fallback {
		t.Errorf("high tier default = %q, want fallback", got)
	}
	if got := builtinModelForTier(ModelTierMax, fallback); got != "test-opus-b" {
		t.Errorf("max tier default = %q, want latest opus", got)
	}
}

func TestModelTiersFallbackToDefaultModelWithCustomModelList(t *testing.T) {
	withTestModels(t, []Model{
		{Name: "Default", ID: "vendor-default"},
		{Name: "Small", ID: "vendor-small"},
	})

	for _, tier := range []string{ModelTierMid, ModelTierHigh, ModelTierMax} {
		if got := builtinModelForTier(tier, "vendor-default"); got != "vendor-default" {
			t.Errorf("builtinModelForTier(%q) = %q, want vendor-default", tier, got)
		}
	}
}

func TestResolveModelPreference(t *testing.T) {
	withTestModels(t, []Model{
		{Name: "High", ID: "test-high"},
		{Name: "Sonnet", ID: "test-sonnet"},
		{Name: "Opus", ID: "test-opus"},
	})

	const fallback = "test-high"
	if got := resolveModelPreference(nil, "test-opus", fallback); got != "test-opus" {
		t.Errorf("exact model = %q, want test-opus", got)
	}
	if got := resolveModelPreference(nil, ModelTierMid, fallback); got != "test-sonnet" {
		t.Errorf("tier model = %q, want test-sonnet", got)
	}
	if got := resolveModelPreference(nil, "not-configured", fallback); got != "test-high" {
		t.Errorf("invalid preference fallback = %q, want high tier default", got)
	}
}
