package web

import (
	"testing"

	"scrutineer/internal/worker"
)

func init() {
	// Production seeds Models from the active harness in main.go; tests
	// need a non-empty list too. Use the claude harness's own defaults
	// so tests that reference concrete ids (efforts_test.go,
	// settings_handlers_test.go) match without a second hardcoded list.
	for _, d := range (worker.ClaudeHarness{}).DefaultModels() {
		Models = append(Models, Model{Name: d.Name, ID: d.ID, Tier: d.Tier})
	}
}

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

func TestDefaultModel_emptyListReturnsEmpty(t *testing.T) {
	withTestModels(t, nil)
	var s Server
	if got := s.DefaultModel(); got != "" {
		t.Errorf("DefaultModel() with empty list = %q, want empty", got)
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
	// A list with no tier: tags and no sonnet/opus needle match: every
	// tier falls back to the operator's default_model. Set the tiers in
	// /settings or tag entries with tier: to avoid this.
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

func TestModelTiers_explicitTierTags(t *testing.T) {
	// Entries tagged tier: <mid|high|max> in the models: list are the
	// tier default, no needle matching. This is how a non-Anthropic model
	// list (e.g. the codex backend's) declares which entry each tier means
	// so the tiers UI doesn't collapse to default_model in every slot.
	withTestModels(t, []Model{
		{Name: "GPT-5.3 Codex", ID: "gpt-5.3-codex", Tier: ModelTierHigh},
		{Name: "GPT-5.4", ID: "gpt-5.4"},
		{Name: "GPT-5.4 mini", ID: "gpt-5.4-mini", Tier: ModelTierMid},
		{Name: "GPT-5.5", ID: "gpt-5.5", Tier: ModelTierMax},
	})
	if got := builtinModelForTier(ModelTierMid, "gpt-5.3-codex"); got != "gpt-5.4-mini" {
		t.Errorf("mid = %q, want gpt-5.4-mini (tier: mid)", got)
	}
	if got := builtinModelForTier(ModelTierHigh, "gpt-5.3-codex"); got != "gpt-5.3-codex" {
		t.Errorf("high = %q, want gpt-5.3-codex (tier: high)", got)
	}
	if got := builtinModelForTier(ModelTierMax, "gpt-5.3-codex"); got != "gpt-5.5" {
		t.Errorf("max = %q, want gpt-5.5 (tier: max)", got)
	}
}

func TestModelTiers_explicitTierBeatsNeedle(t *testing.T) {
	// An explicit tier: tag wins over the substring heuristic even when a
	// needle would match a different entry.
	withTestModels(t, []Model{
		{Name: "Sonnet", ID: "test-sonnet"},
		{Name: "Mid", ID: "test-explicit-mid", Tier: ModelTierMid},
	})
	if got := builtinModelForTier(ModelTierMid, "fallback"); got != "test-explicit-mid" {
		t.Errorf("mid = %q, want test-explicit-mid (explicit tier: beats sonnet needle)", got)
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
