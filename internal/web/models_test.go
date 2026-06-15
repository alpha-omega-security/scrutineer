package web

import "testing"

func withTestModels(t *testing.T, models []Model) {
	t.Helper()
	oldModels := Models
	oldDefault := defaultModelOverride
	Models = models
	defaultModelOverride = ""
	t.Cleanup(func() {
		Models = oldModels
		defaultModelOverride = oldDefault
	})
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
	if got := builtinModelForTier(ModelTierMid); got != "test-sonnet" {
		t.Errorf("mid tier default = %q, want sonnet", got)
	}
	if got := builtinModelForTier(ModelTierHigh); got != DefaultModel() {
		t.Errorf("high tier default = %q, want DefaultModel()", got)
	}
	if got := builtinModelForTier(ModelTierMax); got != "test-opus-b" {
		t.Errorf("max tier default = %q, want latest opus", got)
	}
}

func TestModelTiersFallbackToDefaultModelWithCustomModelList(t *testing.T) {
	withTestModels(t, []Model{
		{Name: "Default", ID: "vendor-default"},
		{Name: "Small", ID: "vendor-small"},
	})

	for _, tier := range []string{ModelTierMid, ModelTierHigh, ModelTierMax} {
		if got := builtinModelForTier(tier); got != "vendor-default" {
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

	if got := resolveModelPreference(nil, "test-opus"); got != "test-opus" {
		t.Errorf("exact model = %q, want test-opus", got)
	}
	if got := resolveModelPreference(nil, ModelTierMid); got != "test-sonnet" {
		t.Errorf("tier model = %q, want test-sonnet", got)
	}
	if got := resolveModelPreference(nil, "not-configured"); got != "test-high" {
		t.Errorf("invalid preference fallback = %q, want high tier default", got)
	}
}
