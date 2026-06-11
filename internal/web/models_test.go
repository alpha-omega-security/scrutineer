package web

import "testing"

func TestModelTiers(t *testing.T) {
	if !ValidModelTier(ModelTierMid) || !ValidModelTier(ModelTierHigh) || !ValidModelTier(ModelTierMax) {
		t.Fatal("built-in model tiers should be valid")
	}
	if ValidModelTier("ultra") {
		t.Fatal("unknown tier should not be valid")
	}
	if got := builtinModelForTier(ModelTierMid); got != "claude-sonnet-4-6" {
		t.Errorf("mid tier default = %q, want sonnet", got)
	}
	if got := builtinModelForTier(ModelTierHigh); got != DefaultModel() {
		t.Errorf("high tier default = %q, want DefaultModel()", got)
	}
	if got := builtinModelForTier(ModelTierMax); got != "claude-opus-4-8" {
		t.Errorf("max tier default = %q, want latest opus", got)
	}
}

func TestDefaultModelTierForSkill(t *testing.T) {
	tests := map[string]string{
		"metadata":          ModelTierMid,
		deepDiveSkillName:   ModelTierMax,
		"maintainers":       ModelTierHigh,
		"totally-new-skill": ModelTierHigh,
	}
	for skill, want := range tests {
		if got := defaultModelTierForSkill(skill); got != want {
			t.Errorf("defaultModelTierForSkill(%q) = %q, want %q", skill, got, want)
		}
	}
}
