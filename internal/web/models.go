package web

import (
	"strings"

	"scrutineer/internal/db"

	"gorm.io/gorm"
)

// Model is a display-name → claude model id pair offered in the UI.
type Model struct {
	Name string
	ID   string
}

// ModelTier is an operator-facing role whose concrete model can be swapped
// in Settings without editing every skill that uses that role.
type ModelTier struct {
	Name        string
	Value       string
	Description string
}

const (
	ModelTierMid  = "mid"
	ModelTierHigh = "high"
	ModelTierMax  = "max"
)

var ModelTiers = []ModelTier{
	{Name: "Mid", Value: ModelTierMid, Description: "Fast model for lightweight data gathering."},
	{Name: "High", Value: ModelTierHigh, Description: "Default model for most analysis skills."},
	{Name: "Max", Value: ModelTierMax, Description: "Best available model for deep security review."},
}

// Models is the pick list. The first entry is the default unless
// defaultModelOverride is set by the config loader.
var Models = []Model{
	{"Opus 4.6", "claude-opus-4-6"},
	{"Opus 4.7", "claude-opus-4-7"},
	{"Opus 4.8", "claude-opus-4-8"},
	{"Sonnet", "claude-sonnet-4-6"},
	{"Fable 5", "claude-fable-5[1m]"},
}

// defaultModelOverride, when non-empty, replaces the first-entry-wins
// rule. Set at startup from config; empty leaves Models[0] as default.
var defaultModelOverride string

// SetModels replaces the pick list. Called at startup from config; no-op
// for an empty list so a config with only default_model set keeps the
// built-in list.
func SetModels(models []Model) {
	if len(models) == 0 {
		return
	}
	Models = models
}

// SetDefaultModel pins the default model id, overriding "first entry".
// Called at startup from config.
func SetDefaultModel(id string) {
	defaultModelOverride = id
}

func DefaultModel() string {
	if defaultModelOverride != "" {
		return defaultModelOverride
	}
	return Models[0].ID
}

func ValidModel(id string) bool {
	for _, m := range Models {
		if m.ID == id {
			return true
		}
	}
	return false
}

func ValidModelTier(tier string) bool {
	for _, t := range ModelTiers {
		if t.Value == tier {
			return true
		}
	}
	return false
}

func ValidModelPreference(value string) bool {
	return ValidModel(value) || ValidModelTier(value)
}

func modelTierSettingKey(tier string) string {
	switch tier {
	case ModelTierMid:
		return db.SettingModelTierMid
	case ModelTierHigh:
		return db.SettingModelTierHigh
	case ModelTierMax:
		return db.SettingModelTierMax
	default:
		return ""
	}
}

func ModelForTier(gdb *gorm.DB, tier string) string {
	if !ValidModelTier(tier) {
		tier = ModelTierHigh
	}
	if gdb != nil {
		if key := modelTierSettingKey(tier); key != "" {
			if model, ok := db.GetSetting(gdb, key); ok && ValidModel(model) {
				return model
			}
		}
	}
	return builtinModelForTier(tier)
}

func ModelTierValues(gdb *gorm.DB) map[string]string {
	values := make(map[string]string, len(ModelTiers))
	for _, tier := range ModelTiers {
		values[tier.Value] = ModelForTier(gdb, tier.Value)
	}
	return values
}

func builtinModelForTier(tier string) string {
	// Built-in tiers assume the built-in Anthropic-flavoured model ids and
	// ordering. If operators replace Models with a multi-vendor list that
	// lacks "sonnet" or "opus", the tier intentionally falls back to
	// DefaultModel unless they configure the tier in Settings.
	switch tier {
	case ModelTierMid:
		if id := firstModelContaining("sonnet"); id != "" {
			return id
		}
	case ModelTierMax:
		if id := lastModelContaining("opus"); id != "" {
			return id
		}
	}
	return DefaultModel()
}

func firstModelContaining(needle string) string {
	for _, model := range Models {
		if strings.Contains(strings.ToLower(model.ID), needle) {
			return model.ID
		}
	}
	return ""
}

func lastModelContaining(needle string) string {
	for i := len(Models) - 1; i >= 0; i-- {
		if strings.Contains(strings.ToLower(Models[i].ID), needle) {
			return Models[i].ID
		}
	}
	return ""
}

func resolveModelPreference(gdb *gorm.DB, preference string) string {
	if ValidModel(preference) {
		return preference
	}
	if ValidModelTier(preference) {
		return ModelForTier(gdb, preference)
	}
	return ModelForTier(gdb, ModelTierHigh)
}
