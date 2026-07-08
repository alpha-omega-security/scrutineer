package web

import (
	"strings"

	"scrutineer/internal/db"

	"gorm.io/gorm"
)

// Model is a display-name → model id pair offered in the UI. Tier
// optionally tags the entry as the default for one of the mid/high/max
// model tiers, so operators declaring their own models: list can name
// which entry each tier resolves to instead of relying on the built-in
// substring heuristic.
type Model struct {
	Name string
	ID   string
	Tier string
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

// Models is the pick list. The first entry is the default unless the
// server's runtime override is set; see Server.DefaultModel. Populated
// at startup by main.go from the active harness's DefaultModels(), or
// from the operator's models: config; there is no built-in list here
// so a new backend needs no edit to this file.
var Models []Model

// SetModels replaces the pick list. Called at startup from config; no-op
// for an empty list so a config with only default_model set keeps the
// built-in list.
func SetModels(models []Model) {
	if len(models) == 0 {
		return
	}
	Models = models
}

// SetDefaultModel pins the default model id, overriding "first entry in
// the pick list". Set at startup from config and mutable via
// /settings/model; in-memory only, so restart resets it to the
// configured default. The empty string and any id not in the pick list
// are no-ops, so a bad default_model in config can't silently install an
// invalid runtime default that resolveModelPreference would then
// propagate into scans. Mirrors SetDefaultEffort. Call SetModels first so
// a configured pick list is in place to validate against.
func (s *Server) SetDefaultModel(id string) {
	if id == "" || !ValidModel(id) {
		return
	}
	s.defaultsMu.Lock()
	s.defaultModel = id
	s.defaultsMu.Unlock()
}

// DefaultModel is the model id a tier falls back to when no
// tier-specific setting is configured. The runtime override wins;
// otherwise the first entry in the pick list.
func (s *Server) DefaultModel() string {
	s.defaultsMu.RLock()
	defer s.defaultsMu.RUnlock()
	if s.defaultModel != "" {
		return s.defaultModel
	}
	if len(Models) == 0 {
		return ""
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

// ModelForTier resolves a tier name to a concrete model id: a
// per-tier setting in the DB wins, then a built-in heuristic over the
// pick list, then the caller-supplied fallback (the server's default
// model). The fallback is threaded in rather than read from a global
// so the runtime default lives on Server behind a mutex.
func ModelForTier(gdb *gorm.DB, tier, fallback string) string {
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
	return builtinModelForTier(tier, fallback)
}

func ModelTierValues(gdb *gorm.DB, fallback string) map[string]string {
	values := make(map[string]string, len(ModelTiers))
	for _, tier := range ModelTiers {
		values[tier.Value] = ModelForTier(gdb, tier.Value, fallback)
	}
	return values
}

func builtinModelForTier(tier, fallback string) string {
	// An entry explicitly tagged tier: <mid|high|max> in the models: list
	// wins — the operator has said which model this tier means, so no
	// guessing. First match wins if several entries share a tier.
	for _, m := range Models {
		if m.Tier == tier {
			return m.ID
		}
	}
	// Otherwise the substring heuristic keeps older or minimally tagged
	// model lists usable: Mid → first sonnet, Max → latest opus.
	// A custom list that neither tags tiers nor matches these needles falls
	// through to DefaultModel; set the tiers in /settings for that case.
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
	return fallback
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

func resolveModelPreference(gdb *gorm.DB, preference, fallback string) string {
	if ValidModel(preference) {
		return preference
	}
	if ValidModelTier(preference) {
		return ModelForTier(gdb, preference, fallback)
	}
	return ModelForTier(gdb, ModelTierHigh, fallback)
}

// isDowngradableTier reports whether a model preference is one of the expensive
// tiers (max/high) or the empty default (which resolves to high), which the
// overage fallback rewrites to mid. A concrete model id or the mid tier is left
// as-is, so an explicit per-scan model choice is always honoured.
func isDowngradableTier(preference string) bool {
	return preference == "" || preference == ModelTierHigh || preference == ModelTierMax
}

// applyOverageDowngrade rewrites an expensive tier preference to mid when the
// overage fallback is active; otherwise it returns the preference unchanged.
// Kept as a pure function so the (active x preference) matrix is unit-testable
// without a live worker on overage.
func applyOverageDowngrade(preference string, active bool) string {
	if active && isDowngradableTier(preference) {
		return ModelTierMid
	}
	return preference
}
