package web

// Model is a display-name → claude model id pair offered in the UI.
type Model struct {
	Name string
	ID   string
}

// Models is the pick list. The first entry is the default unless
// defaultModelOverride is set by the config loader.
var Models = []Model{
	{"Opus 4.6", "claude-opus-4-6"},
	{"Opus 4.7", "claude-opus-4-7"},
	{"Sonnet", "claude-sonnet-4-6"},
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
