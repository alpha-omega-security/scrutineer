package web

// Model is a display-name → claude model id pair offered in the UI.
type Model struct {
	Name string
	ID   string
}

// Models is the pick list. The first entry is the default.
var Models = []Model{
	{"Mythos", "claude-mythos-preview"},
	{"Opus", "claude-opus-4-6"},
	{"Sonnet", "claude-sonnet-4-6"},
}

func DefaultModel() string { return Models[0].ID }

func ValidModel(id string) bool {
	for _, m := range Models {
		if m.ID == id {
			return true
		}
	}
	return false
}
