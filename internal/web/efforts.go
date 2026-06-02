package web

// Effort is a display label paired with the claude `--effort` level it
// selects. The settings page renders these as a row of buttons in order,
// fastest to most thorough; the chosen Value is snapshotted onto each scan
// and passed straight through to `claude -p --effort`.
type Effort struct {
	Value string
	Label string
}

// Efforts is the ordered effort scale, fastest first. The Values are the
// only levels `claude --effort` accepts.
var Efforts = []Effort{
	{"low", "Low"},
	{"medium", "Medium"},
	{"high", "High"},
	{"xhigh", "Very high"},
	{"max", "Max"},
}

const builtinDefaultEffort = "high"

// defaultEffortOverride, when non-empty, is the runtime-selected effort
// applied to new scans. Set at startup from config and mutable via
// /settings/effort; empty leaves the built-in default. Mirrors the model
// override: in-memory only, so it resets to the configured default on
// restart.
var defaultEffortOverride string

// SetDefaultEffort pins the effort applied to new scans. No-op for an empty
// or unknown value so a bad config or form post leaves the current default.
func SetDefaultEffort(value string) {
	if ValidEffort(value) {
		defaultEffortOverride = value
	}
}

// DefaultEffort is the effort a new scan inherits when the caller pins none.
// The runtime override wins; otherwise the built-in default.
func DefaultEffort() string {
	if defaultEffortOverride != "" {
		return defaultEffortOverride
	}
	return builtinDefaultEffort
}

func ValidEffort(value string) bool {
	for _, e := range Efforts {
		if e.Value == value {
			return true
		}
	}
	return false
}
