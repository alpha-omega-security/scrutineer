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
// only levels `claude --effort` accepts. This is the source of truth for the
// effort levels; config.Efforts mirrors the Values for startup validation, and
// TestEffortsMatchConfig guards the two against drift.
var Efforts = []Effort{
	{"low", "Low"},
	{"medium", "Medium"},
	{"high", "High"},
	{"xhigh", "Very high"},
	{"max", "Max"},
}

const builtinDefaultEffort = "high"

// SetDefaultEffort pins the effort applied to new scans. No-op for an empty
// or unknown value so a bad config or form post leaves the current default.
// Set at startup from config and mutable via /settings/effort; in-memory
// only, so restart resets it to the configured default.
func (s *Server) SetDefaultEffort(value string) {
	if !ValidEffort(value) {
		return
	}
	s.defaultsMu.Lock()
	s.defaultEffort = value
	s.defaultsMu.Unlock()
}

// DefaultEffort is the effort a new scan inherits when the caller pins none.
// The runtime override wins; otherwise the built-in default.
func (s *Server) DefaultEffort() string {
	s.defaultsMu.RLock()
	defer s.defaultsMu.RUnlock()
	if s.defaultEffort != "" {
		return s.defaultEffort
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
