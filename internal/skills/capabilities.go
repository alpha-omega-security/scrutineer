package skills

import (
	"fmt"
	"regexp"
)

var capabilityCommand = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}$`)

// ValidateCapabilities also protects jobs built directly from stored skill rows.
// Commands are executable names, never paths, arguments, or shell programs.
func ValidateCapabilities(commands, features []string) error {
	if len(commands) > 64 || len(features) > 64 {
		return fmt.Errorf("capability requirements must contain at most 64 entries per list")
	}
	seen := make(map[string]bool)
	for _, command := range commands {
		if !capabilityCommand.MatchString(command) || seen["command:"+command] {
			return fmt.Errorf("invalid or duplicate required command %q", command)
		}
		seen["command:"+command] = true
	}
	for _, feature := range features {
		switch feature {
		case "docker-in-docker", "fuse", "network-egress":
		default:
			return fmt.Errorf("unknown required feature %q", feature)
		}
		if seen["feature:"+feature] {
			return fmt.Errorf("duplicate required feature %q", feature)
		}
		seen["feature:"+feature] = true
	}
	return nil
}
