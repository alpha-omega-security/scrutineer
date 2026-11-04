package web

import (
	"slices"

	"scrutineer/internal/db"
)

// lifecycleStep is one state on the finding page's progress line.
type lifecycleStep struct {
	Name  string
	State string // done | current | todo
}

// findingLifecycleSteps lays the main track out up to the finding's status.
// Rejected and duplicate findings left the track, so they get no line.
func findingLifecycleSteps(status db.FindingLifecycle) []lifecycleStep {
	if status == db.FindingRejected || status == db.FindingDuplicate || !slices.Contains(db.FindingLifecycles, status) {
		return nil
	}
	steps := make([]lifecycleStep, 0, len(db.FindingLifecycles))
	state := "done"
	for _, s := range db.FindingLifecycles {
		if s == db.FindingRejected || s == db.FindingDuplicate {
			continue
		}
		if s == status {
			steps = append(steps, lifecycleStep{Name: string(s), State: "current"})
			state = "todo"
			continue
		}
		steps = append(steps, lifecycleStep{Name: string(s), State: state})
	}
	return steps
}
