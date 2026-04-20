package worker

import (
	"context"
)

// fakeRunner stubs the SkillRunner for unit tests: emits a log line so the
// wrap() path is exercised and returns a pre-set result. Shared by the
// skill and parser test files in this package.
type fakeRunner struct {
	skillRes SkillResult
	skillErr error
}

func (f fakeRunner) RunSkill(_ context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	emit(Event{Kind: "text", Text: "running skill " + sj.Name})
	return f.skillRes, f.skillErr
}
