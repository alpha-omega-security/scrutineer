package worker

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

const semanticValidationTestSchema = `{
  "type": "object",
  "required": ["inventory", "findings", "ruled_out"],
  "properties": {
    "inventory": {"type": "array"},
    "findings": {"type": "array"},
    "ruled_out": {"type": "array"}
  }
}`

func TestValidateReportSemanticsDeepDiveSinkDispositions(t *testing.T) {
	tests := []struct {
		name   string
		report string
		want   string
	}{
		{
			name:   "complete",
			report: `{"inventory":[{"id":"S1"},{"id":"S2"}],"findings":[{"id":"F1","sinks":["S1"]}],"ruled_out":[{"sinks":["S2"]}]}`,
		},
		{
			name:   "unresolved inventory",
			report: `{"inventory":[{"id":"S1"}],"findings":[],"ruled_out":[]}`,
			want:   "inventory sink S1 has no disposition",
		},
		{
			name:   "unknown finding reference",
			report: `{"inventory":[{"id":"S1"}],"findings":[{"id":"F3","sinks":["S99"]}],"ruled_out":[{"sinks":["S1"]}]}`,
			want:   "finding F3 references unknown sink S99",
		},
		{
			name:   "duplicate inventory id",
			report: `{"inventory":[{"id":"S1"},{"id":"S1"}],"findings":[{"id":"F1","sinks":["S1"]}],"ruled_out":[]}`,
			want:   "inventory sink S1 is duplicated",
		},
		{
			name:   "finding ruled out conflict",
			report: `{"inventory":[{"id":"S4"}],"findings":[{"id":"F1","sinks":["S4"]}],"ruled_out":[{"sinks":["S4"]}]}`,
			want:   "sink S4 appears in both findings and ruled_out",
		},
		{
			name:   "repeated finding reference",
			report: `{"inventory":[{"id":"S1"}],"findings":[{"id":"F1","sinks":["S1","S1"]}],"ruled_out":[]}`,
			want:   "finding F1 repeats sink S1",
		},
		{
			name:   "repeated ruled out reference",
			report: `{"inventory":[{"id":"S1"}],"findings":[],"ruled_out":[{"sinks":["S1","S1"]}]}`,
			want:   "ruled_out[0] repeats sink S1",
		},
		{
			name:   "empty inventory",
			report: `{"inventory":[],"findings":[],"ruled_out":[]}`,
		},
		{
			name:   "malformed json",
			report: `{"inventory":`,
			want:   "report.json is not valid JSON",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateReportSemantics(deepDiveSkillName, tc.report)
			if tc.want == "" && got != "" {
				t.Fatalf("ValidateReportSemantics() = %q, want valid", got)
			}
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("ValidateReportSemantics() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidateSkillReportAppliesSemanticsOnlyToDeepDive(t *testing.T) {
	incomplete := `{"inventory":[{"id":"S1"}],"findings":[],"ruled_out":[]}`
	if got := ValidateSkillReport("posture", semanticValidationTestSchema, incomplete); got != "" {
		t.Fatalf("other skill validation = %q, want schema-valid report", got)
	}
	if got := ValidateSkillReport(deepDiveSkillName, semanticValidationTestSchema, incomplete); !strings.Contains(got, "inventory sink S1 has no disposition") {
		t.Fatalf("deep-dive validation = %q, want unresolved sink", got)
	}
}

func TestValidateReportSemanticsKeepsCausalErrorOrder(t *testing.T) {
	report := `{"inventory":[{"id":"S1"},{"id":"S1"}],"findings":[{"id":"F1","sinks":["S99"]}],"ruled_out":[]}`
	want := strings.Join([]string{
		"inventory sink S1 is duplicated",
		"finding F1 references unknown sink S99",
		"inventory sink S1 has no disposition",
	}, "\n")
	if got := ValidateReportSemantics(deepDiveSkillName, report); got != want {
		t.Fatalf("ValidateReportSemantics() = %q, want %q", got, want)
	}
}

func TestRepairSchemaReportRepairsSemanticFailure(t *testing.T) {
	incomplete := `{"inventory":[{"id":"S1"}],"findings":[],"ruled_out":[]}`
	repaired := `{"inventory":[{"id":"S1"}],"findings":[{"id":"F1","sinks":["S1"]}],"ruled_out":[]}`
	runner := &sequenceRunner{results: []SkillResult{{Report: repaired}}}
	skill := &db.Skill{Name: deepDiveSkillName, SchemaJSON: semanticValidationTestSchema, OutputKind: "freeform"}
	scan := &db.Scan{SessionID: "session-1"}
	w := &Worker{
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Runner:       runner,
		SchemaStrict: true,
	}
	var events []Event
	report, err := w.repairAndParseSkillOutput(context.Background(), skill, scan, SkillJob{}, incomplete, func(e Event) {
		events = append(events, e)
	})
	if err != nil {
		t.Fatalf("repairAndParseSkillOutput: %v", err)
	}
	if report != repaired {
		t.Fatalf("report = %q, want repaired report", report)
	}
	if len(runner.jobs) != 1 {
		t.Fatalf("RunSkill calls = %d, want 1", len(runner.jobs))
	}
	if prompt := runner.jobs[0].ResumePrompt; !strings.Contains(prompt, "inventory sink S1 has no disposition") || !strings.Contains(prompt, "comply with any skill-specific report rules") {
		t.Fatalf("repair prompt does not require semantic repair: %q", prompt)
	}
	for _, event := range events {
		if strings.Contains(event.Text, "still does not validate") {
			t.Fatalf("repair should have revalidated semantic output: %#v", events)
		}
	}
}
