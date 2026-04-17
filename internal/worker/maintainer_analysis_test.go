package worker

import (
	"strings"
	"testing"
)

func TestMaintainerPromptReferencesReportJSON(t *testing.T) {
	// The prompt tells claude to write report.json; the handler reads report.json.
	// If these diverge, the job silently fails. This test catches filename mismatches.
	prompt := gatherPrompt("https://github.com/example/repo", "{}", maintainerSchema)
	if !strings.Contains(prompt, "./report.json") {
		t.Fatal("prompt does not reference ./report.json")
	}
}

func TestMaintainerSchemaEmbeds(t *testing.T) {
	if len(maintainerSchema) < 100 {
		t.Fatal("maintainer_schema.json not embedded")
	}
	if !strings.Contains(maintainerSchema, `"maintainers"`) {
		t.Fatal("schema missing maintainers key")
	}
}
