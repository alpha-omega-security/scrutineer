package worker

import (
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/skills"
)

// The stub guards are only on while the bundled schemas, with the shared
// audit findings schema inlined, require trace, boundary and validation.
func TestSchemaRequiresEvidence_bundledSkills(t *testing.T) {
	paths, err := filepath.Glob("../../skills/*/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	schemas := map[string]string{}
	for _, path := range paths {
		parsed, err := skills.ParseFile(path)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		schemas[parsed.Name] = parsed.SchemaJSON
	}
	want := map[string]bool{
		"security-deep-dive": true, "vuln-scan": true, "variants": true, "reachability": true,
		"advisory-deep-dive": true, "investigate": true,
		"semgrep": false, "bandit": false, "betterleaks": false,
	}
	audits := 0
	for name := range schemas {
		if strings.HasPrefix(name, "audit-") {
			want[name] = true
			audits++
		}
	}
	if audits == 0 {
		t.Fatal("no audit-* skills found")
	}
	for name, required := range want {
		schema, ok := schemas[name]
		if !ok {
			t.Errorf("bundled skill %s not found", name)
			continue
		}
		if got := schemaRequiresEvidence(schema); got != required {
			t.Errorf("%s: schemaRequiresEvidence = %v, want %v", name, got, required)
		}
	}
}
