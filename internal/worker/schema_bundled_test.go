package worker

import (
	"os"
	"strings"
	"testing"
)

// TestBundledSchemas_compileAndAcceptSamples checks that the three schemas
// added for #182 compile and accept a representative report. repo-overview
// and sbom samples are external-tool output so the schemas are intentionally
// loose; the point is catching a typo in the schema, not proving CycloneDX
// conformance.
func TestBundledSchemas_compileAndAcceptSamples(t *testing.T) {
	cases := []struct {
		schema string
		report string
	}{
		{
			"../../skills/triage/schema.json",
			`{"has_code":true,"has_packages":true,
			  "brief":{"languages":["Go"],"package_managers":["Go Modules"]},
			  "triggered":["packages","advisories","security-deep-dive"],
			  "skipped":["semgrep"],"gated":[],"already_done":["metadata"],
			  "verify":[12,34],"errors":[]}`,
		},
		{
			"../../skills/triage/schema.json",
			`{"error":"context.json missing scrutineer block"}`,
		},
		{
			"../../skills/repo-overview/schema.json",
			`{"version":"dev","path":"/x",
			  "languages":[{"name":"Go","category":"language"}],
			  "package_managers":[{"name":"Go Modules"}],
			  "git":{"branch":"main","default_branch":"main"},
			  "resources":{"license_type":"MIT","readme":"README.md"},
			  "tools":{},"lines":{"total_files":1},"dependencies":[],
			  "stats":{"duration_ms":1.2},"unknown_future_key":42}`,
		},
		{
			"../../skills/repo-overview/schema.json",
			`{"error":"scan_subpath not found: pkg/x"}`,
		},
		{
			"../../skills/sbom/schema.json",
			`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
			  "metadata":{"timestamp":"2026-01-01T00:00:00Z"},
			  "components":[{"type":"library","name":"left-pad","version":"1.0.0",
			    "purl":"pkg:npm/left-pad@1.0.0","bom-ref":"a"}],
			  "dependencies":[]}`,
		},
		{
			"../../skills/sbom/schema.json",
			`{"error":"git-pkgs: exit 1"}`,
		},
	}
	for _, tc := range cases {
		schema, err := os.ReadFile(tc.schema)
		if err != nil {
			t.Fatalf("read %s: %v", tc.schema, err)
		}
		if got := validateReportSchema(string(schema), tc.report); got != "" {
			t.Errorf("%s rejected sample: %s\nreport: %s", tc.schema, got, tc.report)
		}
	}
}

func TestBundledSchemas_rejectBadShapes(t *testing.T) {
	cases := []struct {
		schema string
		report string
		want   string
	}{
		{"../../skills/triage/schema.json", `{"triggered":"not-a-list"}`, "/triggered"},
		{"../../skills/triage/schema.json", `{"triggered":["Bad Name"]}`, "/triggered/0"},
		{"../../skills/repo-overview/schema.json", `{"languages":"go"}`, "/languages"},
		{"../../skills/sbom/schema.json", `{"bomFormat":"SPDX","specVersion":"1.5"}`, "/bomFormat"},
		{"../../skills/sbom/schema.json", `{"specVersion":"1.5"}`, "bomFormat"},
		{"../../skills/sbom/schema.json", `{}`, "oneOf"},
	}
	for _, tc := range cases {
		schema, err := os.ReadFile(tc.schema)
		if err != nil {
			t.Fatalf("read %s: %v", tc.schema, err)
		}
		got := validateReportSchema(string(schema), tc.report)
		if got == "" {
			t.Errorf("%s accepted bad report %s", tc.schema, tc.report)
			continue
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: error %q does not mention %q", tc.schema, got, tc.want)
		}
	}
}
