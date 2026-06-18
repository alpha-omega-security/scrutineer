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
		{
			"../../skills/dependencies/schema.json",
			`{"dependencies":[]}`,
		},
		{
			"../../skills/dependencies/schema.json",
			`{"dependencies":[],"error":"git-pkgs not found on PATH"}`,
		},
		{
			"../../skills/public-issue/schema.json",
			`{"upstream":"owner/repo","title":"Harden parser input handling",
			  "url":"https://github.com/owner/repo/issues/123","truncated":false,"error":null}`,
		},
		{
			"../../skills/public-issue/schema.json",
			`{"error":"finding is High severity; use private disclosure"}`,
		},
		{
			"../../skills/threat-model/schema.json",
			`{"spec_version":1,"repository":"https://github.com/o/r","commit":"abc1234",
			  "date":"2026-05-08","scope_subpath":null,"description":"x",
			  "confidence":{"documented":1,"inferred":2},
			  "components":[{"name":"core","entry_points":["f"],"touches":[],
			    "in_scope":true,"provenance":"documented","source":"README.md:1"}],
			  "out_of_scope":[{"item":"contrib/","reason":"unsupported",
			    "provenance":"documented","source":"contrib/README"}],
			  "trust_boundaries":[{"component":"core","boundary":"public API",
			    "reachability_precondition":"reachable from input bytes","provenance":"inferred"}],
			  "entry_points":[{"entry_point":"gzopen","parameter":"path",
			    "attacker_controllable":"no","caller_must_enforce":"sanitise","provenance":"inferred"}],
			  "environment":{"assumes":["C runtime"],"does_not":["open sockets"],"provenance":"inferred"},
			  "build_variants":{"not_applicable":true,"reason":"no flags"},
			  "adversaries":{"in_scope":["input supplier"],"out_of_scope":["caller"],"provenance":"inferred"},
			  "properties_provided":[{"property":"memory safety","violation_symptom":"OOB",
			    "severity_tier":"security","provenance":"documented","source":"SECURITY.md:8"}],
			  "properties_not_provided":[{"property":"bounded output","reason":"caller's job",
			    "false_friend":false,"provenance":"inferred"}],
			  "attack_classes":["compression oracle"],
			  "downstream_responsibilities":["cap output size"],
			  "known_misuse":[{"pattern":"CRC as MAC","why_unsafe":"not a MAC","instead":"HMAC"}],
			  "known_non_findings":[{"reported_as":"strcpy in gzlib.c","why_safe":"bounded",
			    "cites":"properties_provided[0]"}],
			  "dispositions":["valid","valid_hardening","out_of_model_trusted_input",
			    "out_of_model_adversary","out_of_model_unsupported_component",
			    "out_of_model_non_default_build","by_design_disclaimed",
			    "known_non_finding","model_gap"],
			  "open_questions":[{"claim":"path is trusted","field":"entry_points","proposed":"yes"}]}`,
		},
		{
			"../../skills/vuln-scan/schema.json",
			`{"findings":[{"id":"F001","title":"Archive extraction writes outside the target directory",
			  "severity":"High","confidence":"medium","cwe":"CWE-22","location":"pkg/archive/extract.go:88",
			  "locations":["pkg/archive/extract.go:71"],"reachability":"reachable","quality_tier":"high",
			  "trace":"Archive entry names flow from ParseArchive to filepath.Join before Create.",
			  "boundary":"The public extraction API accepts caller-provided archives and does not document trusted entry names.",
			  "validation":"Static-only review checked for Clean, EvalSymlinks, and containment checks before file creation.",
			  "rating":"High impact because traversal can overwrite files outside the extraction root; medium confidence because no PoC was executed."}]}`,
		},
		{
			"../../skills/vuln-scan/schema.json",
			`{"findings":[]}`,
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
		{"../../skills/dependencies/schema.json", `{"dependencies":null}`, "/dependencies"},
		{"../../skills/public-issue/schema.json",
			`{"upstream":"owner/repo","url":"https://github.com/owner/repo/issues/123"}`, "oneOf"},
		{"../../skills/threat-model/schema.json", `{"spec_version":2}`, "/spec_version"},
		{"../../skills/vuln-scan/schema.json",
			`{"findings":[{"id":"F001","title":"Bad confidence","severity":"High",
			  "confidence":"maybe","cwe":"CWE-22","location":"pkg/archive/extract.go:88","reachability":"reachable",
			  "quality_tier":"high","trace":"x","boundary":"x","validation":"x","rating":"x"}]}`,
			"/findings/0/confidence"},
		{"../../skills/vuln-scan/schema.json",
			`{"findings":[{"id":"F001","title":"Bad location","severity":"High","confidence":"high",
			  "cwe":"CWE-22","location":"pkg/archive/extract.go","reachability":"reachable",
			  "quality_tier":"high","trace":"x","boundary":"x","validation":"x","rating":"x"}]}`,
			"/findings/0/location"},
		{"../../skills/threat-model/schema.json",
			`{"spec_version":1,"repository":"https://x","commit":"abc1234","date":"2026-01-01",
			  "description":"x","components":[{"name":"c","entry_points":[],"touches":[],
			  "in_scope":true,"provenance":"guessed"}],"out_of_scope":[],"trust_boundaries":[
			  {"component":"c","boundary":"x","provenance":"inferred"}],"entry_points":[],
			  "environment":{"assumes":[],"does_not":[],"provenance":"inferred"},
			  "adversaries":{"in_scope":[],"out_of_scope":[],"provenance":"inferred"},
			  "properties_provided":[],"properties_not_provided":[],
			  "downstream_responsibilities":[],"known_misuse":[],"known_non_findings":[],
			  "dispositions":["valid","valid_hardening","out_of_model_trusted_input",
			  "out_of_model_adversary","out_of_model_unsupported_component",
			  "out_of_model_non_default_build","by_design_disclaimed","known_non_finding",
			  "model_gap"],"open_questions":[]}`,
			"/components/0/provenance"},
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
