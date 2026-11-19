package worker

import (
	"encoding/json"
	"strings"
	"testing"
)

// threatModelWithEntryPoint is a minimal valid threat-model report whose only
// entry point is the given JSON object.
func threatModelWithEntryPoint(entry string) string {
	return `{"spec_version":1,"repository":"https://github.com/o/r","commit":"abc1234",
	  "date":"2026-05-08","scope_subpath":null,"description":"x",
	  "confidence":{"documented":0,"inferred":1},
	  "components":[{"name":"core","entry_points":["f"],"touches":[],"in_scope":true,"provenance":"inferred"}],
	  "out_of_scope":[],
	  "trust_boundaries":[{"component":"core","boundary":"public API","provenance":"inferred"}],
	  "entry_points":[` + entry + `],
	  "environment":{"assumes":[],"does_not":[],"provenance":"inferred"},
	  "build_variants":{"not_applicable":true,"reason":"no flags"},
	  "adversaries":{"in_scope":[],"out_of_scope":[],"provenance":"inferred"},
	  "properties_provided":[],"properties_not_provided":[],
	  "attack_classes":[],"downstream_responsibilities":[],"known_misuse":[],"known_non_findings":[],
	  "dispositions":["valid","valid_hardening","out_of_model_trusted_input",
	    "out_of_model_adversary","out_of_model_unsupported_component",
	    "out_of_model_non_default_build","by_design_disclaimed",
	    "known_non_finding","model_gap"],
	  "open_questions":[]}`
}

func TestThreatModelSchemaConditionalEntryPointNeedsCondition(t *testing.T) {
	schema := loadBundledSchema(t, "../../skills/threat-model/schema.json")
	cases := []struct {
		name  string
		entry string
		ok    bool
	}{
		{"conditional with condition",
			`{"entry_point":"f","parameter":"p","attacker_controllable":"conditional","condition":"when the server enables uploads","provenance":"inferred"}`, true},
		{"conditional without condition",
			`{"entry_point":"f","parameter":"p","attacker_controllable":"conditional","provenance":"inferred"}`, false},
		{"conditional with empty condition",
			`{"entry_point":"f","parameter":"p","attacker_controllable":"conditional","condition":"","provenance":"inferred"}`, false},
		{"conditional with blank condition",
			`{"entry_point":"f","parameter":"p","attacker_controllable":"conditional","condition":" \t\n","provenance":"inferred"}`, false},
		{"yes without condition",
			`{"entry_point":"f","parameter":"p","attacker_controllable":"yes","provenance":"inferred"}`, true},
		{"no with condition",
			`{"entry_point":"f","parameter":"p","attacker_controllable":"no","condition":"never","provenance":"inferred"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateReportSchema(schema, threatModelWithEntryPoint(tc.entry))
			if tc.ok && got != "" {
				t.Fatalf("valid entry rejected: %s", got)
			}
			if !tc.ok && (got == "" || !strings.Contains(got, "/entry_points/0")) {
				t.Fatalf("invalid entry: error %q, want a rejection at /entry_points/0", got)
			}
		})
	}
}

func TestFindingSchemasDeclareIdentity(t *testing.T) {
	for _, schemaPath := range []string{
		"../../skills/security-deep-dive/schema.json",
		"../../skills/advisory-deep-dive/schema.json",
		"../../skills/variants/schema.json",
		"../../skills/reachability/schema.json",
		"../../skills/vuln-scan/schema.json",
	} {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(loadBundledSchema(t, schemaPath)), &parsed); err != nil {
			t.Fatalf("%s: %v", schemaPath, err)
		}
		defs, _ := parsed["$defs"].(map[string]any)
		finding, _ := defs["finding"].(map[string]any)
		props, _ := finding["properties"].(map[string]any)
		for _, key := range []string{"rule", "anchor", "instance"} {
			if _, ok := props[key]; !ok {
				t.Errorf("%s: finding has no %q property", schemaPath, key)
			}
		}
	}
}

func TestAuditSchemaValidatesIdentity(t *testing.T) {
	schema := loadBundledSchema(t, "../../skills/audit-injection/schema.json")
	report := func(identity string) string {
		return `{"findings":[{"id":"F001","title":"Webhook branch name reaches a shell command",
		  "severity":"High","confidence":"high","cwe":"CWE-78","location":"internal/hooks/run.go:88",
		  "reachability":"reachable","quality_tier":"high",
		  "trace":"The webhook branch parameter is concatenated into sh -c.",
		  "boundary":"An authenticated repository webhook supplies the branch name.",
		  "validation":"Static review found no allowlist or argv conversion.",
		  "discovered_via":"source",
		  "rating":"High because the attacker runs commands as the deployment worker."` + identity + `}]}`
	}
	if got := ValidateReportSchema(schema, report(`,"rule":"command-injection","anchor":"branch names reach the shell unquoted","instance":"deploy hook"`)); got != "" {
		t.Fatalf("identity rejected: %s", got)
	}
	if got := ValidateReportSchema(schema, report("")); got != "" {
		t.Fatalf("finding without identity rejected: %s", got)
	}
	for _, bad := range []string{
		`,"rule":"Command Injection"`,
		`,"rule":""`,
		`,"anchor":""`,
		`,"instance":"` + strings.Repeat("x", 121) + `"`,
	} {
		if got := ValidateReportSchema(schema, report(bad)); got == "" {
			t.Errorf("accepted %s", bad)
		}
	}
}
