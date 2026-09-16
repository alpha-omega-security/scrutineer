package worker

import (
	"strings"
	"testing"
)

// TestComplianceSchema pins the compliance report contract: the wrapper's
// PENDING_LLM entry with its consultation and the error envelope are
// accepted, and a level outside 1-3, an unknown status or a missing source
// are rejected at the offending pointer.
func TestComplianceSchema(t *testing.T) {
	schema := loadBundledSchema(t, "../../skills/compliance/schema.json")
	for _, report := range []string{
		`{"schema_version":1,"framework":"openssf-baseline","total":4,"controls":[
		  {"id":"OSPS-AC-01.01","level":1,"status":"PASS","details":"MFA required at the org level","source":"darnit"},
		  {"id":"OSPS-DO-01.01","level":1,"status":"FAIL","details":"README.md has no usage section","source":"agent"},
		  {"id":"OSPS-GV-01.01","level":2,"status":"PENDING_LLM","details":"LLM consultation required","source":"darnit",
		    "consultation":{"prompt":"Does GOVERNANCE.md name the roles?","analysis_hints":["look for GOVERNANCE.md"],"gathered_evidence":{"files":["GOVERNANCE.md"]}}},
		  {"id":"OSPS-LE-02.01","level":1,"status":"NA","details":"Excluded via .baseline.toml","source":"darnit"}]}`,
		`{"schema_version":1,"framework":"openssf-baseline","total":0,"controls":[],"error":"darnit not found on PATH"}`,
	} {
		if got := ValidateReportSchema(schema, report); got != "" {
			t.Errorf("rejected sample: %s\nreport: %s", got, report)
		}
	}
	for _, tc := range []struct{ report, want string }{
		{`{"schema_version":1,"framework":"openssf-baseline","total":1,"controls":[{"id":"OSPS-AC-01.01","level":4,"status":"PASS","details":"","source":"darnit"}]}`, "/controls/0/level"},
		{`{"schema_version":1,"framework":"openssf-baseline","total":1,"controls":[{"id":"OSPS-AC-01.01","level":1,"status":"SKIP","details":"","source":"darnit"}]}`, "/controls/0/status"},
		{`{"schema_version":1,"framework":"openssf-baseline","total":1,"controls":[{"id":"OSPS-AC-01.01","level":1,"status":"PASS","details":""}]}`, "/controls/0"},
		{`{"schema_version":2,"framework":"openssf-baseline","total":0,"controls":[]}`, "/schema_version"},
		{`{"schema_version":1,"framework":"openssf-baseline","controls":[]}`, "total"},
	} {
		got := ValidateReportSchema(schema, tc.report)
		if got == "" || !strings.Contains(got, tc.want) {
			t.Errorf("report %s: validation = %q, want a failure at %q", tc.report, got, tc.want)
		}
	}
}
