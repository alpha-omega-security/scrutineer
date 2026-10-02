package worker

import (
	"encoding/json"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

const webAuditFinding = `{"id":"F1","title":"Cross-site account email update","severity":"Medium","confidence":"high","cwe":"CWE-352","location":"server.py:37","reachability":"reachable","quality_tier":"high","trace":"GET /api/email carries the victim's Lax session cookie on a cross-site navigation and writes the supplied email.","boundary":"An attacker-controlled site changes a victim's authenticated account.","validation":"Static trace finds no token or origin check on this GET handler.","discovered_via":"source","rating":"Medium: requires a signed-in victim navigating to an attacker-controlled link.","references":[{"url":"https://github.com/OWASP/ASVS/tree/v5.0.0","summary":"ASVS 5.0.0 browser-origin guidance","tags":"asvs"}]}`

func webAuditReport(findings string) string {
	return `{"review_status":"reviewed","findings":[` + findings + `],"notes":"Static source review only.","scope":"Account HTTP application.","source_sink_inventory":["server.py:37 accepts cookie identity and writes an email."],"negative_results":["server.py:41 rejects display-name POSTs without matching Origin and session token."],"unverified_assumptions":["Deployment TLS was not available in the checkout."],"design_properties":["server.py:25 uses browser session cookies."]}`
}

func TestWebAuditSchemaAndIngestion(t *testing.T) {
	schema := loadBundledSchema(t, "../../skills/audit-web/schema.json")
	report := webAuditReport(webAuditFinding)
	if detail := ValidateReportSchema(schema, report); detail != "" {
		t.Fatal(detail)
	}
	repo, gdb := runSkillWithReport(t, "findings", report)
	var findings []db.Finding
	if err := gdb.Where("repository_id = ?", repo.ID).Find(&findings).Error; err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].CWE != "CWE-352" {
		t.Fatalf("findings=%+v", findings)
	}
	var refs []db.FindingReference
	if err := gdb.Where("finding_id = ?", findings[0].ID).Find(&refs).Error; err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].Summary != "ASVS 5.0.0 browser-origin guidance" {
		t.Fatalf("references=%+v", refs)
	}
}

func TestWebAuditSchemaRejectsInvalidReports(t *testing.T) {
	checkModeSchemaRejectsInvalid(t, modeSchemaCase{
		schemaPath: "../../skills/audit-web/schema.json", report: webAuditReport, finding: webAuditFinding,
		reference:    `{"url":"https://github.com/OWASP/ASVS/tree/v5.0.0","summary":"ASVS 5.0.0 browser-origin guidance","tags":"asvs"}`,
		nonMatchNote: "client.py only sends HTTP requests.",
	})
}

// modeSchemaCase parameterises the invalid-report table shared by the
// focused audit modes, which all use the same envelope.
type modeSchemaCase struct {
	schemaPath, finding, reference, nonMatchNote string
	report                                       func(findings string) string
}

func checkModeSchemaRejectsInvalid(t *testing.T, mc modeSchemaCase) {
	t.Helper()
	schema := loadBundledSchema(t, mc.schemaPath)
	for _, tc := range []struct {
		name, report string
		valid        bool
	}{
		{"empty reviewed", mc.report(""), true},
		{"nonmatch", `{"review_status":"not-applicable","findings":[],"notes":"` + mc.nonMatchNote + `"}`, true},
		{"nonmatch findings", strings.Replace(mc.report(mc.finding), `"reviewed"`, `"not-applicable"`, 1), false},
		{"missing evidence", `{"review_status":"reviewed","findings":[],"notes":"Done"}`, false},
		{"missing status", `{"findings":[],"notes":"Done"}`, false},
		{"unreachable", mc.report(strings.Replace(mc.finding, `"reachable"`, `"harness_only"`, 1)), false},
		{"low quality", mc.report(strings.Replace(mc.finding, `"quality_tier":"high"`, `"quality_tier":"low"`, 1)), false},
		{"string references", mc.report(strings.Replace(mc.finding, mc.reference, `"https://example.test"`, 1)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if detail := ValidateReportSchema(schema, tc.report); (detail == "") != tc.valid {
				t.Fatalf("validation=%q want valid=%t", detail, tc.valid)
			}
		})
	}
	for _, field := range []string{"scope", "source_sink_inventory", "negative_results", "unverified_assumptions", "design_properties"} {
		t.Run("missing "+field, func(t *testing.T) {
			var report map[string]any
			if err := json.Unmarshal([]byte(mc.report("")), &report); err != nil {
				t.Fatal(err)
			}
			delete(report, field)
			raw, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			if detail := ValidateReportSchema(schema, string(raw)); detail == "" {
				t.Fatal("accepted missing evidence category")
			}
		})
	}
}
