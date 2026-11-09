package worker

import "testing"

const mobileAuditFinding = `{"id":"F1","title":"Deep link loads an attacker URL into a WebView that exposes the session token","severity":"High","confidence":"high","cwe":"CWE-749","location":"app/src/main/java/com/example/notes/DeepLinkActivity.kt:23","reachability":"reachable","quality_tier":"high","trace":"The exported DeepLinkActivity reads the url query parameter of a notes://open link and passes it to webView.loadUrl. The same WebView has JavaScript enabled and registers SessionBridge as Session, whose token method returns the stored session token.","boundary":"Any app or web page that can open a notes link makes the app load a page it controls with access to the user's session token.","validation":"Static trace finds no scheme, host or origin check between the query parameter and loadUrl. The exported activity requires no permission.","discovered_via":"source","rating":"High: a malicious link lets the page read the session token and act as the user.","references":[{"url":"https://cwe.mitre.org/data/definitions/749.html","summary":"CWE-749 exposed dangerous method or function","tags":"cwe"}]}`

func mobileAuditReport(findings string) string {
	return `{"review_status":"reviewed","findings":[` + findings + `],"notes":"Static source review only.","scope":"Android notes app.","source_sink_inventory":["app/src/main/java/com/example/notes/DeepLinkActivity.kt:23 loads a URL taken from an exported deep link."],"negative_results":["app/src/main/java/com/example/notes/HelpActivity.kt:16 loads only https URLs whose host equals the help host."],"unverified_assumptions":["Server-side token revocation was not available in the checkout."],"design_properties":["app/src/main/java/com/example/notes/TokenStore.kt:8 keeps the session token in EncryptedSharedPreferences."]}`
}

func TestMobileAuditSchemaAndIngestion(t *testing.T) {
	report := mobileAuditReport(mobileAuditFinding)
	if detail := ValidateReportSchema(loadBundledSchema(t, "../../skills/audit-mobile/schema.json"), report); detail != "" {
		t.Fatal(detail)
	}
	findings, refs := ingestModeAuditReport(t, report)
	if len(findings) != 1 || findings[0].CWE != "CWE-749" || findings[0].Location != "app/src/main/java/com/example/notes/DeepLinkActivity.kt:23" {
		t.Fatalf("findings=%+v", findings)
	}
	if len(refs) != 1 || refs[0].URL != "https://cwe.mitre.org/data/definitions/749.html" {
		t.Fatalf("references=%+v", refs)
	}
}

func TestMobileAuditSchemaRejectsInvalidReports(t *testing.T) {
	checkModeSchemaRejectsInvalid(t, modeSchemaCase{
		schemaPath: "../../skills/audit-mobile/schema.json", report: mobileAuditReport, finding: mobileAuditFinding,
		reference:    `{"url":"https://cwe.mitre.org/data/definitions/749.html","summary":"CWE-749 exposed dangerous method or function","tags":"cwe"}`,
		nonMatchNote: "pushclient only builds request dictionaries and has no app shell.",
	})
}
