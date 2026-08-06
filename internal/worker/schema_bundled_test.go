package worker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/skills"
)

const sharedAuditSchemaRef = "../_shared/audit-findings.schema.json"

func TestAuditFindingSchemasReferenceSharedContract(t *testing.T) {
	paths := []string{
		"../../skills/audit-injection/schema.json",
		"../../skills/audit-exfil/schema.json",
		"../../skills/audit-authz/schema.json",
		"../../skills/audit-pii/schema.json",
		"../../skills/audit-memory/schema.json",
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var wrapper map[string]any
		if err := json.Unmarshal(raw, &wrapper); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		if got := wrapper["$ref"]; got != sharedAuditSchemaRef {
			t.Errorf("%s $ref = %v, want %q", path, got, sharedAuditSchemaRef)
		}
		for _, keyword := range []string{"type", "properties", "$defs"} {
			if _, ok := wrapper[keyword]; ok {
				t.Errorf("%s defines validation keyword %q instead of using the shared contract", path, keyword)
			}
		}
	}
}

func loadBundledSchema(t *testing.T, schemaPath string) string {
	t.Helper()
	parsed, err := skills.ParseFile(filepath.Join(filepath.Dir(schemaPath), "SKILL.md"))
	if err != nil {
		t.Fatalf("load schema for %s: %v", schemaPath, err)
	}
	return parsed.SchemaJSON
}

// TestBundledSchemas_compileAndAcceptSamples checks that bundled schemas
// compile and accept representative reports. Some samples are external-tool
// output, so the point is catching schema mistakes rather than proving each
// upstream format's conformance.
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
			depEnvelope(`[]`, ""),
		},
		{
			"../../skills/dependencies/schema.json",
			depEnvelope(`[{"name":"x","ecosystem":"npm","type":"runtime"}]`, cdxEnvelopeFixture),
		},
		{
			"../../skills/dependencies/schema.json",
			`{"schema_version":1,"analyses":{
				"inventory":{"status":"error","error":"git-pkgs: exit 1"},
				"sbom":{"status":"error","error":"git-pkgs: exit 1"}}}`,
		},
		{
			// The SKILL.md fallback shape for a wholesale script failure:
			// analyses is present but empty. Sections are not required so
			// schema validation still surfaces the top-level error.
			"../../skills/dependencies/schema.json",
			`{"schema_version":1,"analyses":{},"error":"git-pkgs init failed"}`,
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
			"../../skills/recon/schema.json",
			`{"focus_areas":[{"name":"XML parser",
			  "surface":"External XML documents supplied by library callers.",
			  "paths":["lib/xmlparse.c","lib/xmlrole.c"]}],
			  "notes":["Examples and vendored code were excluded."]}`,
		},
		{
			"../../skills/security-deep-dive/schema.json",
			`{"repository":"https://github.com/o/r","commit":"abc1234","spec_version":13,
			  "model":"claude","date":"2026-07-16","languages":["C"],
			  "boundaries":[{"actor":"library caller","trusted":"no","controls":"XML bytes","source":"README.md:1"},
			    {"actor":"CLI operator","trusted":"conditional","controls":"command-line input","source":"README.md:2"}],
			  "method":{"scope":"./src","grep_patterns":[{"class":"Memory safety","primitive":"realloc",
			    "command":"grep -rn 'realloc' ./src","hit_count":1,"inventory_sinks":["S1","S2"],"excluded_hits":[]}],
			    "inventory_count":2,"ruled_out_count":2,"unresolved_count":0},
			  "inventory":[{"id":"S1","location":"lib/parser.c:42","class":"Memory safety",
			    "boundary":"library caller","primitive":"realloc","consumes":"XML length"},
			    {"id":"S2","location":"lib/parser.c:42","class":"Memory safety",
			    "boundary":"CLI operator","primitive":"realloc","consumes":"command-line length"}],
			  "findings":[],"ruled_out":[{"sinks":["S1","S2"],"step":2,"reason":"Bounded by documented caller invariants."}]}`,
		},
		{
			"../../skills/forensics/schema.json",
			`{"repository":"https://github.com/o/r","scope":"finding","finding_id":12,
			  "head":"0123456789abcdef0123456789abcdef01234567",
			  "window":{"from":"2026-01-10T00:00:00Z","to":"2026-01-17T00:00:00Z"},
			  "timeline":[{"time":"2026-01-12T14:03:00Z","source":"github","kind":"push",
			    "summary":"main changed","evidence":"public event 1","url":"https://api.github.com/repos/o/r/events"}],
			  "artifacts":[{"kind":"commit","identifier":"0123456789abcdef0123456789abcdef01234567",
			    "summary":"HEAD","url":null}],"indicators":[],
			  "assessment":{"status":"inconclusive","summary":"History is incomplete."},
			  "gaps":["The clone is shallow."],"notes":[],"error":null}`,
		},
		{
			"../../skills/forensics/schema.json",
			`{"error":"repository URL is unavailable"}`,
		},
		{
			"../../skills/audit-injection/schema.json",
			`{"findings":[{"id":"F001","title":"Webhook branch name reaches a shell command",
			  "severity":"High","confidence":"high","cwe":"CWE-78","location":"internal/hooks/run.go:88",
			  "reachability":"reachable","quality_tier":"high",
			  "trace":"The webhook branch parameter is concatenated into sh -c before the deployment command runs.",
			  "boundary":"An authenticated repository webhook supplies the branch name.",
			  "validation":"Static review confirmed the shell wrapper receives one command string and found no allowlist or argv conversion.",
			  "discovered_via":"source",
			  "rating":"High because an attacker controlling the webhook value can execute commands as the deployment worker.",
			  "references":[{"url":"https://github.com/owner/repo/security/advisories/GHSA-xxxx-yyyy-zzzz",
			    "summary":"Related advisory","tags":"advisory"}]}]}`,
		},
		{
			"../../skills/audit-injection/schema.json",
			`{"findings":[]}`,
		},
		{
			"../../skills/audit-exfil/schema.json",
			`{"findings":[{"id":"F001","title":"Webhook URL fetch can reach internal metadata service",
			  "severity":"High","confidence":"high","cwe":"CWE-918","location":"internal/webhooks/route:v2/fetch.go:91",
			  "reachability":"reachable","quality_tier":"high",
			  "trace":"The webhook endpoint stores a caller-provided callback URL and later passes it to http.Client.Do.",
			  "boundary":"An authenticated project member controls the callback URL, while the worker can reach internal services.",
			  "validation":"Static review confirmed the request follows redirects and found no host, scheme, or private-IP allowlist.",
			  "discovered_via":"source",
			  "rating":"High because a project member can make the server disclose cloud metadata or internal service responses.",
			  "references":[{"url":"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
			    "summary":"SSRF overview","tags":"ssrf"}]}]}`,
		},
		{
			"../../skills/audit-exfil/schema.json",
			`{"findings":[]}`,
		},
		{
			"../../skills/audit-authz/schema.json",
			`{"findings":[{"id":"F001","title":"Invoice lookup omits tenant ownership",
			  "severity":"High","confidence":"high","cwe":"CWE-639","location":"internal/invoices/show.go:74",
			  "reachability":"reachable","quality_tier":"high",
			  "trace":"The authenticated endpoint passes the caller-controlled invoice ID to a global lookup and returns the row.",
			  "boundary":"A tenant member may supply another tenant's invoice ID.",
			  "validation":"Static review resolved the route middleware and repository helper, then confirmed neither checks invoice tenant membership.",
			  "discovered_via":"source",
			  "rating":"High because any authenticated tenant member can read another tenant's billing record.",
			  "references":[{"url":"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
			    "summary":"OWASP API1:2023 Broken Object Level Authorization","tags":"authorization,idor"}]}]}`,
		},
		{
			"../../skills/audit-authz/schema.json",
			`{"findings":[]}`,
		},
		{
			"../../skills/audit-pii/schema.json",
			`{"findings":[{"id":"F001","title":"Customer email is written to an analytics event",
			  "severity":"Medium","confidence":"high","cwe":"CWE-359","location":"internal/analytics/signup.go:64",
			  "reachability":"reachable","quality_tier":"high",
			  "trace":"The signup handler passes the account email to the analytics properties map without redaction.",
			  "boundary":"A user email leaves the application database and is retained by the third-party analytics provider.",
			  "validation":"Static review confirmed this is a runtime account value, not an example literal, and found no hashing or analytics allowlist.",
			  "discovered_via":"source",
			  "rating":"Medium because every signup discloses a personal identifier to a durable third-party sink.",
			  "references":[{"url":"https://cwe.mitre.org/data/definitions/359.html",
			    "summary":"CWE-359","tags":"privacy,pii"}]}]}`,
		},
		{
			"../../skills/audit-pii/schema.json",
			`{"findings":[]}`,
		},
		{
			"../../skills/audit-memory/schema.json",
			`{"findings":[{"id":"F001","title":"Overflowed growth leaves parser buffer undersized",
			  "severity":"High","confidence":"high","cwe":"CWE-787","location":"lib/xmlparse.c:418",
			  "reachability":"reachable","quality_tier":"high",
			  "trace":"A library caller's XML token length reaches bytes * 2 in size_t; the wrapped allocation is smaller after overflow and the decoder writes the full token.",
			  "boundary":"The public parser API accepts untrusted XML bytes and reaches the first-party token buffer in the library build.",
			  "validation":"The literal realloc inventory hit was traced through the local wrapper; neither the wrapper nor callers check multiplication overflow before allocation.",
			  "discovered_via":"source",
			  "rating":"High because a crafted document can cause an out-of-bounds write in applications embedding the parser.",
			  "references":[{"url":"https://cwe.mitre.org/data/definitions/787.html",
			    "summary":"CWE-787","tags":"memory-safety,out-of-bounds-write"}]}]}`,
		},
		{
			"../../skills/audit-memory/schema.json",
			`{"findings":[]}`,
		},
		{
			"../../skills/variants/schema.json",
			`{"findings":[{"id":"F1","title":"Variant of finding #42: archive extraction escapes destination",
			  "severity":"High","confidence":"high","cwe":"CWE-22","location":"pkg/archive/legacy.go:88",
			  "reachability":"reachable","quality_tier":"high",
			  "trace":"Caller-provided archive entry names reach filepath.Join before file creation.",
			  "boundary":"The public extraction API accepts caller-provided archives and entry names.",
			  "validation":"Variant analysis of finding #42 used rg for filepath.Join and verified this path has no containment guard.",
			  "prior_art":"Variant analysis of finding #42 (archive extraction traversal).",
			  "discovered_via":"source",
			  "rating":"High impact because a crafted archive can create files outside the destination root."}]}`,
		},
		{
			"../../skills/variants/schema.json",
			`{"findings":[]}`,
		},
		{
			"../../skills/variants/schema.json",
			`{"findings":[{"id":"F2","title":"Variant of finding #42: lower-confidence lead",
			  "severity":"Medium","confidence":"medium","cwe":"CWE-22","location":"pkg/archive/experimental.go:29",
			  "reachability":"reachable","quality_tier":"medium","trace":"Input reaches the legacy extraction helper.",
			  "boundary":"The public extraction API accepts caller-provided archives.",
			  "validation":"Variant analysis of finding #42 identified the candidate.",
			  "prior_art":"Variant analysis of finding #42 (archive extraction traversal).",
			  "discovered_via":"source","rating":"Medium pending further validation."}]}`,
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
		{
			"../../skills/advisory-deep-dive/schema.json",
			`{"audits":[{"advisory_uuid":"GHSA-xxxx-yyyy-zzzz","status":"bypass",
			  "evidence":"Repro fired at HEAD via percent-encoded separators.","finding_ids":["F001"]}],
			  "findings":[{"id":"F001","title":"Bypass of GHSA-xxxx path-traversal fix",
			  "severity":"High","confidence":"medium","cwe":"CWE-22","location":"lib/extract.rb:88",
			  "reachability":"reachable","quality_tier":"high",
			  "trace":"Percent-encoded separators skip the added guard and reach File.open.",
			  "boundary":"The public extract API accepts caller-supplied archive entry names.",
			  "validation":"Repro run against HEAD; the encoded entry escaped the destination root.",
			  "prior_art":"Descends from GHSA-xxxx-yyyy-zzzz.",
			  "rating":"High: the shipped fix blocklists literal ../ but not its encodings.",
			  "references":[{"url":"https://github.com/advisories/GHSA-xxxx-yyyy-zzzz","tags":"advisory"},
			    {"url":"https://github.com/o/r/commit/deadbeef","tags":"patch"}]}]}`,
		},
		{
			"../../skills/advisory-deep-dive/schema.json",
			`{"audits":[{"advisory_uuid":"GHSA-aaaa-bbbb-cccc","status":"fixed",
			  "evidence":"Original repro fails at HEAD; no bypass or sibling survived."}],"findings":[]}`,
		},
		{
			"../../skills/advisory-deep-dive/schema.json",
			`{"audits":[],"findings":[]}`,
		},
	}
	for _, tc := range cases {
		schema := loadBundledSchema(t, tc.schema)
		if got := ValidateReportSchema(schema, tc.report); got != "" {
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
		{"../../skills/dependencies/schema.json", `{"schema_version":1}`, "analyses"},
		{"../../skills/dependencies/schema.json",
			`{"schema_version":1,"analyses":{"inventory":{"status":"maybe"}}}`,
			"/analyses/inventory"},
		{"../../skills/dependencies/schema.json",
			`{"schema_version":1,"analyses":{"inventory":{"status":"ok"},"licenses":{"status":"ok"}}}`,
			"/analyses"},
		{"../../skills/advisories/schema.json",
			`{"advisories":[{"uuid":"u1","severity":"HIGHISH"}]}`,
			"/advisories/0/severity"},
		{"../../skills/public-issue/schema.json",
			`{"upstream":"owner/repo","url":"https://github.com/owner/repo/issues/123"}`, "oneOf"},
		{"../../skills/threat-model/schema.json", `{"spec_version":2}`, "/spec_version"},
		{"../../skills/recon/schema.json", `{"focus_areas":[{"name":"parser","surface":"bytes","paths":[]}],"notes":[]}`, "/focus_areas/0/paths"},
		{"../../skills/security-deep-dive/schema.json",
			`{"repository":"https://github.com/o/r","commit":"abc1234","spec_version":13,
			  "model":"claude","date":"2026-07-16","languages":["C"],"boundaries":[],
			  "inventory":[],"findings":[],"ruled_out":[]}`,
			"method"},
		{"../../skills/forensics/schema.json",
			`{"repository":"https://github.com/o/r","scope":"repository","finding_id":null,"head":null,
			  "window":{"from":null,"to":null},"timeline":[],"artifacts":[],"indicators":[],
			  "assessment":{"status":"maybe","summary":"unknown"},"gaps":[],"notes":[]}`,
			"/assessment/status"},
		{"../../skills/forensics/schema.json",
			`{"error":"repository URL is unavailable","repository":"https://github.com/o/r"}`,
			"oneOf"},
		{"../../skills/audit-injection/schema.json",
			`{"findings":[{"id":"F001","title":"Bad injection confidence","severity":"High",
			  "confidence":"maybe","cwe":"CWE-78","location":"internal/hooks/run.go:88",
			  "reachability":"reachable","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x"}]}`,
			"/findings/0/confidence"},
		{"../../skills/audit-injection/schema.json",
			`{"findings":[{"id":"F001","title":"Bad injection location","severity":"High",
			  "confidence":"high","cwe":"CWE-78","location":"internal/hooks/run.go",
			  "reachability":"reachable","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x"}]}`,
			"/findings/0/location"},
		{"../../skills/audit-injection/schema.json",
			`{"findings":[{"id":"F001","title":"Missing CWE","severity":"High",
			  "confidence":"high","cwe":"","location":"internal/hooks/run.go:88",
			  "reachability":"reachable","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x"}]}`,
			"/findings/0/cwe"},
		{"../../skills/audit-injection/schema.json",
			`{"findings":[{"id":"F001","title":"Zero line number","severity":"High",
			  "confidence":"high","cwe":"CWE-78","location":"internal/hooks/run.go:0",
			  "reachability":"reachable","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x"}]}`,
			"/findings/0/location"},
		{"../../skills/audit-injection/schema.json",
			`{"findings":[{"id":"F001","title":"Leading-zero line number","severity":"High",
			  "confidence":"high","cwe":"CWE-78","location":"internal/hooks/run.go:08",
			  "reachability":"reachable","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x"}]}`,
			"/findings/0/location"},
		{"../../skills/audit-injection/schema.json",
			`{"findings":[{"id":"F001","title":"Wrong provenance","severity":"High",
			  "confidence":"high","cwe":"CWE-78","location":"internal/hooks/run.go:88",
			  "reachability":"reachable","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"documentation","rating":"x"}]}`,
			"/findings/0/discovered_via"},
		{"../../skills/audit-injection/schema.json",
			`{"findings":[{"id":"F001","title":"Missing provenance","severity":"High",
			  "confidence":"high","cwe":"CWE-78","location":"internal/hooks/run.go:88",
			  "reachability":"reachable","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"x","rating":"x"}]}`,
			"/findings/0"},
		{"../../skills/audit-injection/schema.json",
			`{"findings":[{"id":"F001","title":"Harness-only injection","severity":"High",
			  "confidence":"high","cwe":"CWE-78","location":"internal/hooks/run.go:88",
			  "reachability":"harness_only","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x"}]}`,
			"/findings/0/reachability"},
		{"../../skills/audit-injection/schema.json",
			`{"findings":[{"id":"F001","title":"Low-quality injection","severity":"High",
			  "confidence":"high","cwe":"CWE-78","location":"internal/hooks/run.go:88",
			  "reachability":"reachable","quality_tier":"low","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x"}]}`,
			"/findings/0/quality_tier"},
		{"../../skills/audit-injection/schema.json",
			`{"findings":[{"id":"F001","title":"String references","severity":"High",
			  "confidence":"high","cwe":"CWE-78","location":"internal/hooks/run.go:88",
			  "reachability":"reachable","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x",
			  "references":["https://example.com/advisory"]}]}`,
			"/findings/0/references/0"},
		{"../../skills/audit-exfil/schema.json",
			`{"findings":[{"id":"F001","title":"Harness-only SSRF","severity":"High",
			  "confidence":"high","cwe":"CWE-918","location":"internal/webhooks/fetch.go:91",
			  "reachability":"harness_only","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x"}]}`,
			"/findings/0/reachability"},
		{"../../skills/audit-exfil/schema.json",
			`{"findings":[{"id":"F001","title":"Low-quality file read","severity":"High",
			  "confidence":"high","cwe":"CWE-22","location":"internal/files/read.go:24",
			  "reachability":"reachable","quality_tier":"low","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x"}]}`,
			"/findings/0/quality_tier"},
		{"../../skills/audit-exfil/schema.json",
			`{"findings":[{"id":"F001","title":"String references","severity":"High",
			  "confidence":"high","cwe":"CWE-918","location":"internal/webhooks/fetch.go:91",
			  "reachability":"reachable","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x",
			  "references":["https://example.com/advisory"]}]}`,
			"/findings/0/references/0"},
		{"../../skills/audit-authz/schema.json",
			`{"findings":[{"id":"F001","title":"Harness-only IDOR","severity":"High",
			  "confidence":"high","cwe":"CWE-639","location":"internal/invoices/show.go:74",
			  "reachability":"harness_only","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x"}]}`,
			"/findings/0/reachability"},
		{"../../skills/audit-authz/schema.json",
			`{"findings":[{"id":"F001","title":"Low-quality tenant bypass","severity":"High",
			  "confidence":"high","cwe":"CWE-863","location":"internal/invoices/show.go:74",
			  "reachability":"reachable","quality_tier":"low","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x"}]}`,
			"/findings/0/quality_tier"},
		{"../../skills/audit-authz/schema.json",
			`{"findings":[{"id":"F001","title":"Wrong provenance","severity":"High",
			  "confidence":"high","cwe":"CWE-862","location":"internal/admin/delete.go:51",
			  "reachability":"reachable","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"documentation","rating":"x"}]}`,
			"/findings/0/discovered_via"},
		{"../../skills/audit-authz/schema.json",
			`{"findings":[{"id":"F001","title":"String references","severity":"High",
			  "confidence":"high","cwe":"CWE-639","location":"internal/invoices/show.go:74",
			  "reachability":"reachable","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x",
			  "references":["https://example.com/advisory"]}]}`,
			"/findings/0/references/0"},
		{"../../skills/audit-authz/schema.json",
			`{"findings":[{"id":"F001","title":"Invalid confidence","severity":"High",
			  "confidence":"certain","cwe":"CWE-639","location":"internal/invoices/show.go:74",
			  "reachability":"reachable","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x"}]}`,
			"/findings/0/confidence"},
		{"../../skills/audit-authz/schema.json",
			`{"findings":[{"id":"F001","title":"Location without line","severity":"High",
			  "confidence":"high","cwe":"CWE-639","location":"internal/invoices/show.go",
			  "reachability":"reachable","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x"}]}`,
			"/findings/0/location"},
		{"../../skills/audit-pii/schema.json",
			`{"findings":[{"id":"F001","title":"Low-quality PII resemblance","severity":"Medium",
			  "confidence":"high","cwe":"CWE-359","location":"fixtures/profile.json:12",
			  "reachability":"reachable","quality_tier":"low","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x"}]}`,
			"/findings/0/quality_tier"},
		{"../../skills/audit-pii/schema.json",
			`{"findings":[{"id":"F001","title":"Non-reachable PII candidate","severity":"Medium",
			  "confidence":"high","cwe":"CWE-359","location":"fixtures/profile.json:12",
			  "reachability":"unclear","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x"}]}`,
			"/findings/0/reachability"},
		{"../../skills/audit-memory/schema.json",
			`{"findings":[{"id":"F001","title":"Unproven resize candidate","severity":"High",
			  "confidence":"high","cwe":"CWE-787","location":"lib/parser.c:88",
			  "reachability":"harness_only","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x"}]}`,
			"/findings/0/reachability"},
		{"../../skills/audit-memory/schema.json",
			`{"findings":[{"id":"F001","title":"Low-quality lifetime candidate","severity":"High",
			  "confidence":"high","cwe":"CWE-416","location":"lib/callback.c:119",
			  "reachability":"reachable","quality_tier":"low","trace":"x","boundary":"x",
			  "validation":"x","discovered_via":"source","rating":"x"}]}`,
			"/findings/0/quality_tier"},
		{"../../skills/variants/schema.json",
			`{"findings":[{"id":"F1","title":"Variant of finding #42: weak confidence","severity":"High",
			  "confidence":"maybe","cwe":"CWE-22","location":"pkg/archive/legacy.go:88",
			  "reachability":"reachable","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"Variant analysis of finding #42 checked the candidate.","prior_art":"Variant analysis of finding #42.",
			  "discovered_via":"source","rating":"x"}]}`,
			"/findings/0/confidence"},
		{"../../skills/variants/schema.json",
			`{"findings":[{"id":"F1","title":"Variant of finding #42: unclear reachability","severity":"High",
			  "confidence":"high","cwe":"CWE-22","location":"pkg/archive/legacy.go:88",
			  "reachability":"unclear","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"Variant analysis of finding #42 checked the candidate.","prior_art":"Variant analysis of finding #42.",
			  "discovered_via":"source","rating":"x"}]}`,
			"/findings/0/reachability"},
		{"../../skills/variants/schema.json",
			`{"findings":[{"id":"F1","title":"Variant of finding #42: missing source link","severity":"High",
			  "confidence":"high","cwe":"CWE-22","location":"pkg/archive/legacy.go:88",
			  "reachability":"reachable","quality_tier":"high","trace":"x","boundary":"x",
			  "validation":"checked","prior_art":"Related archive extraction review.",
			  "discovered_via":"source","rating":"x"}]}`,
			"/findings/0/prior_art"},
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
		{"../../skills/advisory-deep-dive/schema.json",
			`{"audits":[],"findings":[{"id":"F001","title":"String references, not objects","severity":"High",
			  "confidence":"high","cwe":"CWE-22","location":"lib/extract.rb:88","reachability":"reachable",
			  "quality_tier":"high","trace":"x","boundary":"x","validation":"x","rating":"x",
			  "references":["https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"]}]}`,
			"/findings/0/references/0"},
		{"../../skills/advisory-deep-dive/schema.json",
			`{"audits":[{"advisory_uuid":"u1","status":"held","evidence":"x"}],"findings":[]}`,
			"/audits/0/status"},
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
		schema := loadBundledSchema(t, tc.schema)
		got := ValidateReportSchema(schema, tc.report)
		if got == "" {
			t.Errorf("%s accepted bad report %s", tc.schema, tc.report)
			continue
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: error %q does not mention %q", tc.schema, got, tc.want)
		}
	}
}
