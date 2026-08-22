package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/ingest"
)

func capFindings(rule string, n int) []ingest.Finding {
	out := make([]ingest.Finding, 0, n)
	for i := range n {
		out = append(out, ingest.Finding{
			RuleID:   rule,
			Title:    "rule " + rule,
			Severity: "High",
			Location: fmt.Sprintf("%s/f%d.go:%d", rule, i, i+1),
		})
	}
	return out
}

func TestCapScannerResult_underCapsKeepsEverything(t *testing.T) {
	res := ingest.Result{Tool: "CodeQL", Findings: capFindings("js/xss", 3)}
	bounded, caps := capScannerResult(res)
	if len(bounded.Findings) != 3 {
		t.Fatalf("kept %d findings, want 3", len(bounded.Findings))
	}
	want := importCapStats{Received: 3, Accepted: 3}
	if caps != want {
		t.Errorf("caps = %+v, want %+v", caps, want)
	}
	if caps.truncated() {
		t.Error("truncated() = true for an untouched result")
	}
}

func TestCapScannerResult_exactlyPerRuleCapKeepsEverything(t *testing.T) {
	res := ingest.Result{Tool: "CodeQL", Findings: capFindings("js/xss", importPerRuleCap)}
	bounded, caps := capScannerResult(res)
	if len(bounded.Findings) != importPerRuleCap {
		t.Fatalf("kept %d findings, want %d", len(bounded.Findings), importPerRuleCap)
	}
	if caps.DroppedPerRule != 0 || caps.DroppedTotal != 0 {
		t.Errorf("caps = %+v, want nothing dropped at exactly the cap", caps)
	}
}

func TestCapScannerResult_oneOverPerRuleCapDropsTheOverflow(t *testing.T) {
	res := ingest.Result{Tool: "CodeQL", Findings: capFindings("js/xss", importPerRuleCap+1)}
	bounded, caps := capScannerResult(res)
	if len(bounded.Findings) != importPerRuleCap {
		t.Fatalf("kept %d findings, want %d", len(bounded.Findings), importPerRuleCap)
	}
	want := importCapStats{Received: importPerRuleCap + 1, Accepted: importPerRuleCap, DroppedPerRule: 1}
	if caps != want {
		t.Errorf("caps = %+v, want %+v", caps, want)
	}
	// The survivors are the first five in input order, not an arbitrary five.
	for i, f := range bounded.Findings {
		if want := fmt.Sprintf("js/xss/f%d.go:%d", i, i+1); f.Location != want {
			t.Errorf("finding %d location = %q, want %q", i, f.Location, want)
		}
	}
}

func TestCapScannerResult_perRuleCapIsPerRule(t *testing.T) {
	var findings []ingest.Finding
	findings = append(findings, capFindings("js/xss", importPerRuleCap+2)...)
	findings = append(findings, capFindings("js/sql-injection", 2)...)
	bounded, caps := capScannerResult(ingest.Result{Tool: "CodeQL", Findings: findings})
	if len(bounded.Findings) != importPerRuleCap+2 {
		t.Fatalf("kept %d findings, want %d", len(bounded.Findings), importPerRuleCap+2)
	}
	if caps.DroppedPerRule != 2 {
		t.Errorf("DroppedPerRule = %d, want 2", caps.DroppedPerRule)
	}
	// A quiet rule keeps all of its hits however loud its neighbour was.
	quiet := 0
	for _, f := range bounded.Findings {
		if f.RuleID == "js/sql-injection" {
			quiet++
		}
	}
	if quiet != 2 {
		t.Errorf("kept %d findings for the quiet rule, want 2", quiet)
	}
}

func TestCapScannerResult_totalCapBoundsDistinctRules(t *testing.T) {
	var findings []ingest.Finding
	for i := range importResultCap + 10 {
		findings = append(findings, capFindings(fmt.Sprintf("rule-%02d", i), 1)...)
	}
	bounded, caps := capScannerResult(ingest.Result{Tool: "Semgrep", Findings: findings})
	if len(bounded.Findings) != importResultCap {
		t.Fatalf("kept %d findings, want %d", len(bounded.Findings), importResultCap)
	}
	want := importCapStats{Received: importResultCap + 10, Accepted: importResultCap, DroppedTotal: 10}
	if caps != want {
		t.Errorf("caps = %+v, want %+v", caps, want)
	}
	first, last := fmt.Sprintf("rule-%02d", 0), fmt.Sprintf("rule-%02d", importResultCap-1)
	if bounded.Findings[0].RuleID != first || bounded.Findings[importResultCap-1].RuleID != last {
		t.Errorf("kept %q..%q, want %q..%q, the first %d rules in input order",
			bounded.Findings[0].RuleID, bounded.Findings[importResultCap-1].RuleID, first, last, importResultCap)
	}
}

func TestCapScannerResult_bothCapsAttributeEachDropOnce(t *testing.T) {
	// Twenty rules firing ten times each: the per-rule cap takes five from
	// every rule, and the total cap closes the door after the tenth rule.
	const rules, hits = 20, 10
	var findings []ingest.Finding
	for i := range rules {
		findings = append(findings, capFindings(fmt.Sprintf("rule-%02d", i), hits)...)
	}
	bounded, caps := capScannerResult(ingest.Result{Tool: "Semgrep", Findings: findings})
	if len(bounded.Findings) != importResultCap {
		t.Fatalf("kept %d findings, want %d", len(bounded.Findings), importResultCap)
	}
	if caps.Received != rules*hits || caps.Accepted != importResultCap {
		t.Errorf("caps = %+v, want received %d accepted %d", caps, rules*hits, importResultCap)
	}
	if got := caps.DroppedPerRule + caps.DroppedTotal; got != caps.Received-caps.Accepted {
		t.Errorf("dropped counts sum to %d, want %d (each drop attributed exactly once)",
			got, caps.Received-caps.Accepted)
	}
	// Everything kept comes from the first ten rules, five hits apiece.
	for i, f := range bounded.Findings {
		if want := fmt.Sprintf("rule-%02d", i/importPerRuleCap); f.RuleID != want {
			t.Fatalf("finding %d from rule %q, want %q", i, f.RuleID, want)
		}
	}
}

func TestCapScannerResult_missingRuleIDGroupsByTitle(t *testing.T) {
	var findings []ingest.Finding
	for i := range importPerRuleCap + 3 {
		findings = append(findings, ingest.Finding{
			Title:    "Hardcoded credential",
			Location: fmt.Sprintf("src/f%d.go:1", i),
		})
	}
	findings = append(findings, ingest.Finding{Title: "Path traversal", Location: "src/dl.go:9"})
	bounded, caps := capScannerResult(ingest.Result{Tool: "bandit", Findings: findings})
	if len(bounded.Findings) != importPerRuleCap+1 {
		t.Fatalf("kept %d findings, want %d", len(bounded.Findings), importPerRuleCap+1)
	}
	if caps.DroppedPerRule != 3 {
		t.Errorf("DroppedPerRule = %d, want 3", caps.DroppedPerRule)
	}
	if last := bounded.Findings[len(bounded.Findings)-1]; last.Title != "Path traversal" {
		t.Errorf("last kept finding = %q, want the distinctly-titled one", last.Title)
	}
}

// A code-scanning CSV export puts the per-alert Finding URL in RuleID, so every
// row carries a distinct id for the same underlying rule. Keying on it straight
// would leave the per-rule cap inert for that whole format.
func TestCapScannerResult_perAlertURLRuleIDGroupsByTitle(t *testing.T) {
	var findings []ingest.Finding
	for i := range importPerRuleCap + 3 {
		findings = append(findings, ingest.Finding{
			RuleID:   fmt.Sprintf("https://github.com/example/widget/security/code-scanning/%d", i),
			Title:    "Hardcoded credential",
			Location: fmt.Sprintf("src/f%d.go:1", i),
		})
	}
	bounded, caps := capScannerResult(ingest.Result{Tool: "github.com", Findings: findings})
	if len(bounded.Findings) != importPerRuleCap {
		t.Fatalf("kept %d findings, want %d", len(bounded.Findings), importPerRuleCap)
	}
	if caps.DroppedPerRule != 3 {
		t.Errorf("DroppedPerRule = %d, want 3", caps.DroppedPerRule)
	}
}

// A code-scanning CSV row carries a Finding URL but can leave both the Name
// and Category columns blank, which is the one input shape that reaches the
// cap with a URL rule id and no title. Keying those on the empty string would
// put unrelated alerts in one bucket the per-rule cap closes at five, so they
// fall back to the URL: unique per alert, therefore inert for the per-rule cap,
// leaving the per-result cap as the only bound.
func TestCapScannerResult_blankTitleKeepsAlertsApart(t *testing.T) {
	var findings []ingest.Finding
	for i := range importPerRuleCap + 3 {
		findings = append(findings, ingest.Finding{
			RuleID:   fmt.Sprintf("https://github.com/example/widget/security/code-scanning/%d", i),
			Location: fmt.Sprintf("src/f%d.go:1", i),
		})
	}
	bounded, caps := capScannerResult(ingest.Result{Tool: "github.com", Findings: findings})
	if len(bounded.Findings) != importPerRuleCap+3 {
		t.Fatalf("kept %d findings, want all %d", len(bounded.Findings), importPerRuleCap+3)
	}
	if caps.DroppedPerRule != 0 || caps.DroppedTotal != 0 {
		t.Errorf("caps = %+v, want no drops for distinct alerts", caps)
	}
}

// Two findings carrying neither a rule id nor a title have nothing left to
// group on, so they share the empty key and the per-rule cap applies. That is
// the only case where the key is empty.
func TestCapScannerResult_noIdentifierAtAllSharesOneBucket(t *testing.T) {
	var findings []ingest.Finding
	for i := range importPerRuleCap + 2 {
		findings = append(findings, ingest.Finding{Location: fmt.Sprintf("src/f%d.go:1", i)})
	}
	bounded, caps := capScannerResult(ingest.Result{Tool: "github.com", Findings: findings})
	if len(bounded.Findings) != importPerRuleCap {
		t.Fatalf("kept %d findings, want %d", len(bounded.Findings), importPerRuleCap)
	}
	if caps.DroppedPerRule != 2 {
		t.Errorf("DroppedPerRule = %d, want 2", caps.DroppedPerRule)
	}
}

// A rule id that is not a URL still wins over the title, so two rules sharing a
// title keep their own budgets.
func TestCapScannerResult_ruleIDWinsOverSharedTitle(t *testing.T) {
	var findings []ingest.Finding
	for _, rule := range []string{"js/xss", "py/xss"} {
		for i := range importPerRuleCap {
			findings = append(findings, ingest.Finding{
				RuleID:   rule,
				Title:    "Cross-site scripting",
				Location: fmt.Sprintf("src/%s-%d.go:1", rule, i),
			})
		}
	}
	bounded, caps := capScannerResult(ingest.Result{Tool: "codeql", Findings: findings})
	if len(bounded.Findings) != 2*importPerRuleCap {
		t.Fatalf("kept %d findings, want %d", len(bounded.Findings), 2*importPerRuleCap)
	}
	if caps.DroppedPerRule != 0 {
		t.Errorf("DroppedPerRule = %d, want 0", caps.DroppedPerRule)
	}
}

// sarifHit is one synthetic SARIF result: which rule fired and where.
type sarifHit struct {
	rule     string
	location string
	line     int
}

// sarifRun renders hits as one SARIF run object, declaring a rule for every
// distinct rule id so the parser resolves titles the way a real scanner
// report does.
func sarifRun(repoURL string, hits []sarifHit) map[string]any {
	declared := map[string]bool{}
	rules := []any{}
	results := []any{}
	for _, h := range hits {
		if !declared[h.rule] {
			declared[h.rule] = true
			rules = append(rules, map[string]any{
				"id":               h.rule,
				"shortDescription": map[string]any{"text": "title for " + h.rule},
				"properties": map[string]any{
					"tags":              []any{"security", "external/cwe/cwe-079"},
					"security-severity": "7.5",
					"precision":         "high",
				},
			})
		}
		results = append(results, map[string]any{
			"ruleId":  h.rule,
			"level":   "error",
			"message": map[string]any{"text": "hit in " + h.location},
			"locations": []any{map[string]any{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{"uri": h.location},
					"region":           map[string]any{"startLine": h.line},
				},
			}},
		})
	}
	return map[string]any{
		"tool": map[string]any{"driver": map[string]any{"name": "NoisyScanner", "rules": rules}},
		"versionControlProvenance": []any{map[string]any{
			"repositoryUri": repoURL, "revisionId": "abc123",
		}},
		"results": results,
	}
}

// sarifBodyRuns renders one SARIF 2.1.0 document with one run per element of
// runs, so a caller can build a multi-run document without duplicating the
// per-run JSON shape.
func sarifBodyRuns(t *testing.T, repoURL string, runs [][]sarifHit) string {
	t.Helper()
	runObjs := make([]any, 0, len(runs))
	for _, hits := range runs {
		runObjs = append(runObjs, sarifRun(repoURL, hits))
	}
	body, err := json.Marshal(map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs":    runObjs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// sarifBody renders hits as a one-run SARIF 2.1.0 document, declaring a rule
// for every distinct rule id so the parser resolves titles the way a real
// scanner report does.
func sarifBody(t *testing.T, repoURL string, hits []sarifHit) string {
	t.Helper()
	return sarifBodyRuns(t, repoURL, [][]sarifHit{hits})
}

// noisySARIF is one rule firing n times at distinct locations.
func noisySARIF(t *testing.T, repoURL, rule string, n int) string {
	t.Helper()
	hits := make([]sarifHit, 0, n)
	for i := range n {
		hits = append(hits, sarifHit{rule: rule, location: fmt.Sprintf("src/f%d.go", i), line: i + 1})
	}
	return sarifBody(t, repoURL, hits)
}

// importCapResponse is the per-result slice of the import response the caps
// extend.
type importCapResponse struct {
	Format  string `json:"format"`
	Results []struct {
		ScanID          uint   `json:"scan_id"`
		Created         int    `json:"created"`
		Observed        int    `json:"observed"`
		Received        int    `json:"received"`
		Accepted        int    `json:"accepted"`
		DroppedPerRule  int    `json:"dropped_per_rule"`
		DroppedTotalCap int    `json:"dropped_total_cap"`
		FindingIDs      []uint `json:"finding_ids"`
	} `json:"results"`
}

func decodeImportResponse(t *testing.T, body []byte) importCapResponse {
	t.Helper()
	var resp importCapResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(resp.Results))
	}
	return resp
}

func TestHandleImportSARIF_capsOneNoisyRule(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	const fired = 12
	body := noisySARIF(t, "https://github.com/example/widget", "js/xss", fired)
	w := postImport(t, s, "/api/v1/import?revalidate=false", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	got := decodeImportResponse(t, w.Body.Bytes()).Results[0]
	if got.Created != importPerRuleCap || got.Accepted != importPerRuleCap {
		t.Errorf("created=%d accepted=%d, want %d/%d", got.Created, got.Accepted, importPerRuleCap, importPerRuleCap)
	}
	if got.Received != fired {
		t.Errorf("received = %d, want %d", got.Received, fired)
	}
	if got.DroppedPerRule != fired-importPerRuleCap || got.DroppedTotalCap != 0 {
		t.Errorf("dropped_per_rule=%d dropped_total_cap=%d, want %d/0",
			got.DroppedPerRule, got.DroppedTotalCap, fired-importPerRuleCap)
	}
	if len(got.FindingIDs) != importPerRuleCap {
		t.Errorf("finding_ids = %d, want %d", len(got.FindingIDs), importPerRuleCap)
	}

	var findings []db.Finding
	s.DB.Where("scan_id = ?", got.ScanID).Order("id").Find(&findings)
	if len(findings) != importPerRuleCap {
		t.Fatalf("stored %d findings, want %d", len(findings), importPerRuleCap)
	}
	// Accepted rows keep the rule-derived mapping; the cap only decides which
	// findings are imported, never what an imported finding looks like.
	for i, f := range findings {
		if want := fmt.Sprintf("src/f%d.go:%d", i, i+1); f.Location != want {
			t.Errorf("finding %d location = %q, want %q", i, f.Location, want)
		}
		if f.Title != "title for js/xss" || f.CWE != "CWE-79" || f.Severity != "High" {
			t.Errorf("finding %d = title=%q cwe=%q severity=%q", i, f.Title, f.CWE, f.Severity)
		}
	}
	var scan db.Scan
	s.DB.First(&scan, got.ScanID)
	if scan.FindingsCount != importPerRuleCap {
		t.Errorf("scan.FindingsCount = %d, want %d", scan.FindingsCount, importPerRuleCap)
	}
}

// TestHandleImportSARIF_capsEachRunSeparately proves the per-rule budget
// resets for every SARIF run rather than being shared across the upload. If
// the cap were tracked once for the whole upload instead of once per parsed
// result, the second run would keep nothing since the first run would already
// have exhausted the budget: this test is what pins the per-result decision.
func TestHandleImportSARIF_capsEachRunSeparately(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	const fired = importPerRuleCap + 4
	runA := make([]sarifHit, 0, fired)
	runB := make([]sarifHit, 0, fired)
	for i := range fired {
		// Distinct locations per run so the second run's findings do not
		// fingerprint-dedupe against the first run's, which would confuse the
		// created counts.
		runA = append(runA, sarifHit{rule: "js/xss", location: fmt.Sprintf("src/a%d.go", i), line: i + 1})
		runB = append(runB, sarifHit{rule: "js/xss", location: fmt.Sprintf("src/b%d.go", i), line: i + 1})
	}
	body := sarifBodyRuns(t, "https://github.com/example/widget", [][]sarifHit{runA, runB})
	w := postImport(t, s, "/api/v1/import?revalidate=false", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp importCapResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(resp.Results))
	}
	for i, got := range resp.Results {
		if got.Created != importPerRuleCap || got.Accepted != importPerRuleCap {
			t.Errorf("run %d: created=%d accepted=%d, want %d/%d", i, got.Created, got.Accepted, importPerRuleCap, importPerRuleCap)
		}
		if got.DroppedPerRule != 4 {
			t.Errorf("run %d: dropped_per_rule = %d, want 4", i, got.DroppedPerRule)
		}
	}
}

func TestHandleImportSARIF_capsTotalAcrossDistinctRules(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	const rules = importResultCap + 12
	hits := make([]sarifHit, 0, rules)
	for i := range rules {
		hits = append(hits, sarifHit{
			rule:     fmt.Sprintf("rule-%02d", i),
			location: fmt.Sprintf("src/f%d.go", i),
			line:     i + 1,
		})
	}
	w := postImport(t, s, "/api/v1/import?revalidate=false",
		sarifBody(t, "https://github.com/example/widget", hits))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	got := decodeImportResponse(t, w.Body.Bytes()).Results[0]
	if got.Created != importResultCap || got.Received != rules {
		t.Errorf("created=%d received=%d, want %d/%d", got.Created, got.Received, importResultCap, rules)
	}
	if got.DroppedTotalCap != rules-importResultCap || got.DroppedPerRule != 0 {
		t.Errorf("dropped_total_cap=%d dropped_per_rule=%d, want %d/0",
			got.DroppedTotalCap, got.DroppedPerRule, rules-importResultCap)
	}
	var stored int64
	s.DB.Model(&db.Finding{}).Where("scan_id = ?", got.ScanID).Count(&stored)
	if stored != importResultCap {
		t.Fatalf("stored %d findings, want %d", stored, importResultCap)
	}
}

func TestHandleImportSARIF_cleanReportReportsNoDrops(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w := postImport(t, s, "/api/v1/import?revalidate=false",
		noisySARIF(t, "https://github.com/example/widget", "js/xss", 2))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	got := decodeImportResponse(t, w.Body.Bytes()).Results[0]
	if got.Received != 2 || got.Accepted != 2 || got.Created != 2 {
		t.Errorf("received=%d accepted=%d created=%d, want 2/2/2", got.Received, got.Accepted, got.Created)
	}
	if got.DroppedPerRule != 0 || got.DroppedTotalCap != 0 {
		t.Errorf("dropped_per_rule=%d dropped_total_cap=%d, want 0/0", got.DroppedPerRule, got.DroppedTotalCap)
	}
}

func TestHandleImportMinimalJSON_isNotCapped(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	// A curated report — an analyst's list, or a trusted sharing bundle —
	// imports whole however long it is.
	const count = importResultCap + 20
	findings := make([]any, 0, count)
	for i := range count {
		findings = append(findings, map[string]any{
			"title":    "Hardcoded credential",
			"severity": "high",
			"location": fmt.Sprintf("src/f%d.go:%d", i, i+1),
		})
	}
	body, err := json.Marshal(map[string]any{
		"repository": "https://github.com/example/widget",
		"commit":     "abc123",
		"tool":       "pentest-2026q2",
		"findings":   findings,
	})
	if err != nil {
		t.Fatal(err)
	}
	w := postImport(t, s, "/api/v1/import?revalidate=false", string(body))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	resp := decodeImportResponse(t, w.Body.Bytes())
	if resp.Format != string(ingest.FormatMinimal) {
		t.Fatalf("format = %q, want minimal", resp.Format)
	}
	got := resp.Results[0]
	if got.Created != count || got.Accepted != count || got.Received != count {
		t.Errorf("created=%d accepted=%d received=%d, want %d for all", got.Created, got.Accepted, got.Received, count)
	}
	if got.DroppedPerRule != 0 || got.DroppedTotalCap != 0 {
		t.Errorf("dropped_per_rule=%d dropped_total_cap=%d, want 0/0 for a curated format",
			got.DroppedPerRule, got.DroppedTotalCap)
	}
}

func TestImportResults_capsAreChosenByFormat(t *testing.T) {
	// The same parsed result, imported once per raw-scanner-output format
	// (SARIF, CSV, markdown) and once as a curated report (minimal JSON): only
	// the format decides whether the caps bite.
	res := ingest.Result{
		RepoURL:  "https://example.com/r",
		Tool:     "NoisyScanner",
		Findings: capFindings("js/xss", importPerRuleCap+4),
	}
	cases := []struct {
		format      ingest.Format
		wantCreated int
		wantDropped int
	}{
		{ingest.FormatSARIF, importPerRuleCap, 4},
		{ingest.FormatCSV, importPerRuleCap, 4},
		{ingest.FormatMarkdown, importPerRuleCap, 4},
		{ingest.FormatMinimal, importPerRuleCap + 4, 0},
	}
	for _, tc := range cases {
		t.Run(string(tc.format), func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			out, err := importSingleResultAs(s, tc.format, res, false)
			if err != nil {
				t.Fatal(err)
			}
			if out["created"] != tc.wantCreated {
				t.Errorf("created = %v, want %d", out["created"], tc.wantCreated)
			}
			if out["dropped_per_rule"] != tc.wantDropped {
				t.Errorf("dropped_per_rule = %v, want %d", out["dropped_per_rule"], tc.wantDropped)
			}
			if out["received"] != importPerRuleCap+4 {
				t.Errorf("received = %v, want %d", out["received"], importPerRuleCap+4)
			}
		})
	}
}

func TestHandleImportSARIF_revalidatesAcceptedFindingsOnly(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	revalidate := db.Skill{
		Name: revalidateSkillName, OutputFile: "report.json",
		OutputKind: "revalidate", Version: 1, Active: true,
	}
	if err := s.DB.Create(&revalidate).Error; err != nil {
		t.Fatal(err)
	}

	w := postImport(t, s, "/api/v1/import",
		noisySARIF(t, "https://github.com/example/widget", "js/xss", importPerRuleCap+7))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	// Dropped findings were never created, so they queue no work: the funnel
	// is primed for the accepted findings and nothing else.
	var queued int64
	s.DB.Model(&db.Scan{}).
		Where("skill_id = ? AND status = ?", revalidate.ID, db.ScanQueued).
		Count(&queued)
	if queued != importPerRuleCap {
		t.Errorf("queued revalidate scans = %d, want %d", queued, importPerRuleCap)
	}
}
