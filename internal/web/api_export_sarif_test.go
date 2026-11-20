package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/git-pkgs/sarif"
	"gorm.io/gorm"

	"scrutineer/internal/db"
)

func getRepoSARIF(t *testing.T, s *Server, repoID uint, qs string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/v1/repositories/"+strconv.FormatUint(uint64(repoID), 10)+"/findings?format=sarif"+qs, nil)
	asOperator(r)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func parseSARIFBody(t *testing.T, w *httptest.ResponseRecorder) *sarif.Log {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200. body=%s", w.Code, w.Body)
	}
	log, err := sarif.Parse(w.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := sarif.Validate(log); err != nil {
		t.Fatalf("emitted log is not valid SARIF: %v", err)
	}
	return log
}

func scrutineerProps(t *testing.T, res sarif.Result) map[string]any {
	t.Helper()
	props, ok := res.Properties["scrutineer"].(map[string]any)
	if !ok {
		t.Fatalf("result %q has no scrutineer property bag: %+v", res.Message.Text, res.Properties)
	}
	return props
}

// TestExportRepoFindingsSARIF pins the finding-to-SARIF mapping: one run per
// observed revision, sub_path-rebased locations, CWE rules, separate audit
// evidence and verification state, and no disclosure correspondence.
func TestExportRepoFindingsSARIF(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/acme/widget", Name: "widget"}
	s.DB.Create(&repo)
	first := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName, Commit: "aaa111"}
	second := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName, Commit: "ccc333"}
	s.DB.Create(&first)
	s.DB.Create(&second)

	overflow := db.Finding{
		ScanID: first.ID, RepositoryID: repo.ID, Commit: "aaa111", LastSeenCommit: "bbb222", SubPath: "pkg",
		FindingID: "F1", Fingerprint: "fp-overflow", VID: "vid-overflow",
		Title: "Heap overflow in parse_header", Severity: "Critical", Confidence: "high", Status: db.FindingTriaged,
		CWE: "CWE-122, CWE-787", Location: "src/header.c:10-14", Locations: "src/header.c:10-14\nsrc/body.c:7:3",
		Reachability: "reachable", Trace: "length flows into memcpy", Validation: "reproduced with a 70-byte header",
		Rule: "heap-overflow", Anchor: "header length is trusted before the copy", Instance: "parse_header",
		DisclosureDraft: "SECRET-DRAFT-BODY", SuggestedRecipients: "maintainer@example.com",
	}
	rejected := db.Finding{
		ScanID: second.ID, RepositoryID: repo.ID, Commit: "ccc333",
		Title: "Unchecked return value", Severity: "Low", Status: db.FindingRejected, Location: "main.c",
	}
	s.DB.Create(&overflow)
	s.DB.Create(&rejected)
	olderVerify := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "verify"}
	latestVerify := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "verify"}
	s.DB.Create(&olderVerify)
	s.DB.Create(&latestVerify)
	score := 0.8
	s.DB.Create(&db.FindingVerification{FindingID: overflow.ID, ScanID: olderVerify.ID, Status: "inconclusive", Report: "{}"})
	s.DB.Create(&db.FindingVerification{FindingID: overflow.ID, ScanID: latestVerify.ID, Status: "confirmed", Score: &score, Report: "{}"})
	s.DB.Create(&db.FindingCommunication{FindingID: overflow.ID, Channel: "email", Body: "SECRET-CORRESPONDENCE"})

	w := getRepoSARIF(t, s, repo.ID, "")
	for _, secret := range []string{"SECRET-DRAFT-BODY", "maintainer@example.com", "SECRET-CORRESPONDENCE"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Errorf("SARIF export leaks %q", secret)
		}
	}
	log := parseSARIFBody(t, w)

	if len(log.Runs) != 2 {
		t.Fatalf("got %d runs, want one per observed revision", len(log.Runs))
	}
	byRevision := map[string]sarif.Run{}
	for _, run := range log.Runs {
		if run.Tool.Driver.Name != "scrutineer" {
			t.Errorf("driver name %q, want scrutineer", run.Tool.Driver.Name)
		}
		vcs := run.VersionControlProvenance
		if len(vcs) != 1 || vcs[0].RepositoryURI != repo.URL {
			t.Fatalf("versionControlProvenance = %+v, want the repository URL", vcs)
		}
		byRevision[vcs[0].RevisionID] = run
	}

	assertOverflowSARIF(t, byRevision["bbb222"], overflow, score)
	assertRejectedSARIF(t, byRevision["ccc333"])
}

func assertOverflowSARIF(t *testing.T, overflowRun sarif.Run, overflow db.Finding, score float64) {
	t.Helper()
	if len(overflowRun.Results) != 1 {
		t.Fatalf("got %d results at the last-seen commit, want 1", len(overflowRun.Results))
	}
	res := overflowRun.Results[0]
	if res.RuleID != "CWE-122" || res.Level != "error" || res.Message.Text != overflow.Title {
		t.Errorf("result = rule %q level %q message %q", res.RuleID, res.Level, res.Message.Text)
	}
	if len(overflowRun.Tool.Driver.Rules) != 1 || overflowRun.Tool.Driver.Rules[0].ID != "CWE-122" {
		t.Errorf("rules = %+v, want the CWE-122 rule", overflowRun.Tool.Driver.Rules)
	}
	if len(res.Locations) != 1 {
		t.Fatalf("got %d locations, want the primary one", len(res.Locations))
	}
	primary := res.Locations[0].PhysicalLocation
	if primary.ArtifactLocation.URI != "pkg/src/header.c" || primary.Region.StartLine != 10 || primary.Region.EndLine != 14 {
		t.Errorf("primary location = %q %d-%d", primary.ArtifactLocation.URI, primary.Region.StartLine, primary.Region.EndLine)
	}
	if len(res.RelatedLocations) != 1 {
		t.Fatalf("got %d related locations, want the second hit only", len(res.RelatedLocations))
	}
	related := res.RelatedLocations[0].PhysicalLocation
	if related.ArtifactLocation.URI != "pkg/src/body.c" || related.Region.StartLine != 7 || related.Region.StartColumn != 3 {
		t.Errorf("related location = %q %d:%d", related.ArtifactLocation.URI, related.Region.StartLine, related.Region.StartColumn)
	}
	if res.Fingerprints["scrutineer/v1"] != "fp-overflow" {
		t.Errorf("fingerprints = %v", res.Fingerprints)
	}
	if len(res.Suppressions) != 0 {
		t.Errorf("triaged finding carries suppressions %+v", res.Suppressions)
	}
	props := scrutineerProps(t, res)
	if props["id"] != float64(overflow.ID) || props["first_seen_commit"] != "aaa111" || props["cwe"] != overflow.CWE {
		t.Errorf("identity properties = %+v", props)
	}
	if props["rule"] != overflow.Rule || props["anchor"] != overflow.Anchor || props["instance"] != overflow.Instance {
		t.Errorf("rule/anchor/instance properties = %+v", props)
	}
	evidence, _ := props["evidence"].(map[string]any)
	if evidence["validation"] != overflow.Validation || evidence["trace"] != overflow.Trace {
		t.Errorf("evidence = %+v", evidence)
	}
	verification, _ := props["verification"].(map[string]any)
	if verification["status"] != "confirmed" || verification["score"] != score {
		t.Errorf("verification = %+v, want the latest verify row", verification)
	}
}

func assertRejectedSARIF(t *testing.T, rejectedRun sarif.Run) {
	t.Helper()
	if len(rejectedRun.Results) != 1 {
		t.Fatalf("got %d results at the rejected finding's commit, want 1", len(rejectedRun.Results))
	}
	res := rejectedRun.Results[0]
	if res.RuleID != sarifFallbackRuleID || res.Level != "note" {
		t.Errorf("rejected result = rule %q level %q", res.RuleID, res.Level)
	}
	if loc := res.Locations[0].PhysicalLocation; loc.ArtifactLocation.URI != "main.c" || loc.Region.StartLine != 0 {
		t.Errorf("line-less location = %q line %d", loc.ArtifactLocation.URI, loc.Region.StartLine)
	}
	if len(res.Suppressions) != 1 || res.Suppressions[0].Kind != "external" || res.Suppressions[0].Justification != "rejected" {
		t.Errorf("suppressions = %+v, want the analyst rejection", res.Suppressions)
	}
	verification, _ := scrutineerProps(t, res)["verification"].(map[string]any)
	if verification["status"] != "unverified" {
		t.Errorf("verification = %+v, want unverified", verification)
	}
}

// TestExportRepoFindingsSARIF_emptyRepository pins the empty case: one run with
// an explicit empty results array.
func TestExportRepoFindingsSARIF_emptyRepository(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/acme/empty", Name: "empty"}
	s.DB.Create(&repo)

	w := getRepoSARIF(t, s, repo.ID, "")
	log := parseSARIFBody(t, w)
	if len(log.Runs) != 1 || log.Runs[0].VersionControlProvenance[0].RevisionID != "" {
		t.Fatalf("runs = %+v, want one run without a revision", log.Runs)
	}
	var raw struct {
		Runs []struct {
			Results json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw.Runs[0].Results) != "[]" {
		t.Errorf("results = %s, want an explicit empty array", raw.Runs[0].Results)
	}
}

// TestExportRepoFindingsSARIF_localRepository pins that a local checkout
// without a portable origin still exports valid SARIF, naming the repository
// by a file URI that round-trips to its path. On Windows the stored
// file://C:\... form is not a valid URI, so this used to fail validation.
func TestExportRepoFindingsSARIF_localRepository(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	dir := filepath.Join(t.TempDir(), "my widget")
	repo := db.Repository{URL: LocalScheme + dir, Name: "my widget"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName, Commit: "aaa111"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Fingerprint: "fp-local",
		Title: "Local issue", Severity: "High", Location: "main.go:3", Commit: "aaa111",
	})

	log := parseSARIFBody(t, getRepoSARIF(t, s, repo.ID, ""))
	uri := log.Runs[0].VersionControlProvenance[0].RepositoryURI
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "file" || u.Host != "" || strings.ContainsAny(uri, " \\") {
		t.Fatalf("repositoryUri = %q, want an escaped file URI with no host", uri)
	}
	// Windows paths gain a leading slash before the drive (/C:/...).
	want := filepath.ToSlash(dir)
	if !strings.HasPrefix(want, "/") {
		want = "/" + want
	}
	if u.Path != want {
		t.Errorf("repositoryUri path = %q, want %q", u.Path, want)
	}
}

func TestSARIFFileURI(t *testing.T) {
	cases := map[string]string{
		"/srv/widget":    "file:///srv/widget",
		"/srv/my widget": "file:///srv/my%20widget",
	}
	if runtime.GOOS == "windows" {
		cases = map[string]string{
			`C:\Users\me\widget`:    "file:///C:/Users/me/widget",
			`C:\Users\me\my widget`: "file:///C:/Users/me/my%20widget",
		}
	}
	for in, want := range cases {
		if got := sarifFileURI(in); got != want {
			t.Errorf("sarifFileURI(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestExportRepoFindingsSARIF_filters pins that the endpoint's selection
// options apply to SARIF and that bundle-only options are refused.
func TestExportRepoFindingsSARIF_filters(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedScopedFindings(t, s)

	titles := func(qs string) []string {
		var out []string
		for _, run := range parseSARIFBody(t, getRepoSARIF(t, s, repo.ID, qs)).Runs {
			for _, res := range run.Results {
				out = append(out, res.Message.Text)
			}
		}
		return out
	}
	if got := titles(""); len(got) != 2 {
		t.Errorf("unfiltered titles = %v, want both findings", got)
	}
	for _, qs := range []string{"&scope=findings", "&status=new"} {
		if got := titles(qs); len(got) != 1 || got[0] != "audit finding" {
			t.Errorf("%s titles = %v, want the audit finding only", qs, got)
		}
	}
	if got := titles("&sub_path=pkg"); len(got) != 1 || got[0] != "semgrep noise" {
		t.Errorf("sub_path titles = %v, want the pkg finding only", got)
	}
	if got := titles("&severity=Low"); len(got) != 0 {
		t.Errorf("severity=Low titles = %v, want none", got)
	}

	for _, qs := range []string{"&encrypt=1", "&include=all", "&scope=everything"} {
		if w := getRepoSARIF(t, s, repo.ID, qs); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", qs, w.Code)
		}
	}
}

// TestSARIFResultSuppressions pins that rejected and duplicate findings carry
// an accepted external suppression and other lifecycle states carry none.
func TestSARIFResultSuppressions(t *testing.T) {
	for status, suppressed := range map[db.FindingLifecycle]bool{
		db.FindingRejected: true, db.FindingDuplicate: true, db.FindingTriaged: false, db.FindingFixed: false,
	} {
		got := sarifResult(db.Finding{Title: "x", Status: status}, nil).Suppressions
		if suppressed && (len(got) != 1 || got[0].State != "accepted" || got[0].Justification != string(status)) {
			t.Errorf("%s: suppressions = %+v, want one accepted suppression", status, got)
		}
		if !suppressed && len(got) != 0 {
			t.Errorf("%s: suppressions = %+v, want none", status, got)
		}
	}
}

func TestSARIFLocation(t *testing.T) {
	cases := []struct {
		subPath, location, uri string
		start, end, column     int
	}{
		{"", "lib/a.go:42", "lib/a.go", 42, 0, 0},
		{"", "lib/a.go:42:7", "lib/a.go", 42, 0, 7},
		{"", "lib/a.go:10-20", "lib/a.go", 10, 20, 0},
		{"pkg", "./lib/a.go:3", "pkg/lib/a.go", 3, 0, 0},
		{"", "lib/my file.go:1", "lib/my%20file.go", 1, 0, 0},
		{"", "lib/a.go:0", "lib/a.go", 0, 0, 0},
		{"", "lib/a.go:9-2", "lib/a.go", 9, 0, 0},
		{"", "C:/src/a.c:4", "./C:/src/a.c", 4, 0, 0},
	}
	for _, tc := range cases {
		loc, ok := sarifLocation(tc.subPath, tc.location)
		if !ok {
			t.Errorf("%q: no location", tc.location)
			continue
		}
		pl := loc.PhysicalLocation
		if pl.ArtifactLocation.URI != tc.uri || pl.Region.StartLine != tc.start || pl.Region.EndLine != tc.end || pl.Region.StartColumn != tc.column {
			t.Errorf("%q = %q %d-%d col %d, want %q %d-%d col %d", tc.location,
				pl.ArtifactLocation.URI, pl.Region.StartLine, pl.Region.EndLine, pl.Region.StartColumn,
				tc.uri, tc.start, tc.end, tc.column)
		}
	}
	for _, bad := range []string{"", "/etc/passwd:1", "../outside.go:3"} {
		if _, ok := sarifLocation("", bad); ok {
			t.Errorf("%q: got a location, want none", bad)
		}
	}
}

func getGlobalSARIF(t *testing.T, s *Server, qs string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/v1/findings?format=sarif"+qs, nil)
	asOperator(r)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// TestExportGlobalSARIF covers separate repositories, multiple revisions,
// verification ID selection, and no disclosure of confidential columns.
func TestExportGlobalSARIF(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repos := []db.Repository{
		{URL: "https://github.com/acme/one", Name: "one"},
		{URL: "https://github.com/acme/two", Name: "two"},
	}
	for i := range repos {
		if err := s.DB.Create(&repos[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	scans := make([]db.Scan, 2)
	for i := range repos {
		scans[i] = db.Scan{RepositoryID: repos[i].ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
		if err := s.DB.Create(&scans[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	findings := []db.Finding{
		{RepositoryID: repos[0].ID, ScanID: scans[0].ID, Title: "one-old", Commit: "initial", LastSeenCommit: "rev-old", Severity: "High", DisclosureDraft: "GLOBAL-SARIF-SECRET"},
		{RepositoryID: repos[0].ID, ScanID: scans[0].ID, Title: "one-new", Commit: "initial", LastSeenCommit: "rev-new", Severity: "High"},
		{RepositoryID: repos[1].ID, ScanID: scans[1].ID, Title: "two-old", Commit: "rev-old", Severity: "Low", Rule: "sql-injection", Anchor: "filter concatenated into the query", Instance: "search"},
	}
	for i := range findings {
		if err := s.DB.Create(&findings[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	verifyOlder := db.Scan{RepositoryID: repos[1].ID, Kind: "skill", Status: db.ScanDone, SkillName: "verify"}
	verifyNewer := db.Scan{RepositoryID: repos[1].ID, Kind: "skill", Status: db.ScanDone, SkillName: "verify"}
	if err := s.DB.Create(&verifyOlder).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&verifyNewer).Error; err != nil {
		t.Fatal(err)
	}
	older := db.FindingVerification{FindingID: findings[2].ID, ScanID: verifyOlder.ID, Status: "inconclusive", Report: "{}"}
	newer := db.FindingVerification{FindingID: findings[2].ID, ScanID: verifyNewer.ID, Status: "confirmed", Report: "{}"}
	if err := s.DB.Create(&older).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&newer).Error; err != nil {
		t.Fatal(err)
	}
	w := getGlobalSARIF(t, s, "")
	if strings.Contains(w.Body.String(), "GLOBAL-SARIF-SECRET") {
		t.Fatal("global SARIF leaked disclosure draft")
	}
	log := parseSARIFBody(t, w)
	if len(log.Runs) != 3 {
		t.Fatalf("runs = %d, want 3", len(log.Runs))
	}
	type key struct{ url, revision string }
	groups := map[key]sarif.Run{}
	for _, run := range log.Runs {
		if len(run.VersionControlProvenance) != 1 {
			t.Fatalf("provenance = %+v", run.VersionControlProvenance)
		}
		p := run.VersionControlProvenance[0]
		groups[key{p.RepositoryURI, p.RevisionID}] = run
	}
	for _, want := range []struct {
		k     key
		title string
	}{
		{key{repos[0].URL, "rev-old"}, "one-old"},
		{key{repos[0].URL, "rev-new"}, "one-new"},
		{key{repos[1].URL, "rev-old"}, "two-old"},
	} {
		run, ok := groups[want.k]
		if !ok || len(run.Results) != 1 || run.Results[0].Message.Text != want.title {
			t.Errorf("group %+v = %+v, want one result %q", want.k, run.Results, want.title)
		}
	}
	twoProps := scrutineerProps(t, groups[key{repos[1].URL, "rev-old"}].Results[0])
	if twoProps["rule"] != "sql-injection" || twoProps["anchor"] != "filter concatenated into the query" || twoProps["instance"] != "search" {
		t.Errorf("global rule/anchor/instance properties = %+v", twoProps)
	}
	verification, _ := twoProps["verification"].(map[string]any)
	if verification["status"] != "confirmed" || verification["verify_scan_id"] != float64(verifyNewer.ID) {
		t.Errorf("latest verification = %+v, want confirmed from scan %d", verification, verifyNewer.ID)
	}
}

func TestExportGlobalSARIFFilters(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedScopedFindings(t, s)
	for _, tc := range []struct {
		qs   string
		want []string
	}{
		{"", []string{"audit finding", "semgrep noise"}},
		{"&scope=findings", []string{"audit finding"}},
		{"&status=new", []string{"audit finding"}},
		{"&sub_path=pkg", []string{"semgrep noise"}},
		{"&severity=Low", nil},
		{"&repository_id=" + strconv.FormatUint(uint64(repo.ID), 10), []string{"audit finding", "semgrep noise"}},
		{"&repository_id=9999999", nil},
		{"&since=2100-01-01T00:00:00Z", nil},
		{"&updated_since=2100-01-01T00:00:00Z", nil},
	} {
		log := parseSARIFBody(t, getGlobalSARIF(t, s, tc.qs))
		var got []string
		for _, run := range log.Runs {
			for _, res := range run.Results {
				got = append(got, res.Message.Text)
			}
		}
		slices.Sort(got)
		slices.Sort(tc.want)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: titles %v, want %v", tc.qs, got, tc.want)
		}
	}
	for _, qs := range []string{"&encrypt=1", "&include=all", "&scope=everything", "&repository_id=oops", "&since=bad"} {
		if w := getGlobalSARIF(t, s, qs); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", qs, w.Code)
		}
	}
}

func TestExportGlobalSARIFEmpty(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	log := parseSARIFBody(t, getGlobalSARIF(t, s, ""))
	if len(log.Runs) != 0 {
		t.Errorf("empty global export has %d runs, want zero", len(log.Runs))
	}
}

func TestExportGlobalSARIFBound(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/acme/huge", Name: "huge"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	// One SQL statement avoids making this test slow by executing 10,001 INSERTs.
	if err := s.DB.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < ?)
		INSERT INTO findings (repository_id, scan_id, title, severity, status)
		SELECT ?, ?, 'finding', 'High', 'new' FROM n`, globalSARIFMaxFindings+1, repo.ID, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	// An oversized export must check IDs without materializing wide evidence
	// columns (trace, validation, etc.) before returning HTTP 400.
	var selects [][]string
	if err := s.DB.Callback().Query().Before("gorm:query").Register("test:global_sarif_bound_columns", func(tx *gorm.DB) {
		if tx.Statement.Table == "findings" {
			selects = append(selects, append([]string(nil), tx.Statement.Selects...))
		}
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.DB.Callback().Query().Remove("test:global_sarif_bound_columns") }()
	w := getGlobalSARIF(t, s, "")
	if len(selects) != 1 || !slices.Equal(selects[0], []string{"id"}) {
		t.Errorf("oversized SARIF queried finding columns %v; want only IDs", selects)
	}
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "10000") {
		t.Fatalf("status %d, body=%s; want bounded 400", w.Code, w.Body)
	}
	if strings.Contains(w.Header().Get("Content-Type"), "x-ndjson") {
		t.Fatal("oversized SARIF wrote streaming output")
	}
}

// A missing portable origin must retain the per-repository SARIF behavior:
// an escaped file URI is emitted, not a malformed file://host/path URL.
func TestExportGlobalSARIFLocalRepository(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	dir := filepath.Join(t.TempDir(), "local checkout")
	repo := db.Repository{URL: LocalScheme + dir, Name: "local checkout"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "local finding"}).Error; err != nil {
		t.Fatal(err)
	}
	log := parseSARIFBody(t, getGlobalSARIF(t, s, ""))
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	uri := log.Runs[0].VersionControlProvenance[0].RepositoryURI
	parsed, err := url.Parse(uri)
	// File URIs use an absolute URL path, including a leading slash before
	// the drive letter on Windows (file:///C:/...), unlike filepath.ToSlash.
	wantPath := filepath.ToSlash(dir)
	if !strings.HasPrefix(wantPath, "/") {
		wantPath = "/" + wantPath
	}
	if err != nil || parsed.Scheme != "file" || parsed.Host != "" || parsed.Path != wantPath {
		t.Fatalf("local provenance %q parsed as %+v: %v (want path %q)", uri, parsed, err, wantPath)
	}
}
