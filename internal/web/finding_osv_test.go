package web

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func getOSV(t *testing.T, s *Server, id uint) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings/"+strconv.FormatUint(uint64(id), 10)+"/osv.json"))
	return w
}

// osvAffectedKinds splits an OSV record's affected[] into the entries that
// carry a package and the entries that carry only ranges, so a test can assert
// which anchoring path fired.
func osvAffectedKinds(t *testing.T, doc map[string]any) (pkgs, ranges []map[string]any) {
	t.Helper()
	raw, ok := doc["affected"].([]any)
	if !ok {
		return nil, nil
	}
	for _, a := range raw {
		m := a.(map[string]any)
		if _, ok := m["package"]; ok {
			pkgs = append(pkgs, m)
		}
		if _, ok := m["ranges"]; ok {
			ranges = append(ranges, m)
		}
	}
	return pkgs, ranges
}

func TestFindingOSV_validatesAgainstOfficialSchema(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, nil)
	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if !strings.Contains(w.Header().Get("Content-Disposition"), "scrutineer-finding-") {
		t.Errorf("Content-Disposition = %q", w.Header().Get("Content-Disposition"))
	}

	doc := decodeCSAF(t, w.Body.Bytes())
	if doc["id"] != "x_scrutineer-finding-"+strconv.FormatUint(uint64(f.ID), 10) {
		t.Errorf("id = %v", doc["id"])
	}
	if doc["schema_version"] != osvSchemaVersion {
		t.Errorf("schema_version = %v", doc["schema_version"])
	}
	if doc["modified"] == nil || doc["modified"] == "" {
		t.Errorf("modified must be present: %v", doc["modified"])
	}
	if !slices.Contains(toStringSlice(doc["aliases"]), "CVE-2026-0001") {
		t.Errorf("aliases should contain the CVE: %v", doc["aliases"])
	}
	sev := doc["severity"].([]any)[0].(map[string]any)
	if sev["type"] != "CVSS_V3" || sev["score"] != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("severity must carry the v3.1 vector string: %+v", sev)
	}
	ds := doc["database_specific"].(map[string]any)
	if _, ok := ds["scrutineer_finding_id"]; !ok {
		t.Errorf("database_specific must carry scrutineer_finding_id: %+v", ds)
	}
}

// A CVSS:3.0 vector must validate under the same CVSS_V3 severity type as a
// 3.1 vector; this is where any go-cvss / OSV-regex misalignment would surface.
func TestFindingOSV_cvss30Validates(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.CVSSVector = "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N"
		f.CVSSScore = 5.0
	})
	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	sev := doc["severity"].([]any)[0].(map[string]any)
	if sev["type"] != "CVSS_V3" || sev["score"] != "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N" {
		t.Errorf("v3.0 vector must validate as CVSS_V3: %+v", sev)
	}
}

func TestFindingOSV_emitsBothCVSSv3AndCVSSv4(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	const v3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	const v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.CVSSVector = v3
		f.CVSSScore = 9.8
		f.CVSSv4Vector = v4
		f.CVSSv4Score = 9.3
	})
	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	sevs := doc["severity"].([]any)
	if len(sevs) != 2 {
		t.Fatalf("severity entries = %d, want 2 (one each for v4 and v3): %+v", len(sevs), sevs)
	}
	first := sevs[0].(map[string]any)
	if first["type"] != "CVSS_V4" || first["score"] != v4 {
		t.Errorf("first severity must be CVSS_V4 with the v4 vector: %+v", first)
	}
	second := sevs[1].(map[string]any)
	if second["type"] != "CVSS_V3" || second["score"] != v3 {
		t.Errorf("second severity must be CVSS_V3 with the v3.1 vector: %+v", second)
	}
}

func TestFindingOSV_emitsOnlyV4WhenV3Absent(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	const v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.CVSSVector = ""
		f.CVSSScore = 0
		f.CVSSv4Vector = v4
		f.CVSSv4Score = 9.3
	})
	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	raw, ok := doc["severity"]
	if !ok {
		t.Fatalf("severity key missing in OSV doc keys=%v", keys(doc))
	}
	sevs, ok := raw.([]any)
	if !ok || len(sevs) != 1 {
		t.Fatalf("severity entries = %v, want 1 (v4 only)", raw)
	}
	if sevs[0].(map[string]any)["type"] != "CVSS_V4" {
		t.Errorf("severity[0].type = %v", sevs[0])
	}
}

func TestFindingOSV_packageWithPURLBecomesAffectedPackage(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, nil)
	s.DB.Create(&db.Package{RepositoryID: f.RepositoryID, Name: "lib", Ecosystem: "npm", PURL: "pkg:npm/lib@1.0.0"})

	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	pkgs, ranges := osvAffectedKinds(t, doc)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package affected entry, got %d", len(pkgs))
	}
	if len(ranges) != 0 {
		t.Errorf("packages present: must not fall back to a GIT range: %+v", ranges)
	}
	pkg := pkgs[0]["package"].(map[string]any)
	if pkg["ecosystem"] != "npm" || pkg["purl"] != "pkg:npm/lib@1.0.0" {
		t.Errorf("package = %+v", pkg)
	}
}

func TestFindingOSV_noPackageRemoteRepoUsesGitRange(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, nil)
	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	pkgs, ranges := osvAffectedKinds(t, doc)
	if len(pkgs) != 0 || len(ranges) != 1 {
		t.Fatalf("expected only a GIT range, got pkgs=%d ranges=%d", len(pkgs), len(ranges))
	}
	rng := ranges[0]["ranges"].([]any)[0].(map[string]any)
	if rng["type"] != "GIT" || rng["repo"] != "https://github.com/example/lib.git" {
		t.Errorf("range = %+v (repo must be the cloneable URL, not HTMLURL)", rng)
	}
	events := rng["events"].([]any)
	if events[0].(map[string]any)["introduced"] != "0" {
		t.Errorf("first event must be introduced:0, got %+v", events)
	}
}

func TestFindingOSV_gitRangeCarriesFixCommit(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	const sha = "0123456789abcdef0123456789abcdef01234567"
	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.FixCommit = sha
	})
	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	_, ranges := osvAffectedKinds(t, doc)
	events := ranges[0]["ranges"].([]any)[0].(map[string]any)["events"].([]any)
	var sawFixed bool
	for _, e := range events {
		if e.(map[string]any)["fixed"] == sha {
			sawFixed = true
		}
	}
	if !sawFixed {
		t.Errorf("GIT range must carry the fix commit, got events %+v", events)
	}
}

// A non-SHA fix commit cannot be a GIT range event (the schema requires a full
// hash); the event must be dropped rather than 500ing the export.
func TestFindingOSV_gitRangeShortFixCommitOmitsFixedEvent(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.FixCommit = "v1.4.2"
	})
	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	_, ranges := osvAffectedKinds(t, doc)
	events := ranges[0]["ranges"].([]any)[0].(map[string]any)["events"].([]any)
	if len(events) != 1 {
		t.Errorf("non-SHA fix commit must yield only the introduced event, got %+v", events)
	}
}

func TestFindingOSV_localRepoNoPackageOmitsAffected(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "file:///tmp/widget", Name: "widget"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "bug", Status: db.FindingTriaged, Location: "src/x.go:12"}
	s.DB.Create(&f)

	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	if _, ok := doc["affected"]; ok {
		t.Errorf("local repo with no package must omit affected: %+v", doc["affected"])
	}
	ds := doc["database_specific"].(map[string]any)
	if ds["location"] != "src/x.go:12" {
		t.Errorf("location must live in database_specific: %+v", ds)
	}
}

// An ecosystem the schema's controlled list does not contain (here cocoapods,
// which git-pkgs maps but OSV omits) must route to a GIT range, never an
// invalid package entry that would 500 at validation.
func TestFindingOSV_unmappableEcosystemFallsBackToGitRange(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, nil)
	s.DB.Create(&db.Package{RepositoryID: f.RepositoryID, Name: "AFNetworking", Ecosystem: "cocoapods", PURL: "pkg:cocoapods/AFNetworking@1.0.0"})

	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	pkgs, ranges := osvAffectedKinds(t, doc)
	if len(pkgs) != 0 {
		t.Errorf("unmappable ecosystem must not become a package entry: %+v", pkgs)
	}
	if len(ranges) != 1 {
		t.Errorf("expected GIT-range fallback, got %d ranges", len(ranges))
	}
}

func TestFindingOSV_referencesMappedWithTypes(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, nil)
	s.DB.Create(&db.FindingReference{FindingID: f.ID, URL: "https://github.com/example/lib/security/advisories/GHSA-jfh8-c2jp-5v3q", Tags: "advisory"})
	s.DB.Create(&db.FindingReference{FindingID: f.ID, URL: "https://github.com/example/lib/pull/42", Tags: "pr"})

	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	byURL := map[string]string{}
	for _, r := range doc["references"].([]any) {
		m := r.(map[string]any)
		byURL[m["url"].(string)] = m["type"].(string)
	}
	if byURL["https://github.com/example/lib/security/advisories/GHSA-jfh8-c2jp-5v3q"] != "ADVISORY" {
		t.Errorf("advisory tag must map to ADVISORY: %+v", byURL)
	}
	if byURL["https://github.com/example/lib/pull/42"] != "FIX" {
		t.Errorf("pr tag must map to FIX: %+v", byURL)
	}
}

// A finding reference may carry a non-URI string; export must still validate
// (mirrors CSAF, which emits the URL raw).
func TestFindingOSV_junkReferenceURLStillValidates(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, nil)
	s.DB.Create(&db.FindingReference{FindingID: f.ID, URL: "not a url", Tags: "article"})

	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
}

func TestFindingOSV_noCVSSOmitsSeverity(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.CVSSVector = ""
		f.CVSSScore = 0
		f.CVEID = ""
	})
	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	if _, ok := doc["severity"]; ok {
		t.Errorf("severity must be omitted without a vector: %+v", doc["severity"])
	}
	if _, ok := doc["aliases"]; ok {
		t.Errorf("aliases must be omitted without a CVE/GHSA: %+v", doc["aliases"])
	}
}

func TestFindingOSV_malformedVectorOmitsSeverity(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.CVSSVector = "not-a-vector"
		f.CVSSScore = 5.0
	})
	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	if _, ok := doc["severity"]; ok {
		t.Errorf("malformed vector must omit severity, not 500: %+v", doc["severity"])
	}
}

func TestFindingOSV_aliasesIncludeGHSAFromReferences(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.CVEID = ""
	})
	s.DB.Create(&db.FindingReference{FindingID: f.ID, URL: "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q", Tags: "ghsa"})

	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	if !slices.Contains(toStringSlice(doc["aliases"]), "GHSA-jfh8-c2jp-5v3q") {
		t.Errorf("aliases should include the GHSA id from the reference: %v", doc["aliases"])
	}
}

func TestFindingOSV_aliasesIncludeGHSAID(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.GHSAID = "GHSA-jfh8-c2jp-5v3q"
	})

	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	if !slices.Contains(toStringSlice(doc["aliases"]), "GHSA-jfh8-c2jp-5v3q") {
		t.Errorf("aliases should include the finding's GHSA id: %v", doc["aliases"])
	}
}

func TestFindingOSV_duplicateReturns410(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.Status = db.FindingDuplicate
	})
	w := getOSV(t, s, f.ID)
	if w.Code != http.StatusGone {
		t.Fatalf("status %d, want 410", w.Code)
	}
}

func TestFindingOSV_404ForMissingFinding(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w := getOSV(t, s, 99999)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", w.Code)
	}
}

func TestOSVReferenceType(t *testing.T) {
	cases := []struct {
		tags string
		want string
	}{
		{"advisory", "ADVISORY"},
		{"ghsa", "ADVISORY"},
		{"cve", "ADVISORY"},
		{"patch", "FIX"},
		{"pr", "FIX"},
		{"issue", "REPORT"},
		{"discussion", "DISCUSSION"},
		{"article", "ARTICLE"},
		{"", "WEB"},
		{"something-else", "WEB"},
		{"pr,advisory", "FIX"},
	}
	for _, tc := range cases {
		if got := osvReferenceType(tc.tags); got != tc.want {
			t.Errorf("osvReferenceType(%q) = %q, want %q", tc.tags, got, tc.want)
		}
	}
}

func TestOSVEcosystem(t *testing.T) {
	cases := []struct {
		purl string
		want string
		ok   bool
	}{
		{"pkg:npm/lib@1.0.0", "npm", true},
		{"pkg:golang/example/lib@1.0.0", "Go", true},
		{"pkg:gem/rails@7.0.0", "RubyGems", true},
		{"pkg:cargo/serde@1.0.0", "crates.io", true},
		{"pkg:cocoapods/AFNetworking@1.0.0", "", false},
		{"", "", false},
		{"not-a-purl", "", false},
	}
	for _, tc := range cases {
		got, ok := osvEcosystem(db.Package{PURL: tc.purl})
		if got != tc.want || ok != tc.ok {
			t.Errorf("osvEcosystem(%q) = (%q, %v), want (%q, %v)", tc.purl, got, ok, tc.want, tc.ok)
		}
	}
}

func TestOSVCWEIDs_splitsAndNormalises(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"CWE-79", []string{"CWE-79"}},
		{"cwe-79, CWE-89", []string{"CWE-79", "CWE-89"}},
		{"CWE-79, CWE-79, CWE-89", []string{"CWE-79", "CWE-89"}},
		// Mixed-case duplicate: case normalisation must run before dedup,
		// so the second occurrence collapses even when its case differs.
		{"CWE-79, cwe-79", []string{"CWE-79"}},
	}
	for _, tc := range cases {
		got := osvCWEIDs(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("osvCWEIDs(%q) = %v, want %v", tc.in, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("osvCWEIDs(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

func TestOSVSemverRangeFromFix(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"1.6.3", true},
		{"v1.6.3", true},
		{"1.6", false},
		{"<1.6.3", false},
		{"1.6.3-beta.1", true},
	}
	for _, tc := range cases {
		_, ok := osvSemverRangeFromFix(tc.in)
		if ok != tc.want {
			t.Errorf("osvSemverRangeFromFix(%q) ok=%v want %v", tc.in, ok, tc.want)
		}
	}
}

func TestFindingOSV_includesSIRTTemplateFields(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.FixVersion = "1.6.3"
	})
	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())

	credits, ok := doc["credits"].([]any)
	if !ok || len(credits) == 0 {
		t.Errorf("credits missing/empty: %v", doc["credits"])
	}
	var sawCoordinator bool
	for _, c := range credits {
		m := c.(map[string]any)
		if m["type"] == "COORDINATOR" && m["name"] == "scrutineer" {
			sawCoordinator = true
		}
	}
	if !sawCoordinator {
		t.Errorf("expected a COORDINATOR credit named scrutineer: %v", credits)
	}

	ds := doc["database_specific"].(map[string]any)
	if ds["tracking_id"] == nil {
		t.Errorf("database_specific.tracking_id missing: %v", ds)
	}
	if _, ok := ds["cwe_ids"].([]any); !ok {
		t.Errorf("database_specific.cwe_ids missing or not an array: %v", ds["cwe_ids"])
	}
}

func TestFindingOSV_withdrawnSetWhenRejected(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.Status = db.FindingRejected
	})
	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	if doc["withdrawn"] == nil || doc["withdrawn"] == "" {
		t.Errorf("rejected finding must carry withdrawn timestamp, got %v", doc["withdrawn"])
	}
}

func TestFindingOSV_packageHasSemverRangeFromFixVersion(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.FixVersion = "2.3.1"
	})
	// Add a package so the affected entry takes the package shape (not GIT).
	s.DB.Create(&db.Package{
		RepositoryID: f.RepositoryID,
		Name:         "lib",
		Ecosystem:    "npm",
		PURL:         "pkg:npm/lib",
	})
	w := getOSV(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	affected := doc["affected"].([]any)
	if len(affected) == 0 {
		t.Fatal("affected[] is empty")
	}
	a0 := affected[0].(map[string]any)
	ranges, ok := a0["ranges"].([]any)
	if !ok || len(ranges) == 0 {
		t.Fatalf("affected[0].ranges missing: %v", a0)
	}
	r0 := ranges[0].(map[string]any)
	if r0["type"] != "SEMVER" {
		t.Errorf("range type = %v, want SEMVER", r0["type"])
	}
	events := r0["events"].([]any)
	if len(events) < 2 {
		t.Fatalf("SEMVER range needs introduced + fixed events: %v", events)
	}
	if events[1].(map[string]any)["fixed"] != "2.3.1" {
		t.Errorf("fixed event = %v, want 2.3.1", events[1])
	}
}
