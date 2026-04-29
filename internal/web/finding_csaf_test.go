package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

const wantAttackVectorNetwork = "NETWORK"

func seedCSAFFinding(t *testing.T, s *Server, mut func(*db.Finding)) db.Finding {
	t.Helper()
	repo := db.Repository{
		URL:      "https://github.com/example/lib.git",
		Name:     "lib",
		FullName: "example/lib",
		HTMLURL:  "https://github.com/example/lib",
	}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	f := db.Finding{
		ScanID:       scan.ID,
		RepositoryID: repo.ID,
		FindingID:    "F1",
		Title:        "ReDoS in pattern matcher",
		Severity:     "High",
		Status:       db.FindingTriaged,
		CWE:          "CWE-79",
		Affected:     "<1.4.2",
		CVEID:        "CVE-2026-0001",
		CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSSScore:    9.8,
	}
	if mut != nil {
		mut(&f)
	}
	s.DB.Create(&f)
	return f
}

func decodeCSAF(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, body)
	}
	return m
}

func getCSAF(t *testing.T, s *Server, id uint) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings/"+strconv.FormatUint(uint64(id), 10)+"/csaf.json"))
	return w
}

func TestFindingCSAF_validatesAgainstOfficialSchema(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, nil)
	w := getCSAF(t, s, f.ID)
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
	docMeta := doc["document"].(map[string]any)
	if docMeta["category"] != "csaf_vex" || docMeta["csaf_version"] != "2.0" {
		t.Errorf("document meta = %+v", docMeta)
	}
	vulns := doc["vulnerabilities"].([]any)
	if len(vulns) != 1 {
		t.Fatalf("vulnerabilities = %d", len(vulns))
	}
	v := vulns[0].(map[string]any)
	if v["cve"] != "CVE-2026-0001" {
		t.Errorf("cve = %v", v["cve"])
	}
	cwe := v["cwe"].(map[string]any)
	if cwe["id"] != "CWE-79" {
		t.Errorf("cwe id = %v", cwe["id"])
	}
	scores := v["scores"].([]any)
	cvss := scores[0].(map[string]any)["cvss_v3"].(map[string]any)
	if cvss["attackVector"] != wantAttackVectorNetwork || cvss["baseSeverity"] != "HIGH" {
		t.Errorf("cvss = %+v", cvss)
	}
	ps := v["product_status"].(map[string]any)
	if _, ok := ps["known_affected"]; !ok {
		t.Errorf("product_status missing known_affected: %+v", ps)
	}
}

func TestFindingCSAF_omitsCVEWhenAbsent(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.CVEID = ""
		f.CVSSVector = ""
		f.CVSSScore = 0
	})
	w := getCSAF(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	v := doc["vulnerabilities"].([]any)[0].(map[string]any)
	if _, ok := v["cve"]; ok {
		t.Errorf("cve must be omitted when empty: %+v", v)
	}
	tracking := doc["document"].(map[string]any)["tracking"].(map[string]any)
	if tracking["id"] != "scrutineer-finding-"+strconv.FormatUint(uint64(f.ID), 10) {
		t.Errorf("tracking id = %v", tracking["id"])
	}
}

func TestFindingCSAF_rejectedMapsToNotAffected(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.Status = db.FindingRejected
		f.Boundary = "Sink unreachable from any network surface."
	})
	w := getCSAF(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	v := doc["vulnerabilities"].([]any)[0].(map[string]any)
	ps := v["product_status"].(map[string]any)
	if _, ok := ps["known_not_affected"]; !ok {
		t.Fatalf("known_not_affected expected: %+v", ps)
	}
	flags := v["flags"].([]any)
	if flags[0].(map[string]any)["label"] != csafJustificationControlledByAdversary {
		t.Errorf("flag = %+v", flags[0])
	}
}

func TestFindingCSAF_fixedHasRemediation(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.Status = db.FindingFixed
		f.FixVersion = "1.4.2"
		f.FixCommit = "abc123"
	})
	w := getCSAF(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	v := doc["vulnerabilities"].([]any)[0].(map[string]any)
	if _, ok := v["product_status"].(map[string]any)["fixed"]; !ok {
		t.Errorf("missing fixed bucket: %+v", v["product_status"])
	}
	rem := v["remediations"].([]any)[0].(map[string]any)
	if rem["category"] != "vendor_fix" {
		t.Errorf("rem category = %v", rem["category"])
	}
	if !strings.Contains(rem["details"].(string), "1.4.2") {
		t.Errorf("rem details = %v", rem["details"])
	}
	if !strings.Contains(rem["url"].(string), "abc123") {
		t.Errorf("rem url = %v", rem["url"])
	}
}

func TestFindingCSAF_404ForMissingFinding(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w := getCSAF(t, s, 99999)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", w.Code)
	}
}

func TestFindingCSAF_malformedCVSSVectorIsOmitted(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.CVSSVector = "not-a-vector"
		f.CVSSScore = 5.0
		f.Severity = "Medium"
	})
	w := getCSAF(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	v := doc["vulnerabilities"].([]any)[0].(map[string]any)
	if _, ok := v["scores"]; ok {
		t.Errorf("scores must be omitted when vector is malformed: %+v", v["scores"])
	}
}

func TestFindingCSAF_emitsAuditNotes(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.Trace = "trace text"
		f.Boundary = "boundary text"
		f.Reach = "reach text"
	})
	w := getCSAF(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	v := doc["vulnerabilities"].([]any)[0].(map[string]any)
	notes := v["notes"].([]any)
	titles := map[string]bool{}
	for _, n := range notes {
		titles[n.(map[string]any)["title"].(string)] = true
	}
	for _, want := range []string{"trace", "boundary", "reach"} {
		if !titles[want] {
			t.Errorf("missing note %q in %+v", want, titles)
		}
	}
}

func TestFindingCSAF_workaroundResolutionAddsRemediation(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, func(f *db.Finding) {
		f.Status = db.FindingTriaged
		f.Resolution = db.ResolutionWorkaround
		f.Trace = "Disable feature X via config flag."
	})
	w := getCSAF(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	v := doc["vulnerabilities"].([]any)[0].(map[string]any)
	rem := v["remediations"].([]any)
	var workaround map[string]any
	for _, r := range rem {
		m := r.(map[string]any)
		if m["category"] == "workaround" {
			workaround = m
			break
		}
	}
	if workaround == nil {
		t.Fatalf("workaround remediation missing: %+v", rem)
	}
	if !strings.Contains(workaround["details"].(string), "Disable feature X") {
		t.Errorf("workaround details = %v", workaround["details"])
	}
}

func TestFindingCSAF_referencesMappedFromFindingRefs(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f := seedCSAFFinding(t, s, nil)
	s.DB.Create(&db.FindingReference{FindingID: f.ID, URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-0001", Tags: "cve", Summary: "NVD"})
	s.DB.Create(&db.FindingReference{FindingID: f.ID, URL: "https://github.com/example/lib/pull/42", Tags: "pr"})

	w := getCSAF(t, s, f.ID)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	doc := decodeCSAF(t, w.Body.Bytes())
	v := doc["vulnerabilities"].([]any)[0].(map[string]any)
	refs := v["references"].([]any)
	if len(refs) != 2 {
		t.Fatalf("references = %d, want 2", len(refs))
	}
	urls := map[string]string{}
	for _, r := range refs {
		m := r.(map[string]any)
		if m["category"] != "external" {
			t.Errorf("category = %v", m["category"])
		}
		urls[m["url"].(string)], _ = m["summary"].(string)
	}
	if urls["https://nvd.nist.gov/vuln/detail/CVE-2026-0001"] != "NVD" {
		t.Errorf("NVD summary missing: %+v", urls)
	}
	if urls["https://github.com/example/lib/pull/42"] != "pr" {
		t.Errorf("PR summary should fall back to Tags: %+v", urls)
	}
}

func TestCSAFProductSuffix(t *testing.T) {
	cases := []struct {
		name string
		in   db.Finding
		want string
	}{
		{"uses FindingID when set", db.Finding{ID: 7, FindingID: "F3"}, "F3"},
		{"falls back to numeric ID", db.Finding{ID: 7, FindingID: ""}, "7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := csafProductSuffix(tc.in); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseCVSSv3Vector(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		want   *csafCVSSv3
		isNil  bool
		checks func(*testing.T, *csafCVSSv3)
	}{
		{
			name: "full v3.1",
			in:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			checks: func(t *testing.T, c *csafCVSSv3) {
				if c.Version != "3.1" || c.AttackVector != wantAttackVectorNetwork || c.AttackComplexity != "LOW" {
					t.Errorf("parsed = %+v", c)
				}
				if c.Scope != "UNCHANGED" || c.AvailabilityImpact != "HIGH" {
					t.Errorf("parsed = %+v", c)
				}
			},
		},
		{
			name: "v3.0 prefix",
			in:   "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N",
			checks: func(t *testing.T, c *csafCVSSv3) {
				if c.Version != "3.0" {
					t.Errorf("version = %q", c.Version)
				}
				if c.AttackVector != "LOCAL" || c.UserInteraction != "REQUIRED" || c.AvailabilityImpact != "NONE" {
					t.Errorf("parsed = %+v", c)
				}
			},
		},
		{
			name:  "missing prefix",
			in:    "AV:N/AC:L",
			isNil: true,
		},
		{
			name: "unknown keys ignored",
			in:   "CVSS:3.1/XX:Y/AV:N",
			checks: func(t *testing.T, c *csafCVSSv3) {
				if c.AttackVector != wantAttackVectorNetwork {
					t.Errorf("parsed = %+v", c)
				}
			},
		},
		{
			name: "duplicate keys: last wins",
			in:   "CVSS:3.1/AV:L/AV:N",
			checks: func(t *testing.T, c *csafCVSSv3) {
				if c.AttackVector != wantAttackVectorNetwork {
					t.Errorf("AV = %q", c.AttackVector)
				}
			},
		},
		{
			name:  "no key/value pairs",
			in:    "CVSS:3.1",
			isNil: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCVSSv3Vector(tc.in)
			if tc.isNil {
				if got != nil {
					t.Fatalf("want nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("got nil")
			}
			if tc.checks != nil {
				tc.checks(t, got)
			}
		})
	}
}
