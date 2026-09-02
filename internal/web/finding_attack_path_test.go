package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

const criticReportFixture = `{"production_viability":"NON_VIABLE","source_state":"PRESENT","reason":"The release target excludes tools/poc.c and no shipped target links it.","counterevidence":["tests compile the helper"],"attacker_position":"local test runner","preconditions":["build the test target"],"impact":"test process aborts","likelihood":"unlikely","applied_adjustments":[],"facts_that_would_change_the_result":["a release target links tools/poc.c"]}`

func TestFindingShowRendersAttackPathAndBlocksDisclosure(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/example/project", Name: "project"}
	s.DB.Create(&repo)
	parent := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&parent)
	f := db.Finding{ScanID: parent.ID, RepositoryID: repo.ID, Title: "test-only crash", Severity: "High", Status: db.FindingTriaged, ProductionViability: db.ProductionViabilityNonViable}
	s.DB.Create(&f)
	criticScan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: criticSkillName, FindingID: new(f.ID)}
	s.DB.Create(&criticScan)
	s.DB.Create(&db.FindingAttackPath{FindingID: f.ID, ScanID: criticScan.ID, ProductionViability: db.ProductionViabilityNonViable, Report: criticReportFixture})
	s.DB.Create(&db.Skill{Name: discloseSkillName, OutputFile: "report.json", OutputKind: "disclose", Version: 1, Active: true})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d", f.ID)))
	if w.Code != http.StatusOK {
		t.Fatalf("GET status = %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{"Production viability history", "NON_VIABLE", "Release path ruled out", "release target excludes", "Disclosure blocked"} {
		if !strings.Contains(body, want) {
			t.Errorf("finding page missing %q", want)
		}
	}

	w = postForm(t, s, fmt.Sprintf("/findings/%d/disclose", f.ID), nil)
	if w.Code != http.StatusPreconditionFailed || !strings.Contains(w.Body.String(), "NON_VIABLE") {
		t.Fatalf("disclose status = %d, body=%s; want 412 NON_VIABLE", w.Code, w.Body)
	}
	var count int64
	s.DB.Model(&db.Scan{}).Where("finding_id = ? AND skill_name = ?", f.ID, discloseSkillName).Count(&count)
	if count != 0 {
		t.Fatalf("disclose scans = %d, want 0", count)
	}
}

func TestNonViableFindingCannotTransitionToReported(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedFindingForForm(t, s)
	if err := s.DB.Model(&f).Updates(map[string]any{
		"status": db.FindingReady, "production_viability": db.ProductionViabilityNonViable,
	}).Error; err != nil {
		t.Fatal(err)
	}
	w := postForm(t, s, fmt.Sprintf("/findings/%d/status", f.ID), url.Values{"status": {string(db.FindingReported)}})
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412; body=%s", w.Code, w.Body)
	}
	var got db.Finding
	s.DB.First(&got, f.ID)
	if got.Status != db.FindingReady {
		t.Fatalf("finding status = %q, want ready", got.Status)
	}
}

func TestNonViableFindingCannotTransitionToReady(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedFindingForForm(t, s)
	if err := s.DB.Model(&f).Updates(map[string]any{
		"status": db.FindingTriaged, "disclosure_draft": "reviewed draft",
		"production_viability": db.ProductionViabilityNonViable,
	}).Error; err != nil {
		t.Fatal(err)
	}
	w := postForm(t, s, fmt.Sprintf("/findings/%d/status", f.ID), url.Values{"status": {string(db.FindingReady)}})
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412; body=%s", w.Code, w.Body)
	}
	var got db.Finding
	s.DB.First(&got, f.ID)
	if got.Status != db.FindingTriaged {
		t.Fatalf("finding status = %q, want triaged", got.Status)
	}
}

func TestAPINonViableFindingCannotEnterReportingStates(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, token, _ := seedFindingForAPI(t, s)
	s.DB.Model(&f).Update("production_viability", db.ProductionViabilityNonViable)
	if err := s.DB.Model(&db.Scan{}).Where("api_token = ?", token).
		Update("finding_id", f.ID).Error; err != nil {
		t.Fatal(err)
	}
	for _, status := range []db.FindingLifecycle{db.FindingReady, db.FindingReported} {
		t.Run(string(status), func(t *testing.T) {
			body := fmt.Sprintf(`{"fields":{"status":%q},"by":"report-upstream"}`, status)
			w := apiReq(t, s, http.MethodPatch, fmt.Sprintf("/api/findings/%d", f.ID), token, body)
			if w.Code != http.StatusPreconditionFailed || !strings.Contains(w.Body.String(), "NON_VIABLE") {
				t.Fatalf("status = %d, body=%s; want 412 NON_VIABLE", w.Code, w.Body)
			}
		})
	}
}

func TestNonViableFindingCannotEnqueuePublicIssue(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedFindingForForm(t, s)
	if err := s.DB.Model(&f).Updates(map[string]any{
		"status": db.FindingReady, "severity": "Low",
		"production_viability": db.ProductionViabilityNonViable,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&db.Skill{
		Name: publicIssueSkillName, OutputFile: "report.json", OutputKind: "freeform", Version: 1, Active: true,
	}).Error; err != nil {
		t.Fatal(err)
	}
	w := postForm(t, s, fmt.Sprintf("/findings/%d/public-issue", f.ID), nil)
	if w.Code != http.StatusPreconditionFailed || !strings.Contains(w.Body.String(), "NON_VIABLE") {
		t.Fatalf("status = %d, body=%s; want 412 NON_VIABLE", w.Code, w.Body)
	}
	var count int64
	s.DB.Model(&db.Scan{}).Where("finding_id = ? AND skill_name = ?", f.ID, publicIssueSkillName).Count(&count)
	if count != 0 {
		t.Fatalf("public-issue scans = %d, want 0", count)
	}
}

func TestFindingsProductionViabilityFilter(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "shipping finding", Severity: "High", ProductionViability: db.ProductionViabilityViable})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "test-only finding", Severity: "High", ProductionViability: db.ProductionViabilityNonViable})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "unassessed finding", Severity: "High"})

	for query, expected := range map[string][2]string{
		"NON_VIABLE": {"test-only finding", "shipping finding"},
		"unassessed": {"unassessed finding", "test-only finding"},
	} {
		want, absent := expected[0], expected[1]
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq(http.MethodGet, "/findings?viability="+query))
		if w.Code != http.StatusOK {
			t.Fatalf("%s status = %d: %s", query, w.Code, w.Body)
		}
		body := w.Body.String()
		if !strings.Contains(body, want) || strings.Contains(body, absent) {
			t.Errorf("filter %s body did not include %q and exclude %q", query, want, absent)
		}
	}
}

func TestEnsureFindingReportableBlocksExternalReportingSkills(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedFindingForForm(t, s)
	s.DB.Model(&f).Update("production_viability", db.ProductionViabilityNonViable)
	for _, skill := range []string{discloseSkillName, reportUpstreamSkillName, publicIssueSkillName} {
		if err := s.ensureFindingReportable(f.ID, skill); !errors.Is(err, db.ErrFindingNonViable) {
			t.Errorf("%s error = %v, want %q", skill, err, db.ErrFindingNonViable)
		}
	}
}
