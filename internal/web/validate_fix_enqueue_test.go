package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

type validateFixFixture struct {
	s          *Server
	repoID     uint
	baselineID uint
	deepDiveID uint
	verifyID   uint
	f1, f2     db.Finding
}

// validateFixSetup builds a repo with an active deep-dive and verify skill, a
// done baseline deep-dive scan, and two findings under it — the starting state
// a fix-validation run acts on.
func validateFixSetup(t *testing.T) (validateFixFixture, func()) {
	t.Helper()
	s, done := newTestServer(t)
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	deepdive := db.Skill{Name: deepDiveSkillName, OutputFile: "report.json", OutputKind: "findings", Version: 1, Active: true}
	verify := db.Skill{Name: verifySkillName, OutputFile: "report.json", OutputKind: "verify", Version: 1, Active: true}
	s.DB.Create(&deepdive)
	s.DB.Create(&verify)
	baseline := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, SkillID: &deepdive.ID, SkillName: deepDiveSkillName}
	s.DB.Create(&baseline)
	f1 := db.Finding{ScanID: baseline.ID, RepositoryID: repo.ID, Title: "f1", Severity: "High", Fingerprint: "fp1", Status: db.FindingNew}
	f2 := db.Finding{ScanID: baseline.ID, RepositoryID: repo.ID, Title: "f2", Severity: "Critical", Fingerprint: "fp2", Status: db.FindingNew}
	s.DB.Create(&f1)
	s.DB.Create(&f2)
	return validateFixFixture{s, repo.ID, baseline.ID, deepdive.ID, verify.ID, f1, f2}, done
}

func validateFixPost(s *Server, repoID uint, ref string, findingIDs ...uint) *httptest.ResponseRecorder {
	form := url.Values{}
	if ref != "" {
		form.Set("ref", ref)
	}
	for _, id := range findingIDs {
		form.Add("finding_ids", strconv.FormatUint(uint64(id), 10))
	}
	r := httptest.NewRequest("POST", fmt.Sprintf("/repositories/%d/validate-fix", repoID), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func validationAnchorCount(s *Server) int64 {
	var n int64
	s.DB.Model(&db.Scan{}).Where("baseline_scan_id IS NOT NULL").Count(&n)
	return n
}

func TestValidateFix_happy(t *testing.T) {
	fx, done := validateFixSetup(t)
	defer done()

	w := validateFixPost(fx.s, fx.repoID, "fix-branch", fx.f1.ID, fx.f2.ID)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", w.Code, w.Body.String())
	}
	var anchor db.Scan
	if err := fx.s.DB.Where("repository_id = ? AND baseline_scan_id = ? AND ref = ?",
		fx.repoID, fx.baselineID, "fix-branch").First(&anchor).Error; err != nil {
		t.Fatalf("anchor scan not created: %v", err)
	}
	if anchor.SkillID == nil || *anchor.SkillID != fx.deepDiveID {
		t.Fatalf("anchor skill = %v, want deep-dive %d", anchor.SkillID, fx.deepDiveID)
	}
	if loc := w.Header().Get("Location"); loc != fmt.Sprintf("/scans/%d", anchor.ID) {
		t.Fatalf("redirect = %q, want /scans/%d", loc, anchor.ID)
	}
	var verifyCount int64
	fx.s.DB.Model(&db.Scan{}).
		Where("skill_id = ? AND ref = ? AND finding_id IN ?", fx.verifyID, "fix-branch", []uint{fx.f1.ID, fx.f2.ID}).
		Count(&verifyCount)
	if verifyCount != 2 {
		t.Fatalf("verify-against-ref scans = %d, want 2", verifyCount)
	}
}

func TestValidateFix_rejects(t *testing.T) {
	t.Run("missing ref", func(t *testing.T) {
		fx, done := validateFixSetup(t)
		defer done()
		w := validateFixPost(fx.s, fx.repoID, "", fx.f1.ID)
		assertValidateFixRejected(t, fx.s, w, fx.repoID)
	})
	t.Run("invalid ref", func(t *testing.T) {
		fx, done := validateFixSetup(t)
		defer done()
		w := validateFixPost(fx.s, fx.repoID, "--bad ref", fx.f1.ID)
		assertValidateFixRejected(t, fx.s, w, fx.repoID)
	})
	t.Run("no finding ids", func(t *testing.T) {
		fx, done := validateFixSetup(t)
		defer done()
		w := validateFixPost(fx.s, fx.repoID, "fix-branch")
		assertValidateFixRejected(t, fx.s, w, fx.repoID)
	})
	t.Run("finding not on repo", func(t *testing.T) {
		fx, done := validateFixSetup(t)
		defer done()
		w := validateFixPost(fx.s, fx.repoID, "fix-branch", fx.f1.ID, 999999)
		assertValidateFixRejected(t, fx.s, w, fx.repoID)
	})
	t.Run("findings from different scans", func(t *testing.T) {
		fx, done := validateFixSetup(t)
		defer done()
		other := db.Scan{RepositoryID: fx.repoID, Status: db.ScanDone, SkillID: &fx.deepDiveID, SkillName: deepDiveSkillName}
		fx.s.DB.Create(&other)
		stray := db.Finding{ScanID: other.ID, RepositoryID: fx.repoID, Title: "stray", Severity: "Low", Fingerprint: "fpx"}
		fx.s.DB.Create(&stray)
		w := validateFixPost(fx.s, fx.repoID, "fix-branch", fx.f1.ID, stray.ID)
		assertValidateFixRejected(t, fx.s, w, fx.repoID)
	})
	t.Run("baseline scan has no skill", func(t *testing.T) {
		fx, done := validateFixSetup(t)
		defer done()
		noSkill := db.Scan{RepositoryID: fx.repoID, Status: db.ScanDone, SkillName: "import"}
		fx.s.DB.Create(&noSkill)
		imported := db.Finding{ScanID: noSkill.ID, RepositoryID: fx.repoID, Title: "imp", Severity: "Low", Fingerprint: "fpi"}
		fx.s.DB.Create(&imported)
		w := validateFixPost(fx.s, fx.repoID, "fix-branch", imported.ID)
		assertValidateFixRejected(t, fx.s, w, fx.repoID)
	})
}

func assertValidateFixRejected(t *testing.T, s *Server, w *httptest.ResponseRecorder, repoID uint) {
	t.Helper()
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 redirect; body=%s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != fmt.Sprintf("/repositories/%d", repoID) {
		t.Fatalf("redirect = %q, want repo page /repositories/%d", loc, repoID)
	}
	if n := validationAnchorCount(s); n != 0 {
		t.Fatalf("rejected request still created %d anchor scan(s)", n)
	}
}

func TestAutoComputeFixValidation_writesReport(t *testing.T) {
	fx, done := validateFixSetup(t)
	defer done()

	anchor := db.Scan{RepositoryID: fx.repoID, Status: db.ScanDone, SkillName: deepDiveSkillName, Ref: "fix", BaselineScanID: &fx.baselineID}
	fx.s.DB.Create(&anchor)
	// f1 survived (re-observed by the anchor), f2 resolved (not re-observed).
	fx.s.DB.Model(&db.Finding{}).Where("id = ?", fx.f1.ID).Update("last_seen_scan_id", anchor.ID)
	fx.s.DB.Model(&db.Finding{}).Where("id = ?", fx.f2.ID).Update("last_seen_scan_id", fx.baselineID)
	newF := db.Finding{ScanID: anchor.ID, RepositoryID: fx.repoID, Title: "new on fix ref", Severity: "Medium", Fingerprint: "fpnew"}
	fx.s.DB.Create(&newF)
	verifyScan := db.Scan{RepositoryID: fx.repoID, Status: db.ScanDone, SkillName: verifySkillName, Ref: "fix", FindingID: &fx.f1.ID, Report: `{"status":"confirmed"}`}
	fx.s.DB.Create(&verifyScan)

	fx.s.autoComputeFixValidation(&anchor)

	var reloaded db.Scan
	fx.s.DB.First(&reloaded, anchor.ID)
	var rep fixValidationReport
	if err := json.Unmarshal([]byte(reloaded.Report), &rep); err != nil {
		t.Fatalf("report is not valid JSON: %v; report=%q", err, reloaded.Report)
	}
	if (rep.Counts != fixValidationCounts{Resolved: 1, Surviving: 1, New: 1}) {
		t.Fatalf("counts = %+v, want {1 1 1}", rep.Counts)
	}
	if len(rep.Resolved) != 1 || rep.Resolved[0].FindingID != fx.f2.ID {
		t.Fatalf("resolved = %+v, want [f2 id=%d]", rep.Resolved, fx.f2.ID)
	}
	if len(rep.Surviving) != 1 || rep.Surviving[0].FindingID != fx.f1.ID {
		t.Fatalf("surviving = %+v, want [f1 id=%d]", rep.Surviving, fx.f1.ID)
	}
	if len(rep.Verify) != 1 || rep.Verify[0].FindingID != fx.f1.ID || rep.Verify[0].Status != "confirmed" {
		t.Fatalf("verify = %+v, want [f1 confirmed]", rep.Verify)
	}
}

func TestAutoComputeFixValidation_pendingVerify(t *testing.T) {
	fx, done := validateFixSetup(t)
	defer done()
	anchor := db.Scan{RepositoryID: fx.repoID, Status: db.ScanDone, SkillName: deepDiveSkillName, Ref: "fix", BaselineScanID: &fx.baselineID}
	fx.s.DB.Create(&anchor)
	// A verify against the fix ref that has not finished yet.
	verifyScan := db.Scan{RepositoryID: fx.repoID, Status: db.ScanRunning, SkillName: verifySkillName, Ref: "fix", FindingID: &fx.f1.ID}
	fx.s.DB.Create(&verifyScan)

	fx.s.autoComputeFixValidation(&anchor)

	var reloaded db.Scan
	fx.s.DB.First(&reloaded, anchor.ID)
	var rep fixValidationReport
	if err := json.Unmarshal([]byte(reloaded.Report), &rep); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if len(rep.Verify) != 1 || rep.Verify[0].Status != verifyStatusPending {
		t.Fatalf("verify = %+v, want [f1 pending]", rep.Verify)
	}
}

func TestAutoComputeFixValidation_ignoresOrdinaryScan(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, SkillName: deepDiveSkillName, Report: "untouched"}
	s.DB.Create(&scan)
	s.autoComputeFixValidation(&scan)
	var reloaded db.Scan
	s.DB.First(&reloaded, scan.ID)
	if reloaded.Report != "untouched" {
		t.Fatalf("ordinary scan report changed to %q", reloaded.Report)
	}
}

func TestAutoComputeFixValidation_nilScan(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.autoComputeFixValidation(nil)
}

// TestFixValidationAnchor_skipsAutoFunnel proves a validation anchor (a
// deep-dive re-run carrying BaselineScanID) does not feed its findings back
// into the revalidate or finding-dedup auto-funnel.
func TestFixValidationAnchor_skipsAutoFunnel(t *testing.T) {
	fx, done := validateFixSetup(t)
	defer done()
	dedup := db.Skill{Name: findingDedupSkillName, OutputFile: "report.json", OutputKind: "finding_dedup", Version: 1, Active: true}
	reval := db.Skill{Name: revalidateSkillName, OutputFile: "report.json", OutputKind: "revalidate", Version: 1, Active: true}
	fx.s.DB.Create(&dedup)
	fx.s.DB.Create(&reval)

	anchor := db.Scan{RepositoryID: fx.repoID, Status: db.ScanDone, SkillName: deepDiveSkillName, Ref: "fix", BaselineScanID: &fx.baselineID}
	fx.s.DB.Create(&anchor)
	anchorFinding := db.Finding{ScanID: anchor.ID, RepositoryID: fx.repoID, Title: "anchor finding", Severity: "Critical", Fingerprint: "afp"}
	fx.s.DB.Create(&anchorFinding)

	fx.s.autoEnqueueRevalidate(&anchor, &anchorFinding)
	fx.s.onScanFinalized(&anchor)

	var revalQ, dedupQ int64
	fx.s.DB.Model(&db.Scan{}).Where("skill_id = ? AND status = ?", reval.ID, db.ScanQueued).Count(&revalQ)
	fx.s.DB.Model(&db.Scan{}).Where("skill_id = ? AND status = ?", dedup.ID, db.ScanQueued).Count(&dedupQ)
	if revalQ != 0 || dedupQ != 0 {
		t.Fatalf("anchor scan triggered the auto-funnel: revalidate=%d dedup=%d, want 0/0", revalQ, dedupQ)
	}
}

func TestParseFindingIDs(t *testing.T) {
	form := func(values ...string) *http.Request {
		v := url.Values{}
		for _, val := range values {
			v.Add("finding_ids", val)
		}
		r := httptest.NewRequest("POST", "/x", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	got, err := parseFindingIDs(form("3", "1,2", "3"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 || got[0] != 3 || got[1] != 1 || got[2] != 2 {
		t.Fatalf("ids = %v, want [3 1 2] (split, de-duped, order-preserving)", got)
	}
	if _, err := parseFindingIDs(form()); err == nil {
		t.Fatal("empty finding_ids: expected error")
	}
	if _, err := parseFindingIDs(form("notanumber")); err == nil {
		t.Fatal("non-numeric finding id: expected error")
	}
}
