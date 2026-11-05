package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/verification"
)

func seedVerificationFeedback(t *testing.T, s *Server) db.Finding {
	t.Helper()
	repo := db.Repository{URL: "https://example.com/feedback", Name: "feedback"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	skill := db.Skill{Name: verifySkillName, Active: true, Source: "ui", Body: "verify", OutputKind: "verify", OutputFile: "report.json"}
	if err := s.DB.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	original := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	if err := s.DB.Create(&original).Error; err != nil {
		t.Fatal(err)
	}
	finding := db.Finding{RepositoryID: repo.ID, ScanID: original.ID, Title: "Parser issue", Status: db.FindingEnriched, Validation: "original reproduction", Severity: "High"}
	if err := s.DB.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}
	old := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillID: &skill.ID, SkillName: verifySkillName, FindingID: &finding.ID, VerificationFeedback: "old feedback"}
	if err := s.DB.Create(&old).Error; err != nil {
		t.Fatal(err)
	}
	row := db.FindingVerification{FindingID: finding.ID, ScanID: old.ID, Status: "inconclusive", Report: `{"status":"inconclusive"}`}
	if err := s.DB.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	return finding
}

func TestVerifyRerunFeedback(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedVerificationFeedback(t, s)
	path := fmt.Sprintf("/findings/%d/verify", f.ID)
	feedback := "Check the first-party parser, not <script>alert(1)</script>."
	out := postForm(t, s, path, url.Values{"feedback": {" " + feedback + "\n"}})
	if out.Code != http.StatusSeeOther {
		t.Fatalf("enqueue: %d %s", out.Code, out.Body)
	}
	var scan db.Scan
	if err := s.DB.Where("finding_id = ? AND status = ?", f.ID, db.ScanQueued).First(&scan).Error; err != nil {
		t.Fatal(err)
	}
	if scan.VerificationFeedback != feedback || scan.SessionID != "" {
		t.Fatalf("incorrect fresh run: %+v", scan)
	}
	duplicate := postForm(t, s, path, url.Values{"feedback": {"replacement"}})
	if duplicate.Header().Get("Location") != out.Header().Get("Location") {
		t.Fatal("duplicate request did not redirect to the existing run")
	}
	assertQueuedJobCount(t, s, 1)
	if err := s.DB.First(&scan, scan.ID).Error; err != nil || scan.VerificationFeedback != feedback {
		t.Fatalf("duplicate request changed feedback: %v", err)
	}
	var unchanged db.Finding
	if err := s.DB.First(&unchanged, f.ID).Error; err != nil || unchanged.Status != f.Status || unchanged.Validation != f.Validation {
		t.Fatalf("rerun mutated finding: %+v err=%v", unchanged, err)
	}
	views, err := loadFindingVerificationViews(s.DB, f.ID)
	if err != nil || len(views) != 1 || views[0].VerificationFeedback != "old feedback" {
		t.Fatalf("previous verification changed: %+v err=%v", views, err)
	}
	if scanSummary(scan)["verification_feedback"] != feedback || scanExport(scan)["verification_feedback"] != feedback {
		t.Fatal("scan APIs omitted feedback")
	}
	page := httptest.NewRecorder()
	s.Handler().ServeHTTP(page, localReq(http.MethodGet, fmt.Sprintf("/scans/%d", scan.ID)))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "&lt;script&gt;") || strings.Contains(page.Body.String(), "<script>alert(1)</script>") {
		t.Fatal("scan feedback missing or not escaped")
	}
	body := page.Body.String()
	crumbsEnd := strings.Index(body, "</ol>")
	heading := strings.Index(body, "<h2")
	feedbackHeading := strings.Index(body, ">Verification feedback</h3>")
	if crumbsEnd < 0 || heading < crumbsEnd || feedbackHeading < heading {
		t.Fatal("scan feedback should follow the breadcrumbs and page heading")
	}
	if err := s.DB.Model(&scan).Update("status", db.ScanDone).Error; err != nil {
		t.Fatal(err)
	}
	out = postForm(t, s, path, url.Values{})
	var fresh db.Scan
	if err := s.DB.Where("finding_id = ? AND status = ?", f.ID, db.ScanQueued).First(&fresh).Error; err != nil || out.Code != http.StatusSeeOther || fresh.ID == scan.ID || fresh.VerificationFeedback != "" {
		t.Fatalf("new blank rerun inherited feedback: %+v err=%v", fresh, err)
	}
}

func TestVerifyFeedbackInvalidInput(t *testing.T) {
	for _, body := range []string{
		"feedback=" + strings.Repeat("x", verification.MaxFeedbackBytes+1),
		"feedback=%FF", "feedback=%zz", "feedback=" + strings.Repeat("x", 33<<10),
	} {
		s, done := newTestServer(t)
		f := seedVerificationFeedback(t, s)
		r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/findings/%d/verify", f.ID), strings.NewReader(body))
		asOperator(r)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("invalid form: status=%d", w.Code)
		}
		assertQueuedJobCount(t, s, 0)
		done()
	}
}

func TestVerificationFeedbackRetries(t *testing.T) {
	for _, bulk := range []bool{false, true} {
		t.Run(fmt.Sprint(bulk), func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			f := seedVerificationFeedback(t, s)
			var old db.Scan
			if err := s.DB.Where("finding_id = ?", f.ID).First(&old).Error; err != nil {
				t.Fatal(err)
			}
			if err := s.DB.Model(&old).Update("status", db.ScanFailed).Error; err != nil {
				t.Fatal(err)
			}
			path := fmt.Sprintf("/scans/%d/retry", old.ID)
			if bulk {
				path = "/scans/retry-failed"
			}
			out := postForm(t, s, path, url.Values{})
			var fresh db.Scan
			if err := s.DB.Where("parent_scan_id = ?", old.ID).First(&fresh).Error; err != nil || out.Code != http.StatusSeeOther || fresh.VerificationFeedback != old.VerificationFeedback {
				t.Fatalf("retry dropped feedback: %+v status=%d err=%v", fresh, out.Code, err)
			}
		})
	}
}

func TestVerifyFeedbackFormAfterVerification(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedVerificationFeedback(t, s)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d", f.ID)))
	if w.Code != http.StatusOK {
		t.Fatalf("finding page: %d", w.Code)
	}
	for _, want := range []string{fmt.Sprintf(`action="/findings/%d/verify" hx-post="/findings/%d/verify" hx-swap="none"`, f.ID, f.ID), `name="feedback"`, "<span>1 result</span>", "Rerun verification", "old feedback", "Verification history"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
	out := postForm(t, s, fmt.Sprintf("/findings/%d/verify", f.ID), url.Values{})
	if out.Code != http.StatusSeeOther {
		t.Fatalf("verify: %d", out.Code)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d", f.ID)))
	if !strings.Contains(w.Body.String(), `maxlength="4000" disabled`) || !strings.Contains(w.Body.String(), "Verification in progress") {
		t.Fatal("queued verification did not disable the feedback form")
	}
}

func TestVerifyFeedbackFormForNewFinding(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedVerificationFeedback(t, s)
	if err := s.DB.Model(&f).Update("status", db.FindingNew).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Where("finding_id = ?", f.ID).Delete(&db.FindingVerification{}).Error; err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d", f.ID)))
	if w.Code != http.StatusOK {
		t.Fatalf("finding page: %d", w.Code)
	}
	body := w.Body.String()
	for _, attr := range []string{"action", "hx-post"} {
		if count := strings.Count(body, fmt.Sprintf(`%s="/findings/%d/verify"`, attr, f.ID)); count != 1 {
			t.Errorf("verify %s count = %d, want one feedback-enabled entry point", attr, count)
		}
	}
	for _, want := range []string{`name="feedback"`, "<span>no results</span>", "Run verification", "Mark triaged", "Reject"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestVerifyFeedbackHTMXRedirect(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedVerificationFeedback(t, s)
	feedback := "Check the parser entry point"
	var location string
	for range 2 {
		r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/findings/%d/verify", f.ID), strings.NewReader(url.Values{"feedback": {feedback}}.Encode()))
		asOperator(r)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("HX-Request", "true")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusNoContent || !strings.HasPrefix(w.Header().Get("HX-Redirect"), "/scans/") {
			t.Fatalf("htmx enqueue: %d %s headers=%v", w.Code, w.Body, w.Header())
		}
		if location != "" && w.Header().Get("HX-Redirect") != location {
			t.Fatal("duplicate htmx request did not redirect to the existing run")
		}
		location = w.Header().Get("HX-Redirect")
	}
	assertQueuedJobCount(t, s, 1)
	var scan db.Scan
	if err := s.DB.Where("finding_id = ? AND status = ?", f.ID, db.ScanQueued).First(&scan).Error; err != nil || scan.VerificationFeedback != feedback {
		t.Fatalf("htmx request dropped feedback: %+v err=%v", scan, err)
	}
}

func TestVerificationFeedbackScope(t *testing.T) {
	for _, tc := range []struct {
		skill   string
		finding *uint
	}{
		{"verify", nil}, {"critic", new(uint(1))},
	} {
		opts := ScanOpts{FindingID: tc.finding, VerificationFeedback: "check parser"}
		if err := normalizeVerificationOpts(&opts, tc.skill); err == nil {
			t.Fatal("accepted feedback outside finding-scoped verify")
		}
	}
}
