package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestFindingRejectionRequiresDecisionAndReason(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, _ := seedAuditFixture(t, s)
	for _, form := range []url.Values{
		{statusKey: {"rejected"}},
		{statusKey: {"rejected"}, "verdict": {"false_positive"}, "reason": {" \n"}},
		{statusKey: {"rejected"}, "verdict": {"true_positive"}, "reason": {"reason"}},
	} {
		if w := postFindingStatus(t, s, f.ID, form); w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d: %s", w.Code, w.Body)
		}
	}
	w := postFindingStatus(t, s, f.ID, url.Values{statusKey: {"rejected"}, "verdict": {"false_positive"}, "reason": {"guard verified at parser.go:10"}, "reviewer": {"analyst"}})
	if w.Code >= 400 {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	reviews, err := db.ListFindingReviews(s.DB, f.ID)
	if err != nil || len(reviews) != 1 || reviews[0].Reviewer != "analyst" || reviews[0].SourceScanID != f.ScanID {
		t.Fatalf("reviews = %+v, %v", reviews, err)
	}
	if err := s.DB.First(&f, f.ID).Error; err != nil {
		t.Fatal(err)
	}
	if f.Status != db.FindingRejected {
		t.Fatalf("status = %s", f.Status)
	}
}

func TestFindingRejectionDatabaseError(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, _ := seedAuditFixture(t, s)
	if err := s.DB.Exec("CREATE TRIGGER fail_review BEFORE INSERT ON finding_reviews BEGIN SELECT RAISE(ABORT, 'forced'); END").Error; err != nil {
		t.Fatal(err)
	}
	w := postFindingStatus(t, s, f.ID, url.Values{statusKey: {"rejected"}, "verdict": {"false_positive"}, "reason": {"guarded"}})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	if err := s.DB.First(&f, f.ID).Error; err != nil {
		t.Fatal(err)
	}
	if f.Status == db.FindingRejected {
		t.Fatal("rejected despite failed review persistence")
	}
}

func TestFindingRejectionDialog(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, _ := seedAuditFixture(t, s)
	r := httptest.NewRequest(http.MethodGet, "/findings/"+strconv.FormatUint(uint64(f.ID), 10), nil)
	r.Host = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	for _, want := range []string{`data-dialog="reject-`, `name="verdict" required`, `name="reason" rows="3" maxlength="4096" required`, `Other / not actionable`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
}
