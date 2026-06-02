package web

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

// TestFindingReport_scopedToSingleFinding exercises the per-finding markdown
// export (#299): a scan with a High and a Medium finding should produce a
// report for just the requested finding, not both.
func TestFindingReport_scopedToSingleFinding(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedScanWithFindings(t, s)

	var high db.Finding
	if err := s.DB.Where("scan_id = ? AND severity = ?", scan.ID, "High").First(&high).Error; err != nil {
		t.Fatalf("seed high finding: %v", err)
	}

	path := "/findings/" + strconv.FormatUint(uint64(high.ID), 10) + "/report.md"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", path))

	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("content-type = %q", ct)
	}
	// Filename should encode the repo and finding id so a directory of
	// downloaded reports stays unambiguous without renaming.
	cd := w.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".md") {
		t.Errorf("content-disposition = %q", cd)
	}
	if !strings.Contains(cd, "finding-"+strconv.FormatUint(uint64(high.ID), 10)) {
		t.Errorf("content-disposition missing finding id in filename: %q", cd)
	}

	body := w.Body.String()
	wants := []string{
		repo.FullName + " — finding #",
		repo.FullName,
		"### Finding #",
		"python.lang.security.use-defused-xml",
		"#### Trace",
		"xml.etree.ElementTree is vulnerable to XXE",
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\nbody:\n%s", want, body)
		}
	}

	// The Medium finding from the same scan must NOT appear — the report is
	// scoped to a single finding, unlike the scan report.
	if strings.Contains(body, "generic.html-templates.security.var-in-href") {
		t.Errorf("report should be scoped to one finding, but the other finding leaked in:\n%s", body)
	}
	// No scan-level "## Findings" summary section — this is a single finding.
	if strings.Contains(body, "## Findings") {
		t.Errorf("single-finding report should not have a Findings summary section:\n%s", body)
	}
}

func TestFindingReport_notFoundForMissingFinding(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings/999999/report.md"))
	if w.Code != 404 {
		t.Errorf("status = %d, want 404", w.Code)
	}
}
