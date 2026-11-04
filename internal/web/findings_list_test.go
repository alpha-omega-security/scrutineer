package web

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

// TestFindingsListDropsSummaryAndShowsCWECategory pins the findings list to the
// title alone, the scan page excerpt to escaped text without backticks, and the CWE cell to
// the leaf ID plus its category name.
func TestFindingsListDropsSummaryAndShowsCWECategory(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "SQL in export", Severity: "High",
		CWE: "CWE-89", Trace: "`buildQuery` formats the column list.\n\nSecond paragraph."})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "Unmapped weakness", Severity: "Low",
		CWE: "CWE-999999", Trace: "Echoes <input value=x> back."})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, "/findings"))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if strings.Contains(body, "buildQuery") {
		t.Error("findings list still shows the trace excerpt under the title")
	}
	if !strings.Contains(body, ">Injection</div>") {
		t.Error("CWE-89 does not show its Injection category")
	}
	if strings.Contains(body, "CWE-1409 ›") {
		t.Error("CWE cell still shows the category's CWE ID")
	}
	if !strings.Contains(body, ">CWE-999999</span>") {
		t.Error("an uncatalogued CWE is not shown on its own")
	}

	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, "/scans/"+strconv.FormatUint(uint64(scan.ID), 10)))
	if w.Code != http.StatusOK {
		t.Fatalf("scan status = %d: %s", w.Code, w.Body)
	}
	body = w.Body.String()
	if !strings.Contains(body, "buildQuery formats the column list.") {
		t.Error("scan page summary does not show the first paragraph without backticks")
	}
	if strings.Contains(body, "`buildQuery`") || strings.Contains(body, "Second paragraph.") {
		t.Error("scan page summary shows raw markdown or more than the first paragraph")
	}
	if !strings.Contains(body, "Echoes &lt;input value=x&gt; back.") {
		t.Error("scan page summary drops or unescapes an HTML tag it names")
	}
}
