package web

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"testing"

	"scrutineer/internal/db"
)

func seedFindingForForm(t *testing.T, s *Server) db.Finding {
	t.Helper()
	repo := db.Repository{URL: "https://example.com/forms", Name: "forms"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "t",
		Severity: "High", Status: db.FindingNew}
	s.DB.Create(&f)
	return f
}

func TestFindingFields(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedFindingForForm(t, s)
	path := fmt.Sprintf("/findings/%d/fields", f.ID)

	w := postForm(t, s, path, url.Values{
		"severity":             {"Critical"},
		"cve_id":               {" CVE-2026-12345 "},
		"affected":             {">=1.0.0 <2.0.0"},
		"suggested_recipients": {"@alice (CODEOWNERS: crypto/*)"},
		"ignored":              {"x"}, // not in analystFields, dropped
		"resolution":           {""},  // present but unchanged, no-op
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", w.Code, w.Body)
	}
	if loc := w.Header().Get("Location"); loc != fmt.Sprintf("/findings/%d", f.ID) {
		t.Errorf("Location = %q", loc)
	}

	var got db.Finding
	s.DB.First(&got, f.ID)
	if got.Severity != "Critical" || got.CVEID != "CVE-2026-12345" || got.Affected != ">=1.0.0 <2.0.0" ||
		got.SuggestedRecipients != "@alice (CODEOWNERS: crypto/*)" {
		t.Errorf("after edit: severity=%q cve=%q affected=%q recipients=%q",
			got.Severity, got.CVEID, got.Affected, got.SuggestedRecipients)
	}
	var hist []db.FindingHistory
	s.DB.Where("finding_id = ?", f.ID).Find(&hist)
	if len(hist) != 4 {
		t.Errorf("history rows = %d, want 4 (severity, cve_id, affected, suggested_recipients)", len(hist))
	}
	for _, h := range hist {
		if h.Source != db.SourceAnalyst {
			t.Errorf("history source = %q, want analyst", h.Source)
		}
	}

	// validateFindingField surfaces as 422 and the bad value is not stored.
	w = postForm(t, s, path, url.Values{"ghsa_id": {"not-a-ghsa"}})
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("invalid ghsa_id: status = %d, want 422", w.Code)
	}
	s.DB.First(&got, f.ID)
	if got.GHSAID != "" {
		t.Errorf("GHSAID = %q, want empty (rejected value should not be stored)", got.GHSAID)
	}
	s.DB.Where("finding_id = ?", f.ID).Find(&hist)
	if len(hist) != 4 {
		t.Errorf("history rows after rejected write = %d, want still 4", len(hist))
	}

	if w := postForm(t, s, "/findings/999999/fields", url.Values{"severity": {"Low"}}); w.Code != http.StatusNotFound {
		t.Errorf("missing finding: status = %d, want 404", w.Code)
	}
}

func TestFindingFieldsAtomicRollback(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedFindingForForm(t, s)
	path := fmt.Sprintf("/findings/%d/fields", f.ID)

	w := postForm(t, s, path, url.Values{
		"cve_id":  {"CVE-2026-12345"},
		"ghsa_id": {"not-a-ghsa"},
	})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", w.Code, w.Body)
	}

	var got db.Finding
	s.DB.First(&got, f.ID)
	if got.CVEID != "" || got.GHSAID != "" {
		t.Fatalf("finding fields committed despite failed form: cve=%q ghsa=%q", got.CVEID, got.GHSAID)
	}
	var hist []db.FindingHistory
	s.DB.Where("finding_id = ?", f.ID).Find(&hist)
	if len(hist) != 0 {
		t.Fatalf("history rows = %d, want 0 after rollback: %+v", len(hist), hist)
	}
}

func TestFindingFieldsCVSSSyncsInsideTransaction(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedFindingForForm(t, s)
	path := fmt.Sprintf("/findings/%d/fields", f.ID)
	const vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

	w := postForm(t, s, path, url.Values{
		"cvss_vector": {vec},
		"severity":    {"Critical"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", w.Code, w.Body)
	}

	var got db.Finding
	s.DB.First(&got, f.ID)
	if got.CVSSVector != vec || got.CVSSScore != 9.8 || got.Severity != "Critical" {
		t.Fatalf("finding after form: vector=%q score=%v severity=%q", got.CVSSVector, got.CVSSScore, got.Severity)
	}
	var hist []db.FindingHistory
	s.DB.Where("finding_id = ?", f.ID).Order("field").Find(&hist)
	fields := make([]string, 0, len(hist))
	for _, h := range hist {
		fields = append(fields, h.Field)
	}
	want := []string{"cvss_score", "cvss_vector", "severity"}
	if fmt.Sprint(fields) != fmt.Sprint(want) {
		t.Fatalf("history fields = %v, want %v", fields, want)
	}
}

func TestFindingCommunications(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedFindingForForm(t, s)
	path := fmt.Sprintf("/findings/%d/communications", f.ID)

	w := postForm(t, s, path, url.Values{
		"channel":   {"email"},
		"direction": {"outbound"},
		"actor":     {"alice"},
		"body":      {"sent disclosure"},
		"at":        {"2026-06-01"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", w.Code, w.Body)
	}
	var rows []db.FindingCommunication
	s.DB.Where("finding_id = ?", f.ID).Find(&rows)
	if len(rows) != 1 || rows[0].Channel != "email" || rows[0].At.Format("2006-01-02") != "2026-06-01" {
		t.Errorf("communications = %+v", rows)
	}

	// Empty/unparseable at defaults to now.
	w = postForm(t, s, path, url.Values{"channel": {"github"}, "at": {"not-a-date"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	s.DB.Where("finding_id = ?", f.ID).Order("id").Find(&rows)
	if len(rows) != 2 || rows[1].At.IsZero() {
		t.Errorf("second communication = %+v, want non-zero At", rows)
	}
}

func TestFindingReferences(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedFindingForForm(t, s)
	path := fmt.Sprintf("/findings/%d/references", f.ID)

	w := postForm(t, s, path, url.Values{
		"url":     {"https://example.com/advisory"},
		"tags":    {"advisory"},
		"summary": {"upstream advisory"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", w.Code, w.Body)
	}
	var rows []db.FindingReference
	s.DB.Where("finding_id = ?", f.ID).Find(&rows)
	if len(rows) != 1 || rows[0].URL != "https://example.com/advisory" {
		t.Errorf("references = %+v", rows)
	}

	if w := postForm(t, s, path, url.Values{"url": {"   "}}); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("empty url: status = %d, want 422", w.Code)
	}
}

func TestFindingLabels(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedFindingForForm(t, s)
	path := fmt.Sprintf("/findings/%d/labels", f.ID)

	labelsOf := func() []string {
		var got db.Finding
		s.DB.Preload("Labels").First(&got, f.ID)
		names := make([]string, len(got.Labels))
		for i, l := range got.Labels {
			names[i] = l.Name
		}
		slices.Sort(names)
		return names
	}

	// Checkbox-style: multiple labels= form values.
	w := postForm(t, s, path, url.Values{"labels": {"wontfix", "needs-info", " ", ""}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", w.Code, w.Body)
	}
	if got := labelsOf(); !slices.Equal(got, []string{"needs-info", "wontfix"}) {
		t.Errorf("labels = %v, want [needs-info wontfix]", got)
	}

	// Comma-style: one labels= value with commas.
	w = postForm(t, s, path, url.Values{"labels": {"regression, duplicate ,"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("comma status = %d", w.Code)
	}
	if got := labelsOf(); !slices.Equal(got, []string{"duplicate", "regression"}) {
		t.Errorf("labels after comma input = %v, want [duplicate regression]", got)
	}

	// Clearing.
	w = postForm(t, s, path, url.Values{"labels": {""}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("clear status = %d", w.Code)
	}
	if got := labelsOf(); len(got) != 0 {
		t.Errorf("labels after clear = %v, want []", got)
	}
}
