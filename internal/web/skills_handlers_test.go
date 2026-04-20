package web

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestSkillsList_empty(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/skills"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "No skills") {
		t.Error("empty-state marker missing")
	}
}

func TestSkillsCreateAndShow(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	h := s.Handler()

	form := url.Values{
		"name":        {"hello"},
		"description": {"Say hi"},
		"body":        {"# hello\n\nsay hi"},
		"output_file": {"report.json"},
		"output_kind": {"freeform"},
	}
	req := localReq("POST", "/skills")
	req.Body = nil
	req.PostForm = form
	req.Form = form
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body = httptest.NewRequest("POST", "/skills", strings.NewReader(form.Encode())).Body
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 303 {
		t.Fatalf("create status %d body=%s", w.Code, w.Body)
	}

	var row db.Skill
	s.DB.First(&row)
	if row.Name != "hello" || row.OutputKind != "freeform" || row.Version != 1 {
		t.Fatalf("row = %+v", row)
	}

	// Show page
	w = httptest.NewRecorder()
	h.ServeHTTP(w, localReq("GET", "/skills/1"))
	if w.Code != 200 {
		t.Fatalf("show status %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "hello") {
		t.Error("show page missing name")
	}
}
