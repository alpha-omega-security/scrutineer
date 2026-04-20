package web

import (
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
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

func TestSkillRetry_preservesSkillID(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	h := s.Handler()

	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	skill := db.Skill{
		Name:        "hello",
		Description: "d",
		Body:        "b",
		OutputFile:  "report.json",
		OutputKind:  "freeform",
		Version:     1,
		Active:      true,
		Source:      "ui",
	}
	s.DB.Create(&skill)

	// Create a skill scan via the run endpoint.
	runForm := url.Values{"skill_id": {strconv.Itoa(int(skill.ID))}}
	req := httptest.NewRequest("POST", "/repositories/"+strconv.Itoa(int(repo.ID))+"/skill-scan",
		strings.NewReader(runForm.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 303 {
		t.Fatalf("skill-scan status %d: %s", w.Code, w.Body)
	}

	var initial db.Scan
	if err := s.DB.Where("kind = ?", worker.JobSkill).First(&initial).Error; err != nil {
		t.Fatalf("no skill scan created: %v", err)
	}
	if initial.SkillID == nil || *initial.SkillID != skill.ID {
		t.Fatalf("initial scan SkillID = %v, want %d", initial.SkillID, skill.ID)
	}

	// Retry it.
	req = httptest.NewRequest("POST", "/scans/"+strconv.Itoa(int(initial.ID))+"/retry", nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 204 {
		t.Fatalf("retry status %d: %s", w.Code, w.Body)
	}

	var retried db.Scan
	if err := s.DB.Where("id > ?", initial.ID).Where("kind = ?", worker.JobSkill).
		Order("id desc").First(&retried).Error; err != nil {
		t.Fatalf("retry scan not found: %v", err)
	}
	if retried.SkillID == nil {
		t.Fatal("retried scan has no SkillID -- the bug")
	}
	if *retried.SkillID != skill.ID {
		t.Errorf("retried SkillID = %d, want %d", *retried.SkillID, skill.ID)
	}
}
