package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/skills"
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

func TestSkillCreate_rejectsTraversalName(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	h := s.Handler()

	for _, name := range []string{"../../etc", "a/b", "A_B", "has spaces", "..", "../x"} {
		form := url.Values{
			"name":        {name},
			"description": {"d"},
			"body":        {"b"},
		}
		req := localReq("POST", "/skills")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Body = httptest.NewRequest("POST", "/skills", strings.NewReader(form.Encode())).Body
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Errorf("name=%q: got status %d, want 400", name, w.Code)
		}
	}
}

func TestSkillCreate_rejectsTraversalOutputFile(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	h := s.Handler()

	for _, of := range []string{"../scrutineer.db", "../../etc/passwd", "sub/report.json"} {
		form := url.Values{
			"name":        {"good-name"},
			"description": {"d"},
			"body":        {"b"},
			"output_file": {of},
		}
		req := localReq("POST", "/skills")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Body = httptest.NewRequest("POST", "/skills", strings.NewReader(form.Encode())).Body
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Errorf("output_file=%q: got status %d, want 400", of, w.Code)
		}
	}
}

func TestSkillCreate_acceptsValidNames(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	h := s.Handler()

	for _, name := range []string{"triage", "my-skill", "scan-2"} {
		form := url.Values{
			"name":        {name},
			"description": {"d"},
			"body":        {"b"},
			"output_file": {"report.json"},
		}
		req := localReq("POST", "/skills")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Body = httptest.NewRequest("POST", "/skills", strings.NewReader(form.Encode())).Body
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 303 {
			t.Errorf("name=%q: got status %d, want 303; body=%s", name, w.Code, w.Body)
		}
	}
}

func TestParseMaxTurns(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"50", 50},
		{"0", 0},
		{"-1", 0},
		{"-999", 0},
		{"", 0},
		{"abc", 0},
		{" 42 ", 42},
	}
	for _, tc := range tests {
		got := parseMaxTurns(tc.input)
		if got != tc.want {
			t.Errorf("parseMaxTurns(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestParseSkillModel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"   ", ""},
		{"garbage", ""},
		{ModelTierHigh, ModelTierHigh},
		{"claude-sonnet-4-6", "claude-sonnet-4-6"},
		{" claude-opus-4-7 ", "claude-opus-4-7"},
	}
	for _, tc := range tests {
		got := parseSkillModel(tc.input)
		if got != tc.want {
			t.Errorf("parseSkillModel(%q) = %q, want %q", tc.input, got, tc.want)
		}
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
	if w.Code != http.StatusSeeOther {
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

// TestSkillsUI_bundledAdvisoryDeepDive loads the real bundled skills and
// renders the /skills list and the advisory-deep-dive detail page. It guards
// render paths a UI-created skill (freeform, no schema) never exercises: the
// schema.json section, which runs the prettyjson filter over a real schema.
// An unknown id must 404, not 500.
func TestSkillsUI_bundledAdvisoryDeepDive(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	h := s.Handler()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := skills.LoadDirectory(s.DB, log, "../../skills", "local"); err != nil {
		t.Fatalf("load bundled skills: %v", err)
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, localReq("GET", "/skills"))
	if w.Code != 200 {
		t.Fatalf("list status %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "advisory-deep-dive") {
		t.Error("list page missing advisory-deep-dive row")
	}

	var row db.Skill
	if err := s.DB.Where("name = ?", "advisory-deep-dive").First(&row).Error; err != nil {
		t.Fatalf("advisory-deep-dive not loaded: %v", err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, localReq("GET", "/skills/"+strconv.FormatUint(uint64(row.ID), 10)))
	if w.Code != 200 {
		t.Fatalf("show status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{
		"schema.json",                        // the {{if .SchemaJSON}} section rendered
		"advisory-deep-dive findings report", // schema title, proving prettyjson ran over it
	} {
		if !strings.Contains(body, want) {
			t.Errorf("show page missing %q", want)
		}
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, localReq("GET", "/skills/999999"))
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown skill id: status %d, want 404", w.Code)
	}
}
