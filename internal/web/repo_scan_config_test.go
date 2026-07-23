package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestRepoScanConfigSave(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/config", Name: "config"}
	s.DB.Create(&repo)
	config := `focus_areas:
  - name: parser
    paths: [src/parse/**]
    surface: accepts bytes
skip: [tests/**]`
	w := postForm(t, s, fmt.Sprintf("/repositories/%d/scan-config", repo.ID), url.Values{"scan_config": {config}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code = %d body=%s", w.Code, w.Body.String())
	}
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if !strings.Contains(got.ScanConfig, "focus_areas:") || !strings.Contains(got.ScanConfig, "tests/**") {
		t.Fatalf("ScanConfig = %q", got.ScanConfig)
	}
}

func TestRepoScanConfigSaveRejectsInvalidYAML(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/config-invalid", Name: "config-invalid"}
	s.DB.Create(&repo)
	w := postForm(t, s, fmt.Sprintf("/repositories/%d/scan-config", repo.ID), url.Values{"scan_config": {"skip: [../private/**]"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "relative") {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
	}
}

func TestRepoScanConfigClear(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/config-clear", Name: "config-clear", ScanConfig: "skip: [tests/**]\n"}
	s.DB.Create(&repo)
	w := postForm(t, s, fmt.Sprintf("/repositories/%d/scan-config/clear", repo.ID), url.Values{})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code = %d body=%s", w.Code, w.Body.String())
	}
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.ScanConfig != "" {
		t.Fatalf("ScanConfig = %q, want empty", got.ScanConfig)
	}
}

func TestRepoIgnoredPathAddPreservesScanConfig(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/config-ignore", Name: "config-ignore", ScanConfig: `focus_areas:
  - name: parser
    paths: [src/parse/**]
    surface: accepts bytes
known_bugs:
  - GHSA-xxxx-yyyy
skip:
  - tests/**
`}
	s.DB.Create(&repo)

	w := postForm(t, s, fmt.Sprintf("/repositories/%d/scan-config/ignored-paths", repo.ID), url.Values{"pattern": {"spec/**"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code = %d body=%s", w.Code, w.Body.String())
	}

	var got db.Repository
	s.DB.First(&got, repo.ID)
	for _, want := range []string{"focus_areas:", "known_bugs:", "tests/**", "spec/**"} {
		if !strings.Contains(got.ScanConfig, want) {
			t.Fatalf("ScanConfig = %q, want %q", got.ScanConfig, want)
		}
	}
}

func TestRepoIgnoredPathAddRejectsInvalidPattern(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/config-ignore-invalid", Name: "config-ignore-invalid"}
	s.DB.Create(&repo)

	w := postForm(t, s, fmt.Sprintf("/repositories/%d/scan-config/ignored-paths", repo.ID), url.Values{"pattern": {"../private/**"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "relative") {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
	}
}

func TestRepoIgnoredPathDelete(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/config-ignore-delete", Name: "config-ignore-delete", ScanConfig: "skip:\n  - tests/**\n  - spec/**\n"}
	s.DB.Create(&repo)

	w := postForm(t, s, fmt.Sprintf("/repositories/%d/scan-config/ignored-paths/delete", repo.ID), url.Values{"pattern": {"tests/**"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code = %d body=%s", w.Code, w.Body.String())
	}

	var got db.Repository
	s.DB.First(&got, repo.ID)
	if strings.Contains(got.ScanConfig, "tests/**") || !strings.Contains(got.ScanConfig, "spec/**") {
		t.Fatalf("ScanConfig = %q", got.ScanConfig)
	}
}

func TestRepoShowScanConfigTab(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/config-tab", Name: "config-tab", ScanConfig: "skip:\n  - tests/**\n"}
	s.DB.Create(&repo)
	rw := httptest.NewRecorder()
	s.Handler().ServeHTTP(rw, localReq(http.MethodGet, fmt.Sprintf("/repositories/%d", repo.ID)))
	if rw.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rw.Code, rw.Body.String())
	}
	body := rw.Body.String()
	for _, want := range []string{"Scan config", "scan-config", "scrutineer.scan_config", "Ignored paths", "Path pattern", "tests/**"} {
		if !strings.Contains(body, want) {
			t.Errorf("repo page missing %q", want)
		}
	}
}
