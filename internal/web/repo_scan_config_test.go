package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/repoconfig"
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

func legacyFocusScanConfig(t *testing.T) string {
	t.Helper()
	var cfg strings.Builder
	cfg.WriteString("skip: [tests/**]\nknown_bugs: [documented behavior]\nattack_surface: network inputs\nfocus_areas:\n")
	for i := range repoconfig.MaxFocusAreas + 1 {
		fmt.Fprintf(&cfg, "  - name: area-%d\n    paths: [p%d/**]\n    surface: untrusted input\n", i, i)
	}
	return cfg.String()
}

func TestRepoIgnoredPathsPreserveLegacyFocusAreas(t *testing.T) {
	for _, op := range []string{"add", "delete"} {
		t.Run(op, func(t *testing.T) {
			s, cleanup := newTestServer(t)
			defer cleanup()
			repo := db.Repository{URL: "https://example.com/legacy", Name: "legacy", ScanConfig: legacyFocusScanConfig(t)}
			if err := s.DB.Create(&repo).Error; err != nil {
				t.Fatal(err)
			}
			before, err := repoconfig.Parse(repo.ScanConfig)
			if err != nil {
				t.Fatal(err)
			}
			path := fmt.Sprintf("/repositories/%d/scan-config/ignored-paths", repo.ID)
			pattern := "spec/**"
			wantSkip := []string{"tests/**", "spec/**"}
			if op == "delete" {
				path += "/delete"
				pattern = "tests/**"
				wantSkip = nil
			}
			w := postForm(t, s, path, url.Values{"pattern": {pattern}})
			if w.Code != http.StatusSeeOther {
				t.Fatalf("HTTP %d: %s", w.Code, w.Body)
			}
			var got db.Repository
			if err := s.DB.First(&got, repo.ID).Error; err != nil {
				t.Fatal(err)
			}
			parsed, err := repoconfig.Parse(got.ScanConfig)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(parsed.Skip, wantSkip) {
				t.Fatalf("skip=%v, want %v", parsed.Skip, wantSkip)
			}
			parsed.Skip = before.Skip
			if !reflect.DeepEqual(parsed, before) {
				t.Fatal("ignored-path edit changed other scan guidance")
			}
		})
	}
}

func TestRepoScanConfigSaveStillRejectsOverCapFocusAreas(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	repo := db.Repository{URL: "https://example.com/capped", Name: "capped", ScanConfig: "skip: [tests/**]\n"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	w := postForm(t, s, fmt.Sprintf("/repositories/%d/scan-config", repo.ID), url.Values{"scan_config": {legacyFocusScanConfig(t)}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "limit is 32") {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body)
	}
	var got db.Repository
	if err := s.DB.First(&got, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.ScanConfig != repo.ScanConfig {
		t.Fatal("invalid full-config save changed stored guidance")
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

func TestRepoIgnoredPathAddDetectsNormalisedDuplicate(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/config-ignore-dupe", Name: "config-ignore-dupe", ScanConfig: "skip:\n  - tests/**\n"}
	s.DB.Create(&repo)

	w := postForm(t, s, fmt.Sprintf("/repositories/%d/scan-config/ignored-paths", repo.ID), url.Values{"pattern": {`tests\**`}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code = %d body=%s", w.Code, w.Body.String())
	}

	var got db.Repository
	s.DB.First(&got, repo.ID)
	if strings.Count(got.ScanConfig, "tests/**") != 1 {
		t.Fatalf("ScanConfig = %q, want one tests/** entry", got.ScanConfig)
	}
}

func TestRepoIgnoredPathAddRejectsInvalidPattern(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/config-ignore-invalid", Name: "config-ignore-invalid"}
	s.DB.Create(&repo)

	w := postForm(t, s, fmt.Sprintf("/repositories/%d/scan-config/ignored-paths", repo.ID), url.Values{"pattern": {"../private/**"}})
	body := w.Body.String()
	if w.Code != http.StatusBadRequest || !strings.Contains(body, "relative") || strings.Contains(body, "YAML") {
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

func TestRepoIgnoredPathDeleteNormalisesPattern(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/config-ignore-delete-normalised", Name: "config-ignore-delete-normalised", ScanConfig: "skip:\n  - tests/**\n  - spec/**\n"}
	s.DB.Create(&repo)

	w := postForm(t, s, fmt.Sprintf("/repositories/%d/scan-config/ignored-paths/delete", repo.ID), url.Values{"pattern": {`tests\**`}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code = %d body=%s", w.Code, w.Body.String())
	}

	var got db.Repository
	s.DB.First(&got, repo.ID)
	if strings.Contains(got.ScanConfig, "tests/**") || !strings.Contains(got.ScanConfig, "spec/**") {
		t.Fatalf("ScanConfig = %q", got.ScanConfig)
	}
}

func TestRepoIgnoredPathDeleteRejectsEmptyPattern(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/config-ignore-delete-empty", Name: "config-ignore-delete-empty", ScanConfig: "skip:\n  - tests/**\n"}
	s.DB.Create(&repo)

	w := postForm(t, s, fmt.Sprintf("/repositories/%d/scan-config/ignored-paths/delete", repo.ID), url.Values{"pattern": {" "}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "required") {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
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
