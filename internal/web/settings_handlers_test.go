package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func postForm(t *testing.T, s *Server, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	r.Host = "127.0.0.1:8080"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestSettingsShow_rendersRunnerControls(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	if err := db.SetSetting(s.DB, db.SettingConcurrency, "9"); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/settings", nil)
	r.Host = "127.0.0.1:8080"
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{`name="tier" value="mid"`, `name="concurrency"`, `value="9"`, `name="max_turns"`, "Default turns"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page missing %q", want)
		}
	}
}

func TestSettingsShow_rendersStaleRunnerBanner(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.SetRunnerImageStatus(worker.RunnerImageStatus{
		Stale:       true,
		AgeDays:     10,
		PullCommand: "docker pull ghcr.io/example/runner:latest",
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/settings", nil)
	r.Host = "127.0.0.1:8080"
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	// Covers both the template's banner text and the data-copy attribute the
	// settingsShow overlay feeds it.
	for _, want := range []string{
		"Runner image is 10 days old.",
		`data-copy="docker pull ghcr.io/example/runner:latest"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("stale-runner banner missing %q", want)
		}
	}
}

func TestSettingsShow_noBannerWhenFresh(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	// No SetRunnerImageStatus call: the zero value is not stale, so the banner
	// must not render.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/settings", nil)
	r.Host = "127.0.0.1:8080"
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "days old.") {
		t.Error("stale-runner banner rendered for a fresh image")
	}
}

func TestSettingsUpdateModelTier(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w := postForm(t, s, "/settings/model", url.Values{
		"tier":  {ModelTierMid},
		"model": {"claude-sonnet-4-6"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got := ModelForTier(s.DB, ModelTierMid, s.DefaultModel()); got != "claude-sonnet-4-6" {
		t.Errorf("mid tier model = %q, want claude-sonnet-4-6", got)
	}

	for _, form := range []url.Values{
		{"tier": {"unknown"}, "model": {"claude-sonnet-4-6"}},
		{"tier": {ModelTierMid}, "model": {"not-a-model"}},
	} {
		w := postForm(t, s, "/settings/model", form)
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("form=%v: status %d, want 422", form, w.Code)
		}
	}
	if got := ModelForTier(s.DB, ModelTierMid, s.DefaultModel()); got != "claude-sonnet-4-6" {
		t.Errorf("invalid update clobbered mid tier = %q", got)
	}
}

func TestSettingsUpdateConcurrency(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	// No scans running, so a changed value applies immediately (live runner
	// reconfigure) and redirects.
	w := postForm(t, s, "/settings/concurrency", url.Values{"concurrency": {"12"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got := db.SettingInt(s.DB, db.SettingConcurrency); got != 12 {
		t.Errorf("persisted concurrency = %d, want 12", got)
	}
	if got := s.Queue.Concurrency(); got != 12 {
		t.Errorf("runner concurrency = %d, want 12 (applied immediately)", got)
	}

	for _, bad := range []string{"0", "65", "-1", "abc", ""} {
		w := postForm(t, s, "/settings/concurrency", url.Values{"concurrency": {bad}})
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("concurrency=%q: status %d, want 422", bad, w.Code)
		}
	}
	// A rejected value leaves the stored one untouched.
	if got := db.SettingInt(s.DB, db.SettingConcurrency); got != 12 {
		t.Errorf("concurrency clobbered by invalid input = %d, want 12", got)
	}
}

func TestSettingsUpdateConcurrency_confirmsWhenScansRunning(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanRunning})

	before := s.Queue.Concurrency()
	w := postForm(t, s, "/settings/concurrency", url.Values{"concurrency": {"20"}})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (confirmation): %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{"/settings/runner/restart", "concurrency-confirm", "Restart runner"} {
		if !strings.Contains(body, want) {
			t.Errorf("confirmation missing %q; body=%s", want, body)
		}
	}
	if got := db.SettingInt(s.DB, db.SettingConcurrency); got != 20 {
		t.Errorf("value should be persisted before confirm; got %d", got)
	}
	if got := s.Queue.Concurrency(); got != before {
		t.Errorf("runner reconfigured before confirmation: %d (was %d)", got, before)
	}
}

func TestSettingsRestartRunner(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	if err := db.SetSetting(s.DB, db.SettingConcurrency, "16"); err != nil {
		t.Fatal(err)
	}
	w := postForm(t, s, "/settings/runner/restart", nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got := s.Queue.Concurrency(); got != 16 {
		t.Errorf("runner concurrency = %d, want 16 after restart", got)
	}
}

func TestSettingsUpdateMaxTurns(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w := postForm(t, s, "/settings/max-turns", url.Values{"max_turns": {"50"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got := db.SettingInt(s.DB, db.SettingDefaultMaxTurns); got != 50 {
		t.Errorf("persisted default_max_turns = %d, want 50", got)
	}

	for _, bad := range []string{"0", "501", "-1", "abc", ""} {
		w := postForm(t, s, "/settings/max-turns", url.Values{"max_turns": {bad}})
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("max_turns=%q: status %d, want 422", bad, w.Code)
		}
	}
	if got := db.SettingInt(s.DB, db.SettingDefaultMaxTurns); got != 50 {
		t.Errorf("max_turns clobbered by invalid input = %d, want 50", got)
	}
}
