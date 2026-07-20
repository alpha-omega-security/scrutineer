package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

func TestScheduleNext(t *testing.T) {
	now := time.Now()
	for _, expr := range []string{"daily", "weekly", "@hourly", "*/5 * * * *", "0 3 * * 1"} {
		next, err := ScheduleNext(expr, now)
		if err != nil {
			t.Errorf("ScheduleNext(%q) = %v, want nil", expr, err)
			continue
		}
		if !next.After(now) {
			t.Errorf("ScheduleNext(%q) = %v, want a time after %v", expr, next, now)
		}
	}
	for _, expr := range []string{"", "yearly-ish", "* * *", "61 * * * *"} {
		if _, err := ScheduleNext(expr, now); err == nil {
			t.Errorf("ScheduleNext(%q) = nil error, want error", expr)
		}
	}
}

// scheduleTestServer wires a test server whose git traffic is stubbed:
// resolveRemoteHead returns head, syncUpstream returns syncErr and records
// the calls it received.
func scheduleTestServer(t *testing.T, head string, syncErr error) (*Server, *[]string, func()) {
	t.Helper()
	s, done := newTestServer(t)
	var synced []string
	s.resolveRemoteHead = func(_ context.Context, _ db.Repository) (string, error) {
		if head == "" {
			return "", errors.New("ls-remote exploded")
		}
		return head, nil
	}
	s.syncUpstream = func(_ context.Context, repoURL, upstreamURL string) error {
		synced = append(synced, repoURL+"<-"+upstreamURL)
		return syncErr
	}
	return s, &synced, done
}

func scheduledRepo(t *testing.T, s *Server, schedule string, due time.Time) db.Repository {
	t.Helper()
	repo := db.Repository{URL: "https://example.com/r", Name: "r", ScanSchedule: schedule, NextScheduledScanAt: &due}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	return repo
}

func lastSkip(t *testing.T, s *Server, repoID uint) db.Scan {
	t.Helper()
	var scan db.Scan
	if err := s.DB.Where("repository_id = ? AND status = ?", repoID, db.ScanSkipped).
		Order("id desc").First(&scan).Error; err != nil {
		t.Fatalf("expected a skipped scan row: %v", err)
	}
	return scan
}

func TestScheduleTick_backfillsNextRunWithoutFiring(t *testing.T) {
	s, _, done := scheduleTestServer(t, "abc", nil)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r", ScanSchedule: "daily"}
	s.DB.Create(&repo)

	s.scheduleTick(context.Background(), time.Now())

	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.NextScheduledScanAt == nil || !got.NextScheduledScanAt.After(time.Now()) {
		t.Fatalf("NextScheduledScanAt = %v, want a future time", got.NextScheduledScanAt)
	}
	var scans int64
	s.DB.Model(&db.Scan{}).Count(&scans)
	if scans != 0 {
		t.Fatalf("backfill created %d scan(s), want 0", scans)
	}
}

func TestScheduleTick_inheritsGlobalDefault(t *testing.T) {
	s, _, done := scheduleTestServer(t, "abc", nil)
	defer done()
	if err := db.SetSetting(s.DB, db.SettingScanSchedule, "weekly"); err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)

	s.scheduleTick(context.Background(), time.Now())

	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.NextScheduledScanAt == nil {
		t.Fatal("repo with empty schedule should inherit the global default")
	}
}

func TestScheduleTick_offOverridesGlobalAndClearsNext(t *testing.T) {
	s, _, done := scheduleTestServer(t, "abc", nil)
	defer done()
	if err := db.SetSetting(s.DB, db.SettingScanSchedule, "daily"); err != nil {
		t.Fatal(err)
	}
	repo := scheduledRepo(t, s, ScheduleOff, time.Now().Add(-time.Hour))

	s.scheduleTick(context.Background(), time.Now())

	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.NextScheduledScanAt != nil {
		t.Fatalf("NextScheduledScanAt = %v, want nil for an off schedule", got.NextScheduledScanAt)
	}
	var scans int64
	s.DB.Model(&db.Scan{}).Count(&scans)
	if scans != 0 {
		t.Fatalf("off schedule created %d scan(s), want 0", scans)
	}
}

func TestScheduleTick_notDueYet(t *testing.T) {
	s, _, done := scheduleTestServer(t, "abc", nil)
	defer done()
	future := time.Now().Add(time.Hour)
	repo := scheduledRepo(t, s, "daily", future)

	s.scheduleTick(context.Background(), time.Now())

	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.NextScheduledScanAt == nil || got.NextScheduledScanAt.Sub(future).Abs() > time.Second {
		t.Fatalf("NextScheduledScanAt = %v, want untouched %v", got.NextScheduledScanAt, future)
	}
}

func TestScheduleTick_skipsWhenHeadUnchanged(t *testing.T) {
	s, _, done := scheduleTestServer(t, "abc123", nil)
	defer done()
	repo := scheduledRepo(t, s, "daily", time.Now().Add(-time.Minute))
	now := time.Now()
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, Commit: "abc123", FinishedAt: &now})

	s.scheduleTick(context.Background(), time.Now())

	skip := lastSkip(t, s, repo.ID)
	if !strings.Contains(skip.Error, "no new commits") {
		t.Fatalf("skip reason = %q, want it to mention no new commits", skip.Error)
	}
	if skip.Kind != scheduleKind {
		t.Fatalf("skip kind = %q, want %q", skip.Kind, scheduleKind)
	}
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.NextScheduledScanAt == nil || !got.NextScheduledScanAt.After(time.Now()) {
		t.Fatalf("NextScheduledScanAt = %v, want advanced past now", got.NextScheduledScanAt)
	}
}

func TestScheduleTick_enqueuesDiffRescanWhenHeadChanged(t *testing.T) {
	s, _, done := scheduleTestServer(t, "def456", nil)
	defer done()
	s.DB.Create(&db.Skill{Name: deepDiveSkillName, Description: "d", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"})
	s.DB.Create(&db.Skill{Name: threatModelSkillName, Description: "t", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"})
	repo := scheduledRepo(t, s, "daily", time.Now().Add(-time.Minute))
	now := time.Now()
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, Commit: "abc123", FinishedAt: &now})

	s.scheduleTick(context.Background(), time.Now())

	var queued []db.Scan
	s.DB.Where("repository_id = ? AND status = ?", repo.ID, db.ScanQueued).Find(&queued)
	if len(queued) != 1 {
		t.Fatalf("queued %d scan(s), want 1 (threat-model only, aux skills not installed)", len(queued))
	}
	if queued[0].SkillName != threatModelSkillName || queued[0].RescanMode != db.ScanRescanModeDiff {
		t.Fatalf("queued scan = %q mode %q, want %q in diff mode", queued[0].SkillName, queued[0].RescanMode, threatModelSkillName)
	}
}

func TestScheduleTick_firesWhenRepoNeverScanned(t *testing.T) {
	s, _, done := scheduleTestServer(t, "def456", nil)
	defer done()
	s.DB.Create(&db.Skill{Name: deepDiveSkillName, Description: "d", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"})
	s.DB.Create(&db.Skill{Name: threatModelSkillName, Description: "t", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"})
	repo := scheduledRepo(t, s, "daily", time.Now().Add(-time.Minute))

	s.scheduleTick(context.Background(), time.Now())

	var queued int64
	s.DB.Model(&db.Scan{}).Where("repository_id = ? AND status = ?", repo.ID, db.ScanQueued).Count(&queued)
	if queued != 1 {
		t.Fatalf("queued %d scan(s), want 1 on a never-scanned repo", queued)
	}
}

func TestScheduleTick_skipsWhenScanInFlight(t *testing.T) {
	s, _, done := scheduleTestServer(t, "def456", nil)
	defer done()
	repo := scheduledRepo(t, s, "daily", time.Now().Add(-time.Minute))
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanRunning})

	s.scheduleTick(context.Background(), time.Now())

	skip := lastSkip(t, s, repo.ID)
	if !strings.Contains(skip.Error, "queued or running") {
		t.Fatalf("skip reason = %q, want it to mention queued or running", skip.Error)
	}
}

func TestScheduleTick_skipsWhenScanPaused(t *testing.T) {
	s, _, done := scheduleTestServer(t, "def456", nil)
	defer done()
	repo := scheduledRepo(t, s, "daily", time.Now().Add(-time.Minute))
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanPaused})

	s.scheduleTick(context.Background(), time.Now())

	skip := lastSkip(t, s, repo.ID)
	if !strings.Contains(skip.Error, "queued or running") {
		t.Fatalf("skip reason = %q, want a paused scan to count as in flight", skip.Error)
	}
}

func countSkips(t *testing.T, s *Server, repoID uint) int64 {
	t.Helper()
	var n int64
	s.DB.Model(&db.Scan{}).Where("repository_id = ? AND status = ?", repoID, db.ScanSkipped).Count(&n)
	return n
}

func TestRecordScheduledSkip_collapsesConsecutiveIdenticalReasons(t *testing.T) {
	s, _, done := scheduleTestServer(t, "abc", nil)
	defer done()
	repo := scheduledRepo(t, s, "daily", time.Now())

	s.recordScheduledSkip(repo, "no new commits since abc")
	s.recordScheduledSkip(repo, "no new commits since abc")
	if got := countSkips(t, s, repo.ID); got != 1 {
		t.Fatalf("consecutive identical skips = %d rows, want 1 (collapsed)", got)
	}

	s.recordScheduledSkip(repo, "upstream sync failed: boom")
	if got := countSkips(t, s, repo.ID); got != 2 {
		t.Fatalf("distinct-reason skips = %d rows, want 2", got)
	}
}

func TestRecordScheduledSkip_keepsSkipAfterRealScan(t *testing.T) {
	s, _, done := scheduleTestServer(t, "abc", nil)
	defer done()
	repo := scheduledRepo(t, s, "daily", time.Now())

	s.recordScheduledSkip(repo, "no new commits since abc")
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone})
	s.recordScheduledSkip(repo, "no new commits since abc")

	if got := countSkips(t, s, repo.ID); got != 2 {
		t.Fatalf("skip rows across a real scan = %d, want 2 (not collapsed)", got)
	}
}

func TestScheduleTick_skipsWhenUpstreamSyncFails(t *testing.T) {
	s, synced, done := scheduleTestServer(t, "def456", errors.New("push rejected"))
	defer done()
	repo := scheduledRepo(t, s, "daily", time.Now().Add(-time.Minute))
	s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).Update("upstream_url", "https://example.com/upstream")

	s.scheduleTick(context.Background(), time.Now())

	if len(*synced) != 1 || !strings.Contains((*synced)[0], "https://example.com/upstream") {
		t.Fatalf("syncUpstream calls = %v, want one against the upstream", *synced)
	}
	skip := lastSkip(t, s, repo.ID)
	if !strings.Contains(skip.Error, "upstream sync failed") {
		t.Fatalf("skip reason = %q, want it to mention upstream sync", skip.Error)
	}
}

func TestScheduleTick_skipsWhenHeadLookupFails(t *testing.T) {
	s, _, done := scheduleTestServer(t, "", nil)
	defer done()
	repo := scheduledRepo(t, s, "daily", time.Now().Add(-time.Minute))

	s.scheduleTick(context.Background(), time.Now())

	skip := lastSkip(t, s, repo.ID)
	if !strings.Contains(skip.Error, "remote HEAD lookup failed") {
		t.Fatalf("skip reason = %q, want it to mention the HEAD lookup", skip.Error)
	}
}

func TestRepoScheduleUpdate_savesAndResetsNextRun(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := scheduledRepo(t, s, "daily", time.Now().Add(time.Hour))

	w := postForm(t, s, "/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/schedule", url.Values{
		"scan_schedule":      {"custom"},
		"scan_schedule_cron": {"0 3 * * 1"},
		"upstream_url":       {"https://example.com/upstream"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.ScanSchedule != "0 3 * * 1" || got.UpstreamURL != "https://example.com/upstream" {
		t.Fatalf("saved schedule = %q upstream = %q", got.ScanSchedule, got.UpstreamURL)
	}
	if got.NextScheduledScanAt != nil {
		t.Fatalf("NextScheduledScanAt = %v, want nil after a schedule edit", got.NextScheduledScanAt)
	}
}

func TestRepoScheduleUpdate_rejectsInvalidCron(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := scheduledRepo(t, s, "", time.Now())

	w := postForm(t, s, "/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/schedule", url.Values{
		"scan_schedule":      {"custom"},
		"scan_schedule_cron": {"not a cron"},
	})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422", w.Code)
	}
}

func TestRepoScheduleUpdate_rejectsNonHTTPSUpstream(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := scheduledRepo(t, s, "", time.Now())

	w := postForm(t, s, "/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/schedule", url.Values{
		"scan_schedule": {"daily"},
		"upstream_url":  {"git@github.com:x/y.git"},
	})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422", w.Code)
	}
}

func TestSettingsUpdateScanSchedule_savesAndResetsInheritingRepos(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	inheriting := scheduledRepo(t, s, "", time.Now().Add(time.Hour))
	pinnedDue := time.Now().Add(time.Hour)
	pinned := db.Repository{URL: "https://example.com/p", Name: "p", ScanSchedule: "weekly", NextScheduledScanAt: &pinnedDue}
	s.DB.Create(&pinned)

	w := postForm(t, s, "/settings/scan-schedule", url.Values{"scan_schedule": {"daily"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if v, _ := db.GetSetting(s.DB, db.SettingScanSchedule); v != "daily" {
		t.Fatalf("setting = %q, want daily", v)
	}
	var gotInheriting db.Repository
	s.DB.First(&gotInheriting, inheriting.ID)
	if gotInheriting.NextScheduledScanAt != nil {
		t.Fatalf("inheriting repo NextScheduledScanAt = %v, want reset to nil", gotInheriting.NextScheduledScanAt)
	}
	var gotPinned db.Repository
	s.DB.First(&gotPinned, pinned.ID)
	if gotPinned.NextScheduledScanAt == nil {
		t.Fatal("pinned repo NextScheduledScanAt should be untouched by a global change")
	}
}

func TestSettingsUpdateScanSchedule_offNormalisesToEmpty(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	if err := db.SetSetting(s.DB, db.SettingScanSchedule, "daily"); err != nil {
		t.Fatal(err)
	}

	w := postForm(t, s, "/settings/scan-schedule", url.Values{"scan_schedule": {"off"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if v, _ := db.GetSetting(s.DB, db.SettingScanSchedule); v != "" {
		t.Fatalf("setting = %q, want empty", v)
	}
}

func TestSettingsUpdateScanSchedule_rejectsInvalidCron(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w := postForm(t, s, "/settings/scan-schedule", url.Values{
		"scan_schedule":      {"custom"},
		"scan_schedule_cron": {"every other tuesday"},
	})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422", w.Code)
	}
}

func TestScheduleTick_skipsWhenDeepDiveMissing(t *testing.T) {
	s, _, done := scheduleTestServer(t, "def456", nil)
	defer done()
	repo := scheduledRepo(t, s, "daily", time.Now().Add(-time.Minute))

	s.scheduleTick(context.Background(), time.Now())

	skip := lastSkip(t, s, repo.ID)
	if !strings.Contains(skip.Error, "enqueue failed") {
		t.Fatalf("skip reason = %q, want it to mention the enqueue failure", skip.Error)
	}
}

func TestScheduleTick_deepDiveMissingQueuesNoAuxiliaries(t *testing.T) {
	s, _, done := scheduleTestServer(t, "def456", nil)
	defer done()
	s.DB.Create(&db.Skill{Name: "semgrep", Description: "d", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"})
	repo := scheduledRepo(t, s, "daily", time.Now().Add(-time.Minute))

	s.scheduleTick(context.Background(), time.Now())

	skip := lastSkip(t, s, repo.ID)
	if !strings.Contains(skip.Error, "enqueue failed") {
		t.Fatalf("skip reason = %q, want it to mention the enqueue failure", skip.Error)
	}
	var queued int64
	s.DB.Model(&db.Scan{}).Where("repository_id = ? AND status = ?", repo.ID, db.ScanQueued).Count(&queued)
	if queued != 0 {
		t.Fatalf("queued %d auxiliary scan(s) despite the missing deep-dive, want 0 (group must be all-or-nothing)", queued)
	}
}

func TestScheduleTick_baselineLookupErrorAbortsRun(t *testing.T) {
	s, _, done := scheduleTestServer(t, "def456", nil)
	defer done()
	s.DB.Create(&db.Skill{Name: deepDiveSkillName, Description: "d", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"})
	repo := scheduledRepo(t, s, "daily", time.Now().Add(-time.Minute))

	// Fail only the baseline lookup (the sole query selecting the commit
	// column) to simulate a transient database error mid-run.
	const name = "test:fail_baseline_lookup"
	if err := s.DB.Callback().Query().Before("gorm:query").Register(name, func(d *gorm.DB) {
		if strings.Contains(strings.Join(d.Statement.Selects, ","), "`commit`") {
			_ = d.AddError(errors.New("injected lookup failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.DB.Callback().Query().Remove(name); err != nil {
			t.Fatal(err)
		}
	}()

	s.scheduleTick(context.Background(), time.Now())

	var scans int64
	s.DB.Model(&db.Scan{}).Where("repository_id = ?", repo.ID).Count(&scans)
	if scans != 0 {
		t.Fatalf("wrote %d scan row(s) after a baseline lookup failure, want 0 (no rescan, no skip)", scans)
	}
}
