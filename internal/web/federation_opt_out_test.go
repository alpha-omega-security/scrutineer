package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func seedOptOutRepo(t *testing.T, s *Server, optedOut bool) db.Repository {
	t.Helper()
	repo := db.Repository{URL: "https://github.com/acme/lib", Name: "lib"}
	if optedOut {
		at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		repo.FederationOptOutAt = &at
	}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	return repo
}

func TestEnqueueSkill_refusedForOptedOutRepository(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedOptOutRepo(t, s, true)
	skill := db.Skill{Name: "security-deep-dive", Active: true}
	s.DB.Create(&skill)

	if _, err := s.enqueueSkill(context.Background(), repo.ID, skill.ID, ""); !errors.Is(err, ErrRepoFederationOptOut) {
		t.Fatalf("expected ErrRepoFederationOptOut, got %v", err)
	}
	var scans int64
	s.DB.Model(&db.Scan{}).Count(&scans)
	if scans != 0 {
		t.Fatalf("a refused enqueue must create no scan row, got %d", scans)
	}
}

func TestEnqueueSkill_allowedWhenNotOptedOut(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedOptOutRepo(t, s, false)
	skill := db.Skill{Name: "security-deep-dive", Active: true}
	s.DB.Create(&skill)

	if _, err := s.enqueueSkill(context.Background(), repo.ID, skill.ID, ""); err != nil {
		t.Fatalf("a repository that did not opt out must still be scannable: %v", err)
	}
}

// The scheduler has to refuse before it makes any network call: the upstream
// sync is a force-push to the maintainer's host, which is the other half of
// what the opt-out asks us not to do.
func TestRunScheduledScan_skipsOptedOutRepositoryBeforeAnyNetworkCall(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedOptOutRepo(t, s, true)
	// A bogus upstream: reaching syncUpstream at all would try to talk to it,
	// so the skip reason proves the check fired first.
	s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
		Update("upstream_url", "https://127.0.0.1:1/never/reached.git")

	s.runScheduledScan(context.Background(), db.Repository{
		ID: repo.ID, Name: repo.Name, URL: repo.URL,
		UpstreamURL:        "https://127.0.0.1:1/never/reached.git",
		FederationOptOutAt: repo.FederationOptOutAt,
	})

	var skip db.Scan
	if err := s.DB.Where("repository_id = ?", repo.ID).Order("id desc").First(&skip).Error; err != nil {
		t.Fatal(err)
	}
	if skip.Status != db.ScanSkipped || skip.Kind != scheduleKind {
		t.Fatalf("expected a scheduled skip row, got kind %q status %q", skip.Kind, skip.Status)
	}
	if skip.Error != "maintainer opted out of federated scanning" {
		t.Errorf("skip reason = %q; the opt-out must be why, not a network failure", skip.Error)
	}
}

func TestRepoFederationOptOut_setEditAndClear(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedOptOutRepo(t, s, false)
	path := "/repositories/" + strconv.FormatUint(uint64(repo.ID), 10) + "/federation-opt-out"
	reload := func() db.Repository {
		t.Helper()
		var got db.Repository
		if err := s.DB.First(&got, repo.ID).Error; err != nil {
			t.Fatal(err)
		}
		return got
	}

	if w := postForm(t, s, path, url.Values{"opt_out": {"1"}, "reason": {"maintainer asked"}}); w.Code >= 400 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	set := reload()
	if set.FederationOptOutAt == nil || set.FederationOptOutReason != "maintainer asked" {
		t.Fatalf("opt-out not recorded: %v / %q", set.FederationOptOutAt, set.FederationOptOutReason)
	}
	requested := *set.FederationOptOutAt

	if w := postForm(t, s, path, url.Values{"opt_out": {"1"}, "reason": {"they repeated it"}}); w.Code >= 400 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	edited := reload()
	if !edited.FederationOptOutAt.Equal(requested) {
		t.Errorf("editing the reason must keep the original request date, got %v want %v", edited.FederationOptOutAt, requested)
	}
	if edited.FederationOptOutReason != "they repeated it" {
		t.Errorf("reason = %q", edited.FederationOptOutReason)
	}

	if w := postForm(t, s, path, url.Values{"reason": {"ignored"}}); w.Code >= 400 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	cleared := reload()
	if cleared.FederationOptOutAt != nil || cleared.FederationOptOutReason != "" {
		t.Fatalf("clearing must drop both columns: %v / %q", cleared.FederationOptOutAt, cleared.FederationOptOutReason)
	}
}

func seedScan(t *testing.T, s *Server, repoID uint, status db.ScanStatus) db.Scan {
	t.Helper()
	scan := db.Scan{
		RepositoryID:   repoID,
		Kind:           "skill",
		Status:         status,
		StatusPriority: db.StatusPriorityFor(status),
	}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	return scan
}

func reloadScan(t *testing.T, s *Server, id uint) db.Scan {
	t.Helper()
	var got db.Scan
	if err := s.DB.First(&got, id).Error; err != nil {
		t.Fatal(err)
	}
	return got
}

func optOutPath(repoID uint) string {
	return "/repositories/" + strconv.FormatUint(uint64(repoID), 10) + "/federation-opt-out"
}

// Refusing the next scan is not enough: a queued or paused scan would still
// run later, and a running one keeps reading the maintainer's code.
func TestRepoFederationOptOut_stopsScansAlreadyUnderWay(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedOptOutRepo(t, s, false)
	queued := seedScan(t, s, repo.ID, db.ScanQueued)
	running := seedScan(t, s, repo.ID, db.ScanRunning)
	paused := seedScan(t, s, repo.ID, db.ScanPaused)
	// A finished scan is history, not work in flight, and must survive untouched.
	kept := seedScan(t, s, repo.ID, db.ScanDone)

	if w := postForm(t, s, optOutPath(repo.ID), url.Values{"opt_out": {"1"}}); w.Code >= 400 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	for name, id := range map[string]uint{"queued": queued.ID, "running": running.ID, "paused": paused.ID} {
		got := reloadScan(t, s, id)
		if got.Status != db.ScanCancelled {
			t.Errorf("%s scan status = %q, want cancelled", name, got.Status)
		}
		if got.Error != worker.OptOutCancelReason {
			t.Errorf("%s scan error = %q, want %q", name, got.Error, worker.OptOutCancelReason)
		}
	}
	if got := reloadScan(t, s, kept.ID); got.Status != db.ScanDone {
		t.Errorf("a finished scan must not be rewritten, status = %q", got.Status)
	}
}

func TestRepoFederationOptOut_clearingLeavesScansAlone(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedOptOutRepo(t, s, true)
	queued := seedScan(t, s, repo.ID, db.ScanQueued)

	if w := postForm(t, s, optOutPath(repo.ID), url.Values{}); w.Code >= 400 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got := reloadScan(t, s, queued.ID); got.Status != db.ScanQueued {
		t.Errorf("clearing the opt-out must not cancel anything, status = %q", got.Status)
	}
}

// Resuming re-queues an existing row without going through the enqueue gate,
// so it needs its own check; the row stays paused so the operator can see why.
func TestScanResume_refusedForOptedOutRepository(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedOptOutRepo(t, s, true)
	paused := seedScan(t, s, repo.ID, db.ScanPaused)

	w := postForm(t, s, "/scans/"+strconv.FormatUint(uint64(paused.ID), 10)+"/resume", url.Values{})
	if w.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409. body=%s", w.Code, w.Body)
	}
	if got := reloadScan(t, s, paused.ID); got.Status != db.ScanPaused {
		t.Errorf("a refused resume must leave the scan paused, status = %q", got.Status)
	}
}

// The bulk resume claims every paused row in one statement, so the opt-out has
// to narrow the claim itself rather than be checked per scan afterwards.
func TestScansResumePaused_skipsOptedOutRepository(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	optedOut := seedOptOutRepo(t, s, true)
	open := db.Repository{URL: "https://github.com/acme/other", Name: "other"}
	if err := s.DB.Create(&open).Error; err != nil {
		t.Fatal(err)
	}
	blocked := seedScan(t, s, optedOut.ID, db.ScanPaused)
	resumable := seedScan(t, s, open.ID, db.ScanPaused)

	if w := postForm(t, s, "/scans/resume-paused", url.Values{}); w.Code >= 400 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got := reloadScan(t, s, blocked.ID); got.Status != db.ScanPaused {
		t.Errorf("opted-out scan status = %q, want left paused", got.Status)
	}
	if got := reloadScan(t, s, resumable.ID); got.Status != db.ScanQueued {
		t.Errorf("scan on an open repository status = %q, want queued", got.Status)
	}
}

// The tick loads every due repository up front and then fires them one at a
// time, so a repository still waiting its turn must be re-read rather than
// trusted from the snapshot.
func TestRunScheduledScan_rereadsOptOutRecordedAfterTheSnapshot(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedOptOutRepo(t, s, true)

	// The snapshot predates the opt-out: no FederationOptOutAt on the struct.
	s.runScheduledScan(context.Background(), db.Repository{
		ID: repo.ID, Name: repo.Name, URL: repo.URL,
		UpstreamURL: "https://127.0.0.1:1/never/reached.git",
	})

	var skip db.Scan
	if err := s.DB.Where("repository_id = ?", repo.ID).Order("id desc").First(&skip).Error; err != nil {
		t.Fatal(err)
	}
	if skip.Error != "maintainer opted out of federated scanning" {
		t.Errorf("skip reason = %q; a stale snapshot must not let the sync through", skip.Error)
	}
}

// The gate at the top of enqueueSkillWith runs before the model, the ref and the
// rest of the row are resolved, so an opt-out can commit while the enqueue is
// still assembling it. The scan must not survive that: created and left queued,
// it reports accepted work on a repository whose maintainer just refused.
func TestEnqueueSkill_refusedWhenTheOptOutLandsBeforeTheScanIsCommitted(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedOptOutRepo(t, s, false)
	skill := db.Skill{Name: "security-deep-dive", Active: true}
	s.DB.Create(&skill)

	// Fires inside the creating transaction, right after the scan row is
	// inserted: from that transaction's point of view the maintainer opted out
	// between the gate and the commit. The rollback undoes this write too, so the
	// assertions below are about the scan, not about the flag.
	if err := s.DB.Callback().Create().After("gorm:create").
		Register("test:opt_out_mid_enqueue", func(tx *gorm.DB) {
			if tx.Statement.Schema == nil || tx.Statement.Schema.Name != "Scan" {
				return
			}
			at := time.Now().UTC()
			if err := tx.Session(&gorm.Session{NewDB: true}).Model(&db.Repository{}).
				Where("id = ?", repo.ID).Update("federation_opt_out_at", &at).Error; err != nil {
				t.Error(err)
			}
		}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.DB.Callback().Create().Remove("test:opt_out_mid_enqueue") }()

	if _, err := s.enqueueSkill(context.Background(), repo.ID, skill.ID, ""); !errors.Is(err, ErrRepoFederationOptOut) {
		t.Fatalf("enqueue = %v, want ErrRepoFederationOptOut", err)
	}
	var scans int64
	s.DB.Model(&db.Scan{}).Where("repository_id = ?", repo.ID).Count(&scans)
	if scans != 0 {
		t.Fatalf("the scan must roll back with the refusal, got %d row(s)", scans)
	}
}

// A live read of the flag only narrows the scheduler's window: the opt-out can
// commit right after it, and the upstream push and remote HEAD lookup still
// reach the maintainer's host. Recording it therefore waits for the firing in
// progress, and then stops what that firing enqueued.
func TestRunScheduledScan_optOutRecordedMidFiringWaitsForItAndStopsTheScans(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DB.Create(&db.Skill{Name: deepDiveSkillName, Description: "d", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"})
	s.DB.Create(&db.Skill{Name: threatModelSkillName, Description: "t", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"})
	repo := seedOptOutRepo(t, s, false)
	upstream := "https://127.0.0.1:1/mirror.git"
	s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).Update("upstream_url", upstream)

	reached, release := make(chan struct{}), make(chan struct{})
	s.resolveRemoteHead = func(context.Context, db.Repository) (string, error) { return "deadbeef", nil }
	s.syncUpstream = func(context.Context, string, string) error {
		close(reached)
		<-release
		return nil
	}

	fired := make(chan struct{})
	go func() {
		defer close(fired)
		s.runScheduledScan(context.Background(), db.Repository{
			ID: repo.ID, Name: repo.Name, URL: repo.URL, UpstreamURL: upstream,
		})
	}()
	<-reached

	posted := make(chan int, 1)
	go func() { posted <- postForm(t, s, optOutPath(repo.ID), url.Values{"opt_out": {"1"}}).Code }()
	select {
	case code := <-posted:
		t.Fatalf("the opt-out was recorded mid-firing (status %d): the check and the network calls it gates are not serialised with it", code)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	<-fired
	select {
	case code := <-posted:
		if code >= 400 {
			t.Fatalf("opt-out status %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the opt-out never completed after the firing released the repository")
	}

	var live int64
	s.DB.Model(&db.Scan{}).
		Where("repository_id = ? AND status IN ?", repo.ID, []db.ScanStatus{db.ScanQueued, db.ScanRunning, db.ScanPaused}).
		Count(&live)
	if live != 0 {
		t.Errorf("%d scan(s) still alive; the opt-out must stop what the firing enqueued", live)
	}
}

// A policy refusal must be distinguishable from a server fault on the API,
// or a skill's retry logic hammers the endpoint instead of stopping.
func TestAPIRunSkill_optedOutRepositoryAnswers409(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)
	at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
		Update("federation_opt_out_at", &at).Error; err != nil {
		t.Fatal(err)
	}
	s.DB.Create(&db.Skill{Name: "metadata", Description: "m", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"})

	r := httptest.NewRequest("POST", "/api/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/skills/metadata/run", nil)
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409. body=%s", w.Code, w.Body)
	}
}
