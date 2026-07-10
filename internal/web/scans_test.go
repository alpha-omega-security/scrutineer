package web

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func TestResumeOpts(t *testing.T) {
	uintPtr := func(v uint) *uint { return &v }

	cases := []struct {
		name       string
		scan       db.Scan
		wantSID    string
		wantResume *uint
	}{
		{
			name:    "failed with session resumes from its own id",
			scan:    db.Scan{ID: 7, Status: db.ScanFailed, SessionID: "s1"},
			wantSID: "s1", wantResume: uintPtr(7),
		},
		{
			name:    "failed retry keeps the lineage root",
			scan:    db.Scan{ID: 9, Status: db.ScanFailed, SessionID: "s1", ResumedFromScanID: uintPtr(7)},
			wantSID: "s1", wantResume: uintPtr(7),
		},
		{
			name:    "max-turns done scan resumes from its own id",
			scan:    db.Scan{ID: 7, Status: db.ScanDone, MaxTurnsHit: true, SessionID: "s1"},
			wantSID: "s1", wantResume: uintPtr(7),
		},
		{
			name:    "max-turns retry keeps the lineage root",
			scan:    db.Scan{ID: 9, Status: db.ScanDone, MaxTurnsHit: true, SessionID: "s1", ResumedFromScanID: uintPtr(7)},
			wantSID: "s1", wantResume: uintPtr(7),
		},
		{
			name: "done scan retries fresh",
			scan: db.Scan{ID: 7, Status: db.ScanDone, SessionID: ""},
		},
		{
			name: "failed but no session retries fresh",
			scan: db.Scan{ID: 7, Status: db.ScanFailed, SessionID: ""},
		},
		{
			name: "cancelled scan retries fresh even with a session",
			scan: db.Scan{ID: 7, Status: db.ScanCancelled, SessionID: "s1"},
		},
		{
			// A scan that ran under a different -backend than the current
			// server retries fresh: its session id belongs to another agent
			// CLI (e.g. a codex thread id passed to claude --resume fails).
			name: "different backend retries fresh (cross-backend session id)",
			scan: db.Scan{ID: 7, Status: db.ScanFailed, SessionID: "codex-thr-1", Backend: "codex"},
		},
		{
			name:    "same backend resumes",
			scan:    db.Scan{ID: 7, Status: db.ScanFailed, SessionID: "s1", Backend: "claude"},
			wantSID: "s1", wantResume: uintPtr(7),
		},
		{
			// Rows predating the Backend column (empty) are treated as claude,
			// so under a claude server they resume.
			name:    "empty backend resumes under claude (pre-column rows)",
			scan:    db.Scan{ID: 7, Status: db.ScanFailed, SessionID: "s1", Backend: ""},
			wantSID: "s1", wantResume: uintPtr(7),
		},
	}

	s := &Server{Backend: "claude", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sid, resume := s.resumeOpts(tc.scan)
			if sid != tc.wantSID {
				t.Errorf("sessionID = %q, want %q", sid, tc.wantSID)
			}
			switch {
			case tc.wantResume == nil && resume != nil:
				t.Errorf("resumeOf = %v, want nil", *resume)
			case tc.wantResume != nil && resume == nil:
				t.Errorf("resumeOf = nil, want %d", *tc.wantResume)
			case tc.wantResume != nil && *resume != *tc.wantResume:
				t.Errorf("resumeOf = %d, want %d", *resume, *tc.wantResume)
			}
		})
	}
}

// TestResumeOpts_emptyBackendUnderCodex locks that a pre-column row (empty
// Backend, so a claude session) retried under a codex server starts fresh
// rather than passing a claude session id to codex exec resume.
func TestResumeOpts_emptyBackendUnderCodex(t *testing.T) {
	s := &Server{Backend: "codex", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	sid, resume := s.resumeOpts(db.Scan{ID: 7, Status: db.ScanFailed, SessionID: "s1", Backend: ""})
	if sid != "" || resume != nil {
		t.Errorf("empty-backend row under codex: sid=%q resume=%v, want fresh", sid, resume)
	}
}

// The test worker has an empty running map, so worker.Cancel always reports
// "not in flight" — only the queued-flip path is exercisable here.
func TestScanCancel_flipsQueuedWithoutRedirect(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/c", Name: "c"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanQueued,
		StatusPriority: db.StatusPriorityFor(db.ScanQueued)}
	s.DB.Create(&scan)

	r := localReq("POST", fmt.Sprintf("/scans/%d/cancel", scan.ID))
	r.Header.Set("HX-Request", "true")
	r.SetPathValue("id", fmt.Sprint(scan.ID))
	w := httptest.NewRecorder()
	s.scanCancel(w, r)

	// No redirect for htmx — just a 204 so the operator stays on the list.
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body)
	}
	if loc := w.Header().Get("HX-Redirect"); loc != "" {
		t.Errorf("HX-Redirect = %q, want none", loc)
	}

	var got db.Scan
	s.DB.First(&got, scan.ID)
	if got.Status != db.ScanCancelled {
		t.Errorf("status = %q, want cancelled", got.Status)
	}
	if got.StatusPriority != db.StatusPriorityFor(db.ScanCancelled) {
		t.Errorf("status_priority = %d, want %d", got.StatusPriority, db.StatusPriorityFor(db.ScanCancelled))
	}
}

func TestScanCancel_refererRedirect(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)

	mk := func() db.Scan {
		sc := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanQueued,
			StatusPriority: db.StatusPriorityFor(db.ScanQueued)}
		s.DB.Create(&sc)
		return sc
	}

	cases := []struct {
		name    string
		referer string
		wantLoc string
	}{
		{"same-origin absolute", "http://" + testHost + "/repositories/1#rt3", "http://" + testHost + "/repositories/1#rt3"},
		{"same-origin path-only", "/jobs", "/jobs"},
		{"cross-origin ignored", "https://evil.example.com/phish", ""},
		{"javascript scheme ignored", "javascript:alert(1)", ""},
		{"data scheme ignored", "data:text/html,<script>alert(1)</script>", ""},
		{"opaque http ignored", "http:evil.com", ""},
		{"protocol-relative ignored", "//evil.example.com/phish", ""},
		{"garbage ignored", "://not a url", ""},
		{"no referer", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scan := mk()
			r := localReq("POST", fmt.Sprintf("/scans/%d/cancel", scan.ID))
			r.SetPathValue("id", fmt.Sprint(scan.ID))
			if tc.referer != "" {
				r.Header.Set("Referer", tc.referer)
			}
			w := httptest.NewRecorder()
			s.scanCancel(w, r)

			if w.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303", w.Code)
			}
			want := tc.wantLoc
			if want == "" {
				want = fmt.Sprintf("/scans/%d", scan.ID)
			}
			if got := w.Header().Get("Location"); got != want {
				t.Errorf("Location = %q, want %q", got, want)
			}
		})
	}
}

func TestScansCancelAll_cancelsRepoQueuedAndRunning(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/a", Name: "a"}
	other := db.Repository{URL: "https://example.com/b", Name: "b"}
	s.DB.Create(&repo)
	s.DB.Create(&other)

	mk := func(repoID uint, st db.ScanStatus) db.Scan {
		sc := db.Scan{RepositoryID: repoID, Kind: "skill", Status: st,
			StatusPriority: db.StatusPriorityFor(st)}
		s.DB.Create(&sc)
		return sc
	}
	queued := mk(repo.ID, db.ScanQueued)
	running := mk(repo.ID, db.ScanRunning)
	finished := mk(repo.ID, db.ScanDone)
	paused := mk(repo.ID, db.ScanPaused)
	otherQueued := mk(other.ID, db.ScanQueued)

	r := localReq("POST", fmt.Sprintf("/scans/cancel-all?repository=%d", repo.ID))
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	s.scansCancelAll(w, r)

	if loc := w.Header().Get("HX-Redirect"); loc != fmt.Sprintf("/repositories/%d#rt3", repo.ID) {
		t.Errorf("HX-Redirect = %q, want repo Scans tab", loc)
	}

	statusOf := func(id uint) db.ScanStatus {
		var sc db.Scan
		s.DB.First(&sc, id)
		return sc.Status
	}
	// Queued and running on this repo are cancelled; terminal, paused, and the
	// other repo's queued scan are untouched.
	if got := statusOf(queued.ID); got != db.ScanCancelled {
		t.Errorf("queued -> %q, want cancelled", got)
	}
	if got := statusOf(running.ID); got != db.ScanCancelled {
		t.Errorf("running -> %q, want cancelled", got)
	}
	if got := statusOf(finished.ID); got != db.ScanDone {
		t.Errorf("done -> %q, want done", got)
	}
	if got := statusOf(paused.ID); got != db.ScanPaused {
		t.Errorf("paused -> %q, want paused", got)
	}
	if got := statusOf(otherQueued.ID); got != db.ScanQueued {
		t.Errorf("other repo queued -> %q, want queued (untouched)", got)
	}
	var queuedGot db.Scan
	s.DB.First(&queuedGot, queued.ID)
	if queuedGot.Error != "cancelled by user" || queuedGot.FinishedAt == nil {
		t.Errorf("queued cancel fields: error=%q finished_at=%v", queuedGot.Error, queuedGot.FinishedAt)
	}
	if queuedGot.StatusPriority != db.StatusPriorityFor(db.ScanCancelled) {
		t.Errorf("queued status_priority = %d, want cancelled priority", queuedGot.StatusPriority)
	}
}

func TestScansPauseQueued_bulkUpdatesQueuedOnly(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/pause", Name: "pause"}
	s.DB.Create(&repo)

	mk := func(st db.ScanStatus) db.Scan {
		sc := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: st, StatusPriority: db.StatusPriorityFor(st)}
		s.DB.Create(&sc)
		return sc
	}
	q1 := mk(db.ScanQueued)
	q2 := mk(db.ScanQueued)
	running := mk(db.ScanRunning)
	doneScan := mk(db.ScanDone)

	r := localReq("POST", "/scans/pause-queued")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", w.Code, w.Body)
	}
	if loc := w.Header().Get("Location"); loc != "/scans?status=paused" {
		t.Errorf("Location = %q, want /scans?status=paused", loc)
	}

	var q1got, q2got, runningGot, doneGot db.Scan
	s.DB.First(&q1got, q1.ID)
	s.DB.First(&q2got, q2.ID)
	s.DB.First(&runningGot, running.ID)
	s.DB.First(&doneGot, doneScan.ID)
	for _, got := range []db.Scan{q1got, q2got} {
		if got.Status != db.ScanPaused || got.StatusPriority != db.StatusPriorityFor(db.ScanPaused) {
			t.Errorf("queued scan %d -> status=%s priority=%d, want paused", got.ID, got.Status, got.StatusPriority)
		}
		if got.Error != "paused by user" || got.FinishedAt == nil {
			t.Errorf("queued scan %d pause fields: error=%q finished_at=%v", got.ID, got.Error, got.FinishedAt)
		}
	}
	if runningGot.Status != db.ScanRunning {
		t.Errorf("running -> %q, want running", runningGot.Status)
	}
	if doneGot.Status != db.ScanDone {
		t.Errorf("done -> %q, want done", doneGot.Status)
	}
}

func TestScansResumePaused(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)

	mk := func(st db.ScanStatus) db.Scan {
		sc := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: st,
			StatusPriority: db.StatusPriorityFor(st)}
		s.DB.Create(&sc)
		return sc
	}
	p1 := mk(db.ScanPaused)
	p2 := mk(db.ScanPaused)
	queued := mk(db.ScanQueued)
	finished := mk(db.ScanDone)

	r := localReq("POST", "/scans/resume-paused")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", w.Code, w.Body)
	}
	if loc := w.Header().Get("Location"); loc != "/scans?status=queued" {
		t.Errorf("Location = %q, want /scans?status=queued", loc)
	}

	statusOf := func(id uint) db.ScanStatus {
		var sc db.Scan
		s.DB.First(&sc, id)
		return sc.Status
	}
	if statusOf(p1.ID) != db.ScanQueued || statusOf(p2.ID) != db.ScanQueued {
		t.Errorf("paused scans should be queued: p1=%s p2=%s", statusOf(p1.ID), statusOf(p2.ID))
	}
	if statusOf(queued.ID) != db.ScanQueued {
		t.Errorf("already-queued scan touched: %s", statusOf(queued.ID))
	}
	if statusOf(finished.ID) != db.ScanDone {
		t.Errorf("done scan touched: %s", statusOf(finished.ID))
	}
	var p1got db.Scan
	s.DB.First(&p1got, p1.ID)
	if p1got.StatusPriority != db.StatusPriorityFor(db.ScanQueued) {
		t.Errorf("status_priority = %d, want queued priority", p1got.StatusPriority)
	}
}

func TestScansResumePaused_scopedToRepo(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/a", Name: "a"}
	other := db.Repository{URL: "https://example.com/b", Name: "b"}
	s.DB.Create(&repo)
	s.DB.Create(&other)

	mk := func(repoID uint, st db.ScanStatus) db.Scan {
		sc := db.Scan{RepositoryID: repoID, Kind: "skill", Status: st,
			StatusPriority: db.StatusPriorityFor(st)}
		s.DB.Create(&sc)
		return sc
	}
	paused := mk(repo.ID, db.ScanPaused)
	otherPaused := mk(other.ID, db.ScanPaused)
	finished := mk(repo.ID, db.ScanDone)

	r := localReq("POST", fmt.Sprintf("/scans/resume-paused?repository=%d", repo.ID))
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	s.scansResumePaused(w, r)

	if loc := w.Header().Get("HX-Redirect"); loc != fmt.Sprintf("/repositories/%d#rt3", repo.ID) {
		t.Errorf("HX-Redirect = %q, want repo Scans tab", loc)
	}

	statusOf := func(id uint) db.ScanStatus {
		var sc db.Scan
		s.DB.First(&sc, id)
		return sc.Status
	}
	// Only this repo's paused scan is resumed; the other repo's paused scan and
	// terminal scans are untouched.
	if got := statusOf(paused.ID); got != db.ScanQueued {
		t.Errorf("paused -> %q, want queued", got)
	}
	if got := statusOf(otherPaused.ID); got != db.ScanPaused {
		t.Errorf("other repo paused -> %q, want paused (untouched)", got)
	}
	if got := statusOf(finished.ID); got != db.ScanDone {
		t.Errorf("done -> %q, want done", got)
	}
}

func TestScansCancelAll_requiresRepository(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	w := httptest.NewRecorder()
	s.scansCancelAll(w, localReq("POST", "/scans/cancel-all"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// Repeated failures of one (repository, skill, sub_path, ref, finding_id)
// tuple must retry only the newest failed row, and a failure superseded by a
// newer paused attempt must not retry at all. Suppression by queued/running/
// done — and cancelled deliberately not suppressing — is covered by
// TestScansRetryFailed_skipsAlreadyRetried.
func TestScansRetryFailed_dedupesRepeatedFailures(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "hello", Description: "d", Body: "b",
		OutputFile: "report.json", OutputKind: "freeform", Version: 1,
		Active: true, Source: "ui"}
	s.DB.Create(&skill)

	mk := func(status db.ScanStatus, subPath string) {
		sc := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: status,
			StatusPriority: db.StatusPriorityFor(status),
			SkillID:        &skill.ID, SkillName: skill.Name, SubPath: subPath}
		s.DB.Create(&sc)
	}

	// Three straight failures of the same tuple — only the newest retries.
	mk(db.ScanFailed, "")
	mk(db.ScanFailed, "")
	mk(db.ScanFailed, "")

	// A failure with a newer paused attempt for its tuple — superseded.
	mk(db.ScanFailed, "parked")
	mk(db.ScanPaused, "parked")

	var maxID uint
	s.DB.Model(&db.Scan{}).Select("MAX(id)").Scan(&maxID)

	w := httptest.NewRecorder()
	s.scansRetryFailed(w, localReq("POST", "/scans/retry-failed"))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", w.Code, w.Body)
	}

	var queued []db.Scan
	s.DB.Where("id > ? AND status = ?", maxID, db.ScanQueued).Find(&queued)
	if len(queued) != 1 {
		t.Fatalf("new queued scans = %d, want exactly 1", len(queued))
	}
	if queued[0].SubPath != "" {
		t.Errorf("retried sub_path = %q, want the repeated-failure tuple (parked is superseded)", queued[0].SubPath)
	}
}
