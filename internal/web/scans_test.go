package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"scrutineer/internal/db"
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sid, resume := resumeOpts(tc.scan)
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

func TestScansCancelAll_requiresRepository(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	w := httptest.NewRecorder()
	s.scansCancelAll(w, localReq("POST", "/scans/cancel-all"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}
