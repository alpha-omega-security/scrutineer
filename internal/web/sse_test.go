package web

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
)

// The wire format the browser's EventSource actually parses: a filtered stream
// carries the status events and nothing else, and an event that names no scan
// still arrives (with an empty payload) so the list pages re-fetch.
func TestEventsStream_filteredWireFormat(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", srv.URL+"/events?events=scan-status", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Response headers are flushed after Subscribe, so having them means this
	// client is registered and the publishes below cannot race it.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}

	s.Broker.Publish(Event{Name: "scan-log", Data: "a log line", ScanID: 5})
	s.Broker.Publish(Event{Name: "scan-status", RepoID: 7})

	br := bufio.NewReader(resp.Body)
	name, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read event line: %v", err)
	}
	if name != "event: scan-status\n" {
		t.Errorf("first line = %q, want the scan-status event (the log line must be filtered out)", name)
	}
	payload, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read data line: %v", err)
	}
	if payload != "data: \n" {
		t.Errorf("data line = %q, want empty: an event naming no scan has no row to swap", payload)
	}
}

// A list page reacts to scan-status only, so it must not be sent the log line
// of every running scan on the instance.
func TestBrokerEventNameFilter(t *testing.T) {
	b := NewBroker()
	statusOnly := b.Subscribe(0, 0, 0, "scan-status")
	everything := b.Subscribe(0, 0, 0)

	b.Publish(Event{Name: "scan-log", Data: "a log line", ScanID: 5})
	b.Publish(Event{Name: "scan-status", ScanID: 5})

	if e := recvEvent(t, statusOnly); e.Name != "scan-status" {
		t.Errorf("filtered subscriber got %q, want scan-status only", e.Name)
	}
	select {
	case e := <-statusOnly.ch:
		t.Errorf("filtered subscriber must not receive %+v", e)
	default:
	}

	// An unfiltered subscriber keeps the old behaviour: the scan page still
	// needs its log lines.
	if e := recvEvent(t, everything); e.Name != "scan-log" {
		t.Errorf("unfiltered subscriber got %q first, want scan-log", e.Name)
	}
	if e := recvEvent(t, everything); e.Name != "scan-status" {
		t.Errorf("unfiltered subscriber got %q second, want scan-status", e.Name)
	}
}

// A padded list is the natural way to write one by hand, and an untrimmed name
// matches no event at all, so the stream would go silent instead of erroring.
func TestEventsStream_eventListToleratesSpaces(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", srv.URL+"/events?events=scan-status,%20scan-log", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	s.Broker.Publish(Event{Name: "scan-log", Data: "a log line", ScanID: 5})

	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil {
		t.Fatalf("read event line: %v", err)
	}
	if line != "event: scan-log\n" {
		t.Errorf("first line = %q, want the scan-log event through a padded filter", line)
	}
}

func recvEvent(t *testing.T, c *client) Event {
	t.Helper()
	select {
	case e := <-c.ch:
		return e
	default:
		t.Fatal("expected an event to be delivered")
		return Event{}
	}
}

// A scan reaching `running` pushes its row like any other status change, but a
// toast per start would spam the toaster, and the category would read as an
// error since it is not "done".
func TestRenderScanStatus_runningPushesRowWithoutToast(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/live", Name: "live"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "audit", Status: db.ScanRunning}
	s.DB.Create(&scan)

	out := s.renderScanStatus(scan.ID)

	if !strings.Contains(out, fmt.Sprintf(`id="scan-%d"`, scan.ID)) {
		t.Errorf("missing row id: %s", out)
	}
	if strings.Contains(out, "#toaster") {
		t.Errorf("running scan should not toast: %s", out)
	}
}

// The list pages refresh off scan-status, so every action that changes a scan
// row has to publish one or the tables stay stale in any tab that did not
// trigger the action.
func TestScanActionsPublishScanStatus(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/actions", Name: "actions"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "audit", Body: "b", OutputFile: "r.json", OutputKind: "freeform",
		Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&skill)

	mkScan := func(status db.ScanStatus) db.Scan {
		sc := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "audit", Status: status,
			StatusPriority: db.StatusPriorityFor(status)}
		s.DB.Create(&sc)
		return sc
	}

	for _, tc := range []struct {
		name       string
		act        func(t *testing.T)
		wantScanID bool // the row already exists, so the event carries it
	}{
		{
			name: "enqueue",
			act: func(t *testing.T) {
				if _, err := s.enqueueSkillWith(context.Background(), repo.ID, skill.ID, ScanOpts{}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "resume",
			act: func(t *testing.T) {
				sc := mkScan(db.ScanQueued)
				if err := s.enqueueResumedScan(context.Background(), sc); err != nil {
					t.Fatal(err)
				}
			},
			wantScanID: true,
		},
		{
			name: "cancel",
			act: func(t *testing.T) {
				sc := mkScan(db.ScanQueued)
				r := localReq("POST", fmt.Sprintf("/scans/%d/cancel", sc.ID))
				r.Header.Set("HX-Request", "true")
				r.SetPathValue("id", fmt.Sprint(sc.ID))
				w := httptest.NewRecorder()
				s.scanCancel(w, r)
				if w.Code != http.StatusNoContent {
					t.Fatalf("cancel: status %d, body=%s", w.Code, w.Body)
				}
			},
			wantScanID: true,
		},
		{
			// Instance-wide, but still named per affected repository: a page
			// scoped to one filters on RepoID and would otherwise never hear.
			name: "pause queued",
			act: func(t *testing.T) {
				mkScan(db.ScanQueued)
				w := httptest.NewRecorder()
				s.scansPauseQueued(w, localReq("POST", "/scans/pause-queued"))
			},
		},
		{
			name: "cancel all",
			act: func(t *testing.T) {
				mkScan(db.ScanQueued)
				w := httptest.NewRecorder()
				s.scansCancelAll(w, localReq("POST", fmt.Sprintf("/scans/cancel-all?repository=%d", repo.ID)))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := s.Broker.Subscribe(0, 0, 0, "scan-status")
			defer s.Broker.Unsubscribe(c)

			tc.act(t)

			e := recvEvent(t, c)
			// A per-repository subscriber filters on this, so a zero drops the
			// repo Scans tab from the refresh.
			if e.RepoID != repo.ID {
				t.Errorf("RepoID = %d, want %d", e.RepoID, repo.ID)
			}
			if tc.wantScanID && e.ScanID == 0 {
				t.Error("event should name the scan whose row already exists")
			}
			// A new row nobody rendered yet cannot be swapped OOB, so naming it
			// would make htmx log an oob error against a missing target.
			if !tc.wantScanID && e.ScanID != 0 {
				t.Errorf("ScanID = %d, want none", e.ScanID)
			}
		})
	}
}

// "Pause queued" is instance-wide, but a repository's Scans tab filters on
// RepoID: without a per-repository push it would sit on rows reading "queued"
// that the database now has as paused.
func TestScansPauseQueued_reachesEachAffectedRepositoryTab(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	mine := db.Repository{URL: "https://example.com/mine", Name: "mine"}
	other := db.Repository{URL: "https://example.com/other", Name: "other"}
	s.DB.Create(&mine)
	s.DB.Create(&other)
	for _, repoID := range []uint{mine.ID, other.ID} {
		s.DB.Create(&db.Scan{RepositoryID: repoID, Kind: "skill", SkillName: "audit",
			Status: db.ScanQueued, StatusPriority: db.StatusPriorityFor(db.ScanQueued)})
	}

	// Subscribed the way the repo Scans tab is.
	c := s.Broker.Subscribe(0, mine.ID, 0, "scan-status")
	defer s.Broker.Unsubscribe(c)

	w := httptest.NewRecorder()
	s.scansPauseQueued(w, localReq("POST", "/scans/pause-queued"))

	if e := recvEvent(t, c); e.RepoID != mine.ID {
		t.Errorf("RepoID = %d, want %d", e.RepoID, mine.ID)
	}
	// The other repository's event is filtered out for this subscriber, so it
	// must not arrive here even though the same action paused its scan too.
	select {
	case e := <-c.ch:
		t.Errorf("subscriber scoped to repo %d also received %+v", mine.ID, e)
	default:
	}
}

// Nothing changed means nothing to refresh.
func TestScansPauseQueued_noQueuedScansPublishesNothing(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	c := s.Broker.Subscribe(0, 0, 0, "scan-status")
	defer s.Broker.Unsubscribe(c)

	w := httptest.NewRecorder()
	s.scansPauseQueued(w, localReq("POST", "/scans/pause-queued"))

	select {
	case e := <-c.ch:
		t.Errorf("no queued scan to pause, yet published %+v", e)
	default:
	}
}

// bulkResumePaused hand-picks the columns it reads, and enqueueResumedScan
// publishes the repository the resumed scan belongs to: a missing
// repository_id there reaches the unscoped list pages but never the repo tab.
func TestScansResumePaused_publishesRepositoryScopedEvent(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/resume", Name: "resume"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "audit", Status: db.ScanPaused,
		StatusPriority: db.StatusPriorityFor(db.ScanPaused)}
	s.DB.Create(&scan)

	// Subscribed as the repo Scans tab is, so a zero RepoID is filtered out.
	c := s.Broker.Subscribe(0, repo.ID, 0, "scan-status")
	defer s.Broker.Unsubscribe(c)

	w := httptest.NewRecorder()
	s.scansResumePaused(w, localReq("POST", "/scans/resume-paused"))

	if e := recvEvent(t, c); e.ScanID != scan.ID {
		t.Errorf("ScanID = %d, want %d", e.ScanID, scan.ID)
	}
}
