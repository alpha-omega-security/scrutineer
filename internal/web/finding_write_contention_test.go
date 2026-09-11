package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"

	"gorm.io/gorm"
)

func TestFindingEdits_waitForActiveWriter(t *testing.T) {
	for _, api := range []bool{false, true} {
		t.Run(fmt.Sprintf("api=%t", api), func(t *testing.T) {
			testFindingEditWaitsForWriter(t, api)
		})
	}
}

func testFindingEditWaitsForWriter(t *testing.T, api bool) {
	t.Helper()
	s, cleanup := newTestServer(t)
	t.Cleanup(cleanup)
	f, token, _ := seedFindingForAPI(t, s)
	scopeAPITokenToFinding(t, s, token, f.ID)
	lock := holdFindingEditWriteLock(t, s.DB, f.ID)
	responses, busy := startFindingEdit(t, s, t.Context(), api, f.ID, token)
	waitForFindingEditBusy(t, busy, responses)
	select {
	case response := <-responses:
		t.Fatalf("request returned while lock was held: %d %s", response.Code, response.Body)
	case <-time.After(200 * time.Millisecond):
	}
	if err := lock.Commit().Error; err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-responses:
		wantStatus := http.StatusSeeOther
		if api {
			wantStatus = http.StatusNoContent
		}
		if response.Code != wantStatus {
			t.Fatalf("status = %d, want %d; body=%s", response.Code, wantStatus, response.Body)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for request after lock release")
	}
	var stored db.Finding
	if err := s.DB.First(&stored, f.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Severity != "Medium" || stored.CVEID != "CVE-2026-12345" {
		t.Errorf("finding = severity %q, cve_id %q", stored.Severity, stored.CVEID)
	}
	var history []db.FindingHistory
	if err := s.DB.Where("finding_id = ?", f.ID).Find(&history).Error; err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 {
		t.Errorf("history len = %d, want 2: %+v", len(history), history)
	}
}

func TestFindingEdits_lockWaitStops(t *testing.T) {
	for _, api := range []bool{false, true} {
		for _, mode := range []string{"cancel", "caller deadline", "retry deadline"} {
			t.Run(fmt.Sprintf("api=%t/%s", api, mode), func(t *testing.T) {
				testFindingEditLockWaitStops(t, api, mode)
			})
		}
	}
}

func testFindingEditLockWaitStops(t *testing.T, api bool, mode string) {
	t.Helper()
	s, cleanup := newTestServer(t)
	t.Cleanup(cleanup)
	f, token, _ := seedFindingForAPI(t, s)
	scopeAPITokenToFinding(t, s, token, f.ID)
	// Keep the writer independent so ending the request cannot release its lock.
	lock := holdFindingEditWriteLock(t, s.DB, f.ID)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if mode == "caller deadline" {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, 200*time.Millisecond)
		defer stop()
	}
	responses, busy := startFindingEdit(t, s, ctx, api, f.ID, token)
	waitForFindingEditBusy(t, busy, responses)
	wantErr := context.DeadlineExceeded
	if mode == "cancel" {
		cancel()
		wantErr = context.Canceled
	}
	responseTimeout := 2 * time.Second
	if mode == "retry deadline" {
		responseTimeout = 10 * time.Second
	}
	select {
	case response := <-responses:
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503; body=%s", response.Code, response.Body)
		}
		if !strings.Contains(response.Body.String(), wantErr.Error()) {
			t.Errorf("body = %s, want %q", response.Body, wantErr)
		}
	case <-time.After(responseTimeout):
		t.Fatal("request did not stop within its cancellation or retry budget")
	}
	if err := lock.Commit().Error; err != nil {
		t.Fatalf("independent writer could not commit: %v", err)
	}
	var stored db.Finding
	if err := s.DB.First(&stored, f.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Severity != f.Severity || stored.CVEID != f.CVEID {
		t.Errorf("finding changed after failed write: severity %q, cve_id %q", stored.Severity, stored.CVEID)
	}
	var history []db.FindingHistory
	if err := s.DB.Where("finding_id = ?", f.ID).Find(&history).Error; err != nil {
		t.Fatal(err)
	}
	if len(history) != 0 {
		t.Errorf("history = %+v, want none after failed write", history)
	}
}

func holdFindingEditWriteLock(t *testing.T, gdb *gorm.DB, findingID uint) *gorm.DB {
	t.Helper()
	lock := gdb.Begin()
	if lock.Error != nil {
		t.Fatal(lock.Error)
	}
	t.Cleanup(func() { _ = lock.Rollback().Error })
	if err := lock.Model(&db.Finding{}).Where("id = ?", findingID).UpdateColumn("title", "lock holder").Error; err != nil {
		t.Fatal(err)
	}
	return lock
}

func startFindingEdit(t *testing.T, s *Server, ctx context.Context, api bool, findingID uint, token string) (<-chan *httptest.ResponseRecorder, <-chan struct{}) {
	t.Helper()
	busy := make(chan struct{}, 1)
	const callbackName = "test:observe_edit_busy"
	const sqliteBusyCode = 5
	if err := s.DB.Callback().Update().After("gorm:update").Register(callbackName, func(d *gorm.DB) {
		var sqliteErr interface{ Code() int }
		if !errors.As(d.Error, &sqliteErr) || sqliteErr.Code() != sqliteBusyCode {
			return
		}
		select {
		case busy <- struct{}{}:
		default:
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.DB.Callback().Update().Remove(callbackName); err != nil {
			t.Errorf("remove busy observer: %v", err)
		}
	})
	ctx, cancel := context.WithCancel(ctx)
	r := findingEditRequest(ctx, api, findingID, token)
	handler := s.Handler()
	responses := make(chan *httptest.ResponseRecorder, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, r)
		responses <- response
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return responses, busy
}

func findingEditRequest(ctx context.Context, api bool, findingID uint, token string) *http.Request {
	var r *http.Request
	if api {
		r = httptest.NewRequestWithContext(ctx, http.MethodPatch, fmt.Sprintf("/api/findings/%d", findingID),
			strings.NewReader(`{"fields":{"severity":"Medium","cve_id":"CVE-2026-12345"}}`))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
	} else {
		form := url.Values{"severity": {"Medium"}, "cve_id": {"CVE-2026-12345"}}
		r = httptest.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("/findings/%d/fields", findingID), strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	r.Host = testHost
	return r
}

func waitForFindingEditBusy(t *testing.T, busy <-chan struct{}, responses <-chan *httptest.ResponseRecorder) {
	t.Helper()
	select {
	case <-busy:
	case response := <-responses:
		t.Fatalf("request returned before observing SQLITE_BUSY: %d %s", response.Code, response.Body)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for request to contend with writer")
	}
}
