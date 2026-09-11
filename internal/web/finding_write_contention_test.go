package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	s.DB = s.DB.WithContext(ctx)
	lock := s.DB.Begin()
	if lock.Error != nil {
		t.Fatal(lock.Error)
	}
	t.Cleanup(func() { _ = lock.Rollback().Error })
	if err := lock.Model(&db.Finding{}).Where("id = ?", f.ID).UpdateColumn("title", "lock holder").Error; err != nil {
		t.Fatal(err)
	}

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
	responses := make(chan *httptest.ResponseRecorder, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if api {
			responses <- apiReq(t, s, http.MethodPatch, fmt.Sprintf("/api/findings/%d", f.ID), token,
				`{"fields":{"severity":"Medium","cve_id":"CVE-2026-12345"}}`)
		} else {
			responses <- postForm(t, s, fmt.Sprintf("/findings/%d/fields", f.ID),
				url.Values{"severity": {"Medium"}, "cve_id": {"CVE-2026-12345"}})
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	select {
	case <-busy:
	case response := <-responses:
		t.Fatalf("request returned before observing SQLITE_BUSY: %d %s", response.Code, response.Body)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for request to contend with writer")
	}
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
