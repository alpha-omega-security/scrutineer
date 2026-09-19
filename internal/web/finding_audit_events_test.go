package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"scrutineer/internal/db"

	"gorm.io/gorm"
)

func readFindingAuditEvents(t *testing.T, s *Server, findingID uint) []db.AuditEvent {
	t.Helper()
	var events []db.AuditEvent
	if err := s.DB.Where("subject_type = ? AND subject_id = ?", db.AuditSubjectFinding, findingID).Order("id").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	return events
}

func TestFindingMutationAuditBrowser(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedFindingForForm(t, s)
	for _, tc := range []struct {
		action, kind string
		form         url.Values
	}{
		{"status", db.AuditEventFindingStatusChanged, url.Values{"status": {"triaged"}}},
		{"fields", db.AuditEventFindingSeverityChanged, url.Values{"severity": {"Low"}}},
		{"labels", db.AuditEventFindingLabelsChanged, url.Values{"labels": {" needs-info, needs-info "}}},
	} {
		path := fmt.Sprintf("/findings/%d/%s", f.ID, tc.action)
		for range 2 {
			w := postForm(t, s, path, tc.form)
			if w.Code != http.StatusSeeOther {
				t.Fatalf("%s: status %d: %s", tc.action, w.Code, w.Body)
			}
		}
		events := readFindingAuditEvents(t, s, f.ID)
		if len(events) == 0 {
			t.Fatal("mutation produced no audit event")
		}
		last := events[len(events)-1]
		if last.Kind != tc.kind || last.Source != db.SourceAnalyst || last.Actor != "" {
			t.Fatalf("event = %+v", last)
		}
	}
	if events := readFindingAuditEvents(t, s, f.ID); len(events) != 3 {
		t.Fatalf("events = %+v", events)
	}
}

func TestFindingMutationAuditAPIAttribution(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, token, other := seedFindingForAPI(t, s)
	scopeAPITokenToFinding(t, s, token, f.ID)
	if err := s.DB.Model(&db.Scan{}).Where("id = ?", f.ScanID).Update("skill_name", "verify").Error; err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/findings/%d", f.ID)
	for range 2 {
		w := apiReq(t, s, http.MethodPatch, path, token, `{"fields":{"severity":"Low","status":"triaged"},"by":"claimed-operator"}`)
		if w.Code != http.StatusNoContent {
			t.Fatalf("PATCH status %d: %s", w.Code, w.Body)
		}
		w = apiReq(t, s, http.MethodPut, path+"/labels", token, `{"labels":["reviewed"]}`)
		if w.Code != http.StatusNoContent {
			t.Fatalf("labels status %d: %s", w.Code, w.Body)
		}
	}
	events := readFindingAuditEvents(t, s, f.ID)
	if len(events) != 3 {
		t.Fatalf("events = %+v", events)
	}
	for _, event := range events {
		if event.Source != db.SourceModel || event.Actor != fmt.Sprintf("verify (scan %d)", f.ScanID) {
			t.Fatalf("event = %+v", event)
		}
		var payload struct {
			ScanID       uint   `json:"scan_id"`
			SkillName    string `json:"skill_name"`
			RepositoryID uint   `json:"repository_id"`
		}
		if err := json.Unmarshal([]byte(event.Payload), &payload); err != nil {
			t.Fatal(err)
		}
		if payload.ScanID != f.ScanID || payload.SkillName != "verify" || payload.RepositoryID != f.RepositoryID {
			t.Fatalf("payload = %s", event.Payload)
		}
		if strings.Contains(event.Payload, token) || strings.Contains(event.Payload, "claimed-operator") {
			t.Fatalf("untrusted or secret metadata: %s", event.Payload)
		}
	}
	var history []db.FindingHistory
	if err := s.DB.Where("finding_id = ?", f.ID).Find(&history).Error; err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 {
		t.Fatalf("history = %+v", history)
	}
	for _, entry := range history {
		if entry.By != "claimed-operator" {
			t.Fatalf("legacy history attribution changed: %+v", entry)
		}
	}
	if w := apiReq(t, s, http.MethodPatch, path, other, `{"fields":{"severity":"Critical"}}`); w.Code != http.StatusForbidden {
		t.Fatalf("unauthorized status = %d", w.Code)
	}
	if w := apiReq(t, s, http.MethodPut, path+"/labels", other, `{"labels":["forbidden"]}`); w.Code != http.StatusForbidden {
		t.Fatalf("unauthorized labels status = %d", w.Code)
	}
	if w := apiReq(t, s, http.MethodPatch, path, token, `{"fields":{"severity":"Critical","status":"invalid"}}`); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid PATCH status = %d", w.Code)
	}
	if events := readFindingAuditEvents(t, s, f.ID); len(events) != 3 {
		t.Fatalf("failed request left events: %+v", events)
	}
	var got db.Finding
	if err := s.DB.First(&got, f.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Severity != "Low" {
		t.Fatalf("partial PATCH was not rolled back: %s", got.Severity)
	}
}

func failFindingAuditInsert(t *testing.T, s *Server) {
	t.Helper()
	const callback = "test:fail_audit_insert"
	if err := s.DB.Callback().Create().Before("gorm:create").Register(callback, func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "AuditEvent" {
			_ = tx.AddError(errors.New("audit unavailable"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.DB.Callback().Create().Remove(callback); err != nil {
			t.Error(err)
		}
	})
}

func TestFindingMutationAuditHandlersRollback(t *testing.T) {
	for _, mode := range []string{"browser fields", "browser labels", "API fields", "API labels"} {
		t.Run(mode, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			f, token, _ := seedFindingForAPI(t, s)
			scopeAPITokenToFinding(t, s, token, f.ID)
			failFindingAuditInsert(t, s)
			var status int
			switch mode {
			case "browser fields":
				status = postForm(t, s, fmt.Sprintf("/findings/%d/fields", f.ID), url.Values{"severity": {"Low"}}).Code
			case "browser labels":
				status = postForm(t, s, fmt.Sprintf("/findings/%d/labels", f.ID), url.Values{"labels": {"new-label"}}).Code
			case "API fields":
				status = apiReq(t, s, http.MethodPatch, fmt.Sprintf("/api/findings/%d", f.ID), token, `{"fields":{"severity":"Low"}}`).Code
			case "API labels":
				status = apiReq(t, s, http.MethodPut, fmt.Sprintf("/api/findings/%d/labels", f.ID), token, `{"labels":["new-label"]}`).Code
			}
			wantStatus := http.StatusUnprocessableEntity
			if strings.HasSuffix(mode, "labels") {
				wantStatus = http.StatusInternalServerError
			}
			if status != wantStatus {
				t.Fatalf("status = %d, want %d", status, wantStatus)
			}
			var got db.Finding
			if err := s.DB.Preload("Labels").First(&got, f.ID).Error; err != nil {
				t.Fatal(err)
			}
			if got.Severity != f.Severity || len(got.Labels) != 0 {
				t.Fatalf("failed write persisted: %+v", got)
			}
			if events := readFindingAuditEvents(t, s, f.ID); len(events) != 0 {
				t.Fatalf("failed write left events: %+v", events)
			}
		})
	}
}
