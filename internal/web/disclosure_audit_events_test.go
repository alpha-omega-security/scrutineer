package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/vince"
)

func disclosureEvents(t *testing.T, s *Server, kind string) []db.AuditEvent {
	t.Helper()
	var events []db.AuditEvent
	if err := s.DB.Where("kind = ?", kind).Order("id").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	return events
}

func disclosurePayload(t *testing.T, event db.AuditEvent) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal([]byte(event.Payload), &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func seedDisclosureSkillFinding(t *testing.T, s *Server, skillNames ...string) db.Finding {
	t.Helper()
	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	finding := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "x", Severity: "High", Status: db.FindingTriaged}
	s.DB.Create(&finding)
	for _, name := range skillNames {
		s.DB.Create(&db.Skill{Name: name, Description: "d", Body: "b", OutputFile: "report.json", OutputKind: "freeform", Version: 1, Active: true, Source: "ui"})
	}
	return finding
}

func TestDisclosureRequestedAudit(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedDisclosureSkillFinding(t, s, discloseSkillName, publicIssueSkillName, patchSkillName)
	for _, action := range []string{"disclose", "public-issue", "patch"} {
		w := postForm(t, s, fmt.Sprintf("/findings/%d/%s", f.ID, action), nil)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("%s: status %d: %s", action, w.Code, w.Body)
		}
	}
	events := disclosureEvents(t, s, db.AuditEventDisclosureRequested)
	// report-upstream has no browser route; its skill API launch is covered by
	// TestDisclosureRequestedAuditSkillAPI.
	if len(events) != 2 {
		t.Fatalf("events = %+v, want disclose and public-issue only", events)
	}
	for i, skill := range []string{discloseSkillName, publicIssueSkillName} {
		var scan db.Scan
		if err := s.DB.Where("finding_id = ? AND skill_name = ?", f.ID, skill).First(&scan).Error; err != nil {
			t.Fatal(err)
		}
		event := events[i]
		if event.SubjectType != db.AuditSubjectFinding || event.SubjectID != f.ID || event.Source != db.SourceAnalyst || event.Actor != "" {
			t.Fatalf("event = %+v", event)
		}
		payload := disclosurePayload(t, event)
		if payload["scan_id"] != float64(scan.ID) || payload["skill_name"] != skill || payload["repository_id"] != float64(f.RepositoryID) {
			t.Fatalf("payload = %s", event.Payload)
		}
	}
}

func TestDisclosureRequestedAuditFailureRollsBack(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedDisclosureSkillFinding(t, s, discloseSkillName)
	failFindingAuditInsert(t, s)
	w := postForm(t, s, fmt.Sprintf("/findings/%d/disclose", f.ID), nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var count int64
	s.DB.Model(&db.Scan{}).Where("skill_name = ?", discloseSkillName).Count(&count)
	if count != 0 {
		t.Fatalf("scan survived audit failure: %d", count)
	}
	assertQueuedJobCount(t, s, 0)
}

func TestDisclosureRequestedAuditSkippedWithoutScan(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedDisclosureSkillFinding(t, s)
	w := postForm(t, s, fmt.Sprintf("/findings/%d/disclose", f.ID), nil)
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if events := disclosureEvents(t, s, db.AuditEventDisclosureRequested); len(events) != 0 {
		t.Fatalf("events = %+v", events)
	}
}

func fakeVINCEServer(t *testing.T, s *Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"vrf_id":"VRF#26-07-ABCDE"}`)
	}))
	t.Cleanup(server.Close)
	s.VINCE = vince.Config{BaseURL: server.URL, APIKey: "secret"}
}

func TestDisclosureVINCESubmittedAudit(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	ctx := seedVINCEFinding(t, s)
	fakeVINCEServer(t, s)
	w := postForm(t, s, fmt.Sprintf("/findings/%d/vince", ctx.Finding.ID), validVINCEWebForm())
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	events := disclosureEvents(t, s, db.AuditEventDisclosureVINCESubmitted)
	if len(events) != 1 {
		t.Fatalf("events = %+v", events)
	}
	event := events[0]
	if event.SubjectType != db.AuditSubjectFinding || event.SubjectID != ctx.Finding.ID || event.Source != db.SourceAnalyst {
		t.Fatalf("event = %+v", event)
	}
	payload := disclosurePayload(t, event)
	if payload["vrf_id"] != "VRF#26-07-ABCDE" || payload["attachment"] != false || payload["repository_id"] != float64(ctx.Repository.ID) {
		t.Fatalf("payload = %s", event.Payload)
	}
	if got := disclosureEvents(t, s, db.AuditEventFindingStatusChanged); len(got) != 1 {
		t.Fatalf("status events = %+v", got)
	}
	comms := disclosureEvents(t, s, db.AuditEventDisclosureCommunicationRecorded)
	if len(comms) != 1 || comms[0].Source != db.SourceSystem {
		t.Fatalf("communication events = %+v", comms)
	}
}

func TestDisclosureVINCESubmittedAuditRecordsAttachmentFlag(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	ctx := seedVINCEFinding(t, s)
	if err := s.persistVINCESubmission(ctx.Finding, "VRF#1", "https://vince.example/reports", "secret-name.tar.gz", vince.Report{}, &vince.Attachment{Name: "secret-name.tar.gz", Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	events := disclosureEvents(t, s, db.AuditEventDisclosureVINCESubmitted)
	if len(events) != 1 || disclosurePayload(t, events[0])["attachment"] != true || strings.Contains(events[0].Payload, "secret-name") {
		t.Fatalf("events = %+v", events)
	}
}

func TestDisclosureVINCESubmittedAuditFailureRollsBack(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	ctx := seedVINCEFinding(t, s)
	fakeVINCEServer(t, s)
	// The transaction writes three events. Failing only the last proves the
	// VINCE event itself is inside the transaction, not just an earlier one.
	failAuditKind(t, s, db.AuditEventDisclosureVINCESubmitted)
	w := postForm(t, s, fmt.Sprintf("/findings/%d/vince", ctx.Finding.ID), validVINCEWebForm())
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var finding db.Finding
	s.DB.First(&finding, ctx.Finding.ID)
	if finding.Status != db.FindingReady {
		t.Errorf("status changed despite rollback: %q", finding.Status)
	}
	var refs, comms int64
	s.DB.Model(&db.FindingReference{}).Where("finding_id = ? AND tags = ?", finding.ID, "vince,coordinator").Count(&refs)
	s.DB.Model(&db.FindingCommunication{}).Where("finding_id = ? AND channel = ?", finding.ID, "vince").Count(&comms)
	if refs != 0 || comms != 0 {
		t.Errorf("references=%d communications=%d survived rollback", refs, comms)
	}
	var count int64
	s.DB.Model(&db.AuditEvent{}).Count(&count)
	if count != 0 {
		t.Errorf("audit events = %d after rollback", count)
	}
}

func TestDisclosureDraftUpdatedAuditBrowser(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedFindingForForm(t, s)
	const draft = "Highly sensitive draft body"
	path := fmt.Sprintf("/findings/%d/disclosure-draft", f.ID)
	for range 2 {
		if w := postForm(t, s, path, url.Values{"disclosure_draft": {draft}}); w.Code != http.StatusSeeOther {
			t.Fatalf("status %d: %s", w.Code, w.Body)
		}
	}
	events := disclosureEvents(t, s, db.AuditEventDisclosureDraftUpdated)
	if len(events) != 1 {
		t.Fatalf("events = %+v, want exactly one for an unchanged resave", events)
	}
	if events[0].Source != db.SourceAnalyst || events[0].Actor != "" || strings.Contains(events[0].Payload, "sensitive") {
		t.Fatalf("event = %+v", events[0])
	}
	payload := disclosurePayload(t, events[0])
	if payload["old_length"] != float64(0) || payload["new_length"] != float64(len(draft)) {
		t.Fatalf("payload = %s", events[0].Payload)
	}
}

func TestDisclosureDraftUpdatedAuditSkillAPI(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, token, _ := seedFindingForAPI(t, s)
	scopeAPITokenToFinding(t, s, token, f.ID)
	if err := s.DB.Model(&db.Scan{}).Where("id = ?", f.ScanID).Update("skill_name", discloseSkillName).Error; err != nil {
		t.Fatal(err)
	}
	w := apiReq(t, s, http.MethodPatch, fmt.Sprintf("/api/findings/%d", f.ID), token, `{"fields":{"disclosure_draft":"skill draft"},"by":"claimed"}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	events := disclosureEvents(t, s, db.AuditEventDisclosureDraftUpdated)
	if len(events) != 1 || events[0].Source != db.SourceModel || events[0].Actor != fmt.Sprintf("disclose (scan %d)", f.ScanID) {
		t.Fatalf("events = %+v", events)
	}
	if disclosurePayload(t, events[0])["scan_id"] != float64(f.ScanID) {
		t.Fatalf("payload = %s", events[0].Payload)
	}
}

func TestDisclosureCommunicationRecordedAudit(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, token, _ := seedFindingForAPI(t, s)
	scopeAPITokenToFinding(t, s, token, f.ID)
	if err := s.DB.Model(&db.Scan{}).Where("id = ?", f.ScanID).Update("skill_name", discloseSkillName).Error; err != nil {
		t.Fatal(err)
	}
	form := url.Values{"channel": {"email"}, "direction": {"outbound"}, "actor": {"alice@example.org"}, "body": {"private body"}, "offered_help": {"patch"}}
	if w := postForm(t, s, fmt.Sprintf("/findings/%d/communications", f.ID), form); w.Code != http.StatusSeeOther {
		t.Fatalf("form status %d: %s", w.Code, w.Body)
	}
	w := apiReq(t, s, http.MethodPost, fmt.Sprintf("/api/findings/%d/communications", f.ID), token,
		`{"channel":"github","direction":"inbound","actor":"bob","body":"private reply"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("api status %d: %s", w.Code, w.Body)
	}
	events := disclosureEvents(t, s, db.AuditEventDisclosureCommunicationRecorded)
	if len(events) != 2 {
		t.Fatalf("events = %+v", events)
	}
	if events[0].Source != db.SourceAnalyst || events[0].Actor != "" || disclosurePayload(t, events[0])["offered_help"] != true {
		t.Fatalf("form event = %+v", events[0])
	}
	if events[1].Source != db.SourceModel || events[1].Actor != fmt.Sprintf("disclose (scan %d)", f.ScanID) ||
		disclosurePayload(t, events[1])["scan_id"] != float64(f.ScanID) || disclosurePayload(t, events[1])["offered_help"] != false {
		t.Fatalf("api event = %+v", events[1])
	}
	for _, event := range events {
		for _, secret := range []string{"private", "alice@example.org", "bob", "patch"} {
			if strings.Contains(event.Payload, secret) || strings.Contains(event.Actor, secret) {
				t.Fatalf("%q leaked: %+v", secret, event)
			}
		}
	}
}

func TestDisclosureCommunicationAuditFailureRollsBack(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedFindingForForm(t, s)
	failFindingAuditInsert(t, s)
	form := url.Values{"channel": {"email"}, "direction": {"outbound"}, "body": {"b"}}
	if w := postForm(t, s, fmt.Sprintf("/findings/%d/communications", f.ID), form); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var count int64
	s.DB.Model(&db.FindingCommunication{}).Count(&count)
	if count != 0 {
		t.Fatalf("communications = %d after rollback", count)
	}
}

func TestDisclosureChannelChangedAuditBrowser(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/rails/rails", Name: "rails"}
	s.DB.Create(&repo)
	sub := db.Subproject{RepositoryID: repo.ID, Path: "activesupport", Name: "activesupport"}
	s.DB.Create(&sub)
	repoPath := fmt.Sprintf("/repositories/%d/disclosure-channel", repo.ID)
	subPath := subURL(repo.ID, sub.ID, "/disclosure-channel")
	for _, path := range []string{repoPath, repoPath, subPath, subPath} {
		w := postForm(t, s, path, url.Values{"disclosure_channel": {" sec@example.org "}})
		if w.Code != http.StatusSeeOther {
			t.Fatalf("%s: status %d: %s", path, w.Code, w.Body)
		}
	}
	events := disclosureEvents(t, s, db.AuditEventDisclosureChannelChanged)
	if len(events) != 2 {
		t.Fatalf("events = %+v, want one per real change", events)
	}
	for _, event := range events {
		if event.SubjectType != db.AuditSubjectRepository || event.SubjectID != repo.ID || event.Source != db.SourceAnalyst || event.Actor != "" {
			t.Fatalf("event = %+v", event)
		}
	}
	if p := disclosurePayload(t, events[0]); p["scope"] != "repository" || p["new_value"] != "sec@example.org" {
		t.Fatalf("repo payload = %s", events[0].Payload)
	}
	if p := disclosurePayload(t, events[1]); p["scope"] != "subproject" || p["subproject_id"] != float64(sub.ID) || p["subproject_path"] != "activesupport" {
		t.Fatalf("subproject payload = %s", events[1].Payload)
	}
}

func TestDisclosureChannelAuditFailureRollsBack(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/rails/rails", Name: "rails", DisclosureChannel: "old@example.org"}
	s.DB.Create(&repo)
	sub := db.Subproject{RepositoryID: repo.ID, Path: "activesupport", Name: "activesupport", DisclosureChannel: "old@example.org"}
	s.DB.Create(&sub)
	failFindingAuditInsert(t, s)
	form := url.Values{"disclosure_channel": {"new@example.org"}}
	for _, path := range []string{fmt.Sprintf("/repositories/%d/disclosure-channel", repo.ID), subURL(repo.ID, sub.ID, "/disclosure-channel")} {
		if w := postForm(t, s, path, form); w.Code != http.StatusInternalServerError {
			t.Fatalf("%s: status %d: %s", path, w.Code, w.Body)
		}
	}
	var gotRepo db.Repository
	var gotSub db.Subproject
	s.DB.First(&gotRepo, repo.ID)
	s.DB.First(&gotSub, sub.ID)
	if gotRepo.DisclosureChannel != "old@example.org" || gotSub.DisclosureChannel != "old@example.org" {
		t.Fatalf("channels = %q %q", gotRepo.DisclosureChannel, gotSub.DisclosureChannel)
	}
}

// failAuditKind fails only the audit event inserts of one kind, so a test can
// target the last event of a transaction that writes several.
func failAuditKind(t *testing.T, s *Server, kind string) {
	t.Helper()
	const callback = "test:fail_audit_kind"
	if err := s.DB.Callback().Create().Before("gorm:create").Register(callback, func(tx *gorm.DB) {
		if event, ok := tx.Statement.Dest.(*db.AuditEvent); ok && event.Kind == kind {
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

// A skill chaining a disclosure through the skill API is audited too, with its
// own source and the calling scan recorded beside the launched scan rather
// than overwriting it.
func TestDisclosureRequestedAuditSkillAPI(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := seedDisclosureSkillFinding(t, s, reportUpstreamSkillName)
	callerSkill := db.Skill{Name: "triage-caller", Description: "d", Body: "b", OutputFile: "report.json", OutputKind: "freeform", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&callerSkill)
	caller := db.Scan{RepositoryID: f.RepositoryID, Kind: "skill", Status: db.ScanRunning, SkillID: &callerSkill.ID,
		SkillName: callerSkill.Name, APIToken: "caller-token", StartedAt: new(time.Now())}
	s.DB.Create(&caller)

	w := apiReq(t, s, "POST", fmt.Sprintf("/api/findings/%d/skills/%s/run", f.ID, reportUpstreamSkillName), caller.APIToken, "{}")
	if w.Code >= http.StatusMultipleChoices {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	events := disclosureEvents(t, s, db.AuditEventDisclosureRequested)
	if len(events) != 1 {
		t.Fatalf("events = %+v, want one", events)
	}
	var launched db.Scan
	if err := s.DB.Where("finding_id = ? AND skill_name = ?", f.ID, reportUpstreamSkillName).First(&launched).Error; err != nil {
		t.Fatal(err)
	}
	event := events[0]
	if event.Source != db.SourceModel || !strings.Contains(event.Actor, fmt.Sprintf("scan %d", caller.ID)) {
		t.Fatalf("event source=%q actor=%q, want the calling scan", event.Source, event.Actor)
	}
	payload := disclosurePayload(t, event)
	if payload["scan_id"] != float64(launched.ID) || payload["skill_name"] != reportUpstreamSkillName {
		t.Fatalf("launched scan overwritten by the caller: %s", event.Payload)
	}
	if payload["caller_scan_id"] != float64(caller.ID) || payload["caller_skill_name"] != callerSkill.Name {
		t.Fatalf("caller not recorded: %s", event.Payload)
	}
}

// assertFeedChannelEvent checks a feed import wrote one system event for the
// channel it filled and none for the channel it was not allowed to replace.
func assertFeedChannelEvent(t *testing.T, s *Server, filledID, ownedID uint, feed, channel string) {
	t.Helper()
	var filled, owned []db.AuditEvent
	s.DB.Where("kind = ? AND subject_id = ?", db.AuditEventDisclosureChannelChanged, filledID).Find(&filled)
	s.DB.Where("kind = ? AND subject_id = ?", db.AuditEventDisclosureChannelChanged, ownedID).Find(&owned)
	if len(owned) != 0 {
		t.Errorf("events for a channel the feed may not replace = %+v", owned)
	}
	if len(filled) != 1 {
		t.Fatalf("events for the filled channel = %+v, want one", filled)
	}
	if filled[0].Source != db.SourceSystem || filled[0].Actor != feed {
		t.Errorf("event source=%q actor=%q, want system and the feed", filled[0].Source, filled[0].Actor)
	}
	payload := disclosurePayload(t, filled[0])
	if payload["old_value"] != "" || payload["new_value"] != channel {
		t.Errorf("payload = %s", filled[0].Payload)
	}
}
