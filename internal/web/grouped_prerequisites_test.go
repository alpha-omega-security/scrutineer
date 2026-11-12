package web

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
	"scrutineer/internal/worker"
)

func TestManualScanWaitsForRepositoryPrerequisites(t *testing.T) {
	for _, action := range []string{"scan", "scan-all"} {
		for _, status := range []db.ScanStatus{db.ScanQueued, db.ScanRunning, db.ScanPaused} {
			t.Run(action+"/"+string(status), func(t *testing.T) {
				testManualScanPrerequisites(t, action, status)
			})
		}
	}
}

func testManualScanPrerequisites(t *testing.T, action string, status db.ScanStatus) {
	t.Helper()
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/manual-prerequisites", Name: "manual-prerequisites"}
	deepDive := db.Skill{Name: deepDiveSkillName, Body: "Audit", Requires: "threat-model\nsemgrep", OutputFile: "report.json", OutputKind: "findings", Active: true}
	for _, row := range []any{&repo, &deepDive} {
		if err := s.DB.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DB.Create(&db.Subproject{RepositoryID: repo.ID, Path: "core", Name: "core"}).Error; err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{threatModelSkillName, "semgrep"} {
		skill := db.Skill{Name: name, Body: "Inspect", Active: true}
		if err := s.DB.Create(&skill).Error; err != nil {
			t.Fatal(err)
		}
		for _, prior := range []db.ScanStatus{db.ScanDone, status} {
			scan := db.Scan{RepositoryID: repo.ID, SkillID: &skill.ID, SkillName: name, Kind: worker.JobSkill, Status: prior, ScanGroup: "triage-current"}
			if err := s.DB.Create(&scan).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, localReq(http.MethodPost, fmt.Sprintf("/repositories/%d/%s", repo.ID, action)))
	if response.Code != http.StatusSeeOther {
		t.Fatalf("HTTP %d: %s", response.Code, response.Body)
	}
	var scan db.Scan
	if err := s.DB.Where("repository_id = ? AND skill_name = ?", repo.ID, deepDive.Name).First(&scan).Error; err != nil {
		t.Fatal(err)
	}
	if scan.ScanGroup == "" || scan.ScanGroup == "triage-current" {
		t.Fatalf("manual scan group = %q", scan.ScanGroup)
	}
	w := s.Worker
	w.Log, w.DataDir, w.Runner = s.Log, t.TempDir(), fallbackAuditRunner{}
	w.PrereqRetryDelay = time.Second
	w.PrepareRepoSrc = func(_ context.Context, _, _, root string, _ func(worker.Event)) (string, error) {
		return "abc", os.MkdirAll(filepath.Join(root, "src", scan.SubPath), 0o755)
	}
	finalized := make(chan struct{})
	onFinalized := w.OnScanFinalized
	w.OnScanFinalized = func(completed *db.Scan) {
		onFinalized(completed)
		if completed.ID == scan.ID {
			close(finalized)
		}
	}
	w.Register(s.Queue)
	s.Queue.Reconfigure(1)
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() { s.Queue.Start(ctx); close(stopped) }()
	defer func() { cancel(); <-stopped }()
	waitForPrerequisiteRetry(t, s, scan.ID, finalized)
	if err := s.DB.First(&scan, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if scan.Status != db.ScanQueued || scan.StartedAt != nil {
		t.Fatalf("audit started before prerequisites finished: %+v", scan)
	}
	if err := s.DB.Model(&db.Scan{}).Where("repository_id = ? AND status = ? AND skill_name IN ?",
		repo.ID, status, []string{threatModelSkillName, "semgrep"}).Update("status", db.ScanDone).Error; err != nil {
		t.Fatal(err)
	}
	select {
	case <-finalized:
	case <-time.After(10 * time.Second):
		t.Fatal("audit did not resume after prerequisites completed")
	}
	if err := s.DB.First(&scan, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if scan.Status != db.ScanDone || scan.Report != `{"findings":[]}` {
		t.Fatalf("resumed audit = %+v", scan)
	}
}

func waitForPrerequisiteRetry(t *testing.T, s *Server, scanID uint, finalized <-chan struct{}) {
	t.Helper()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	waiting := false
	for !waiting {
		select {
		case <-finalized:
			t.Fatal("audit dispatched while prerequisites remained in flight")
		case <-timeout.C:
			t.Fatal("audit was not requeued for prerequisite wait")
		case <-tick.C:
			var messages []struct{ Body []byte }
			if err := s.DB.Table("goqite").Select("body").Find(&messages).Error; err != nil {
				t.Fatal(err)
			}
			for _, message := range messages {
				var job struct{ Message []byte }
				if err := gob.NewDecoder(bytes.NewReader(message.Body)).Decode(&job); err != nil {
					t.Fatal(err)
				}
				var payload queue.Payload
				if err := json.Unmarshal(job.Message, &payload); err != nil {
					t.Fatal(err)
				}
				waiting = waiting || (payload.ScanID == scanID && payload.Attempt > 0)
			}
		}
	}
}
