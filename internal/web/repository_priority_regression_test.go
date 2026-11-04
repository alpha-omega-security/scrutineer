package web

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
)

func TestPriorityMaintainersIgnoreCNAMatch(t *testing.T) {
	for _, activity := range []string{"active", "inactive"} {
		t.Run(activity, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			repo := priorityTestRepo(t, s, "maintainer-signals")
			people := db.Skill{Name: "maintainers", OutputKind: "maintainers"}
			cna := db.Skill{Name: "cna-match", OutputKind: "maintainers"}
			for _, skill := range []*db.Skill{&people, &cna} {
				if err := s.DB.Create(skill).Error; err != nil {
					t.Fatal(err)
				}
			}
			assessment := db.Scan{RepositoryID: repo.ID, SkillID: &people.ID, SkillName: people.Name, Status: db.ScanDone,
				Report: fmt.Sprintf(`{"maintainers":[{"login":"person","role":"lead","status":%q}]}`, activity)}
			if err := s.DB.Create(&assessment).Error; err != nil {
				t.Fatal(err)
			}
			newer := db.Scan{RepositoryID: repo.ID, SkillID: &cna.ID, SkillName: cna.Name, Status: db.ScanDone,
				Report: `{"maintainers":[],"disclosure_channel":"security@example.com"}`}
			if err := s.DB.Create(&newer).Error; err != nil {
				t.Fatal(err)
			}
			label := "One maintainer"
			if activity == "inactive" {
				label = "Inactive maintainers"
			}
			row := requireRepoListRow(t, priorityTestPage(t, s, ""), repo.ID)
			if !strings.Contains(row, label) || !strings.Contains(row, fmt.Sprintf(`href="/scans/%d"`, assessment.ID)) || strings.Contains(row, "Maintainer activity unknown") {
				t.Fatalf("CNA report hid the assessment: %s", row)
			}
		})
	}
}

func TestPriorityInventoryInFlightDoesNotRequireRefresh(t *testing.T) {
	for _, status := range []db.ScanStatus{db.ScanQueued, db.ScanRunning, db.ScanPaused} {
		t.Run(string(status), func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			repo := priorityTestRepo(t, s, "inventory-in-flight")
			skill := db.Skill{Name: "dependencies", OutputKind: "dependencies"}
			if err := s.DB.Create(&skill).Error; err != nil {
				t.Fatal(err)
			}
			priorityTestInventory(t, s, repo, skill, `[]`, time.Now())
			attempt := db.Scan{RepositoryID: repo.ID, SkillID: &skill.ID, SkillName: skill.Name, Status: status}
			if err := s.DB.Create(&attempt).Error; err != nil {
				t.Fatal(err)
			}
			row := requireRepoListRow(t, priorityTestPage(t, s, ""), repo.ID)
			if strings.Contains(row, ">stale</span>") {
				t.Fatalf("in-flight replacement marked current inventory stale: %s", row)
			}
			refresh := priorityTestPage(t, s, "&queue=refresh")
			if strings.Contains(refresh, fmt.Sprintf(`<tr id="repo-%d">`, repo.ID)) {
				t.Fatal("in-flight replacement put a fresh inventory in the refresh queue")
			}
			if err := s.DB.Model(&attempt).Update("status", db.ScanFailed).Error; err != nil {
				t.Fatal(err)
			}
			row = requireRepoListRow(t, priorityTestPage(t, s, "&queue=refresh"), repo.ID)
			if !strings.Contains(row, "Newer inventory attempt is incomplete or unusable") {
				t.Fatalf("failed replacement did not require refresh: %s", row)
			}
		})
	}
}

func TestPriorityLanguageSignalCombinesEvidence(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := priorityTestRepo(t, s, "unsafe-languages")
	if err := s.DB.Model(&repo).Update("languages", "C, C++, Objective-C, c, Go").Error; err != nil {
		t.Fatal(err)
	}
	row := requireRepoListRow(t, priorityTestPage(t, s, ""), repo.ID)
	if strings.Count(row, ">Memory-unsafe language</span>") != 1 || !strings.Contains(row, "Contains C, C++, Objective-C;") {
		t.Fatalf("expected one signal with distinct matched languages: %s", row)
	}
}

func TestPriorityViewDoesNotSubscribeToScanUpdates(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	priorityTestRepo(t, s, "refresh-policy")
	const subscription = `sse-connect="/events?events=scan-status"`
	if strings.Contains(priorityTestPage(t, s, ""), subscription) {
		t.Fatal("priority view subscribed to whole-cohort rebuilds on scan status changes")
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/"))
	if w.Code != 200 || !strings.Contains(w.Body.String(), subscription) {
		t.Fatalf("regular repository list lost live updates: HTTP %d", w.Code)
	}
}
