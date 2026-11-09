package worker

import (
	"fmt"
	"testing"
	"time"

	"scrutineer/internal/db"
)

func TestDoSkillMaintainerActivityRefreshesWithinRepository(t *testing.T) {
	w, scan := costCapFixture(t, 0)
	if err := w.DB.Model(&db.Skill{}).Where("id = ?", *scan.SkillID).
		Updates(map[string]any{"name": "maintainers", "output_kind": "maintainers"}).Error; err != nil {
		t.Fatal(err)
	}
	shared := db.Maintainer{Login: "person", Name: "Established", Email: "real@example.org", Status: db.MaintainerActive, Notes: "operator note"}
	if err := w.DB.Create(&shared).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	pushed := now.AddDate(-3, 0, 0)
	if err := w.DB.Model(&db.Repository{}).Where("id = ?", scan.RepositoryID).Update("pushed_at", pushed).Error; err != nil {
		t.Fatal(err)
	}
	metadata := db.Scan{RepositoryID: scan.RepositoryID, Kind: JobSkill, Status: db.ScanDone, SkillName: "metadata"}
	if err := w.DB.Create(&metadata).Error; err != nil {
		t.Fatal(err)
	}
	runMaintainerActivityJob(t, w, scan.RepositoryID, *scan.SkillID, "active")
	runMaintainerActivityJob(t, w, scan.RepositoryID, *scan.SkillID, "inactive")
	runMaintainerActivityJob(t, w, scan.RepositoryID, *scan.SkillID, "unknown")
	other := db.Repository{URL: "https://example.com/other", Name: "other"}
	if err := w.DB.Create(&other).Error; err != nil {
		t.Fatal(err)
	}
	runMaintainerActivityJob(t, w, other.ID, *scan.SkillID, "active")
	requireMaintainerActivity(t, w, scan.RepositoryID, db.MaintainerInactive)
	requireMaintainerActivity(t, w, other.ID, db.MaintainerActive)
	assessment, err := db.RefreshRepositoryHealth(w.DB, scan.RepositoryID, now)
	if err != nil || assessment.Health != db.RepositoryHealthAbandoned {
		t.Fatalf("inactive repository health = %+v, err=%v", assessment, err)
	}
	var stored db.Repository
	if err := w.DB.First(&stored, scan.RepositoryID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Health != db.RepositoryHealthAbandoned {
		t.Fatalf("persisted health = %s", stored.Health)
	}
	runMaintainerActivityJob(t, w, scan.RepositoryID, *scan.SkillID, "active")
	requireMaintainerActivity(t, w, scan.RepositoryID, db.MaintainerActive)
	var got db.Maintainer
	if err := w.DB.First(&got, shared.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Name != shared.Name || got.Email != shared.Email || got.Status != shared.Status || got.Notes != shared.Notes {
		t.Fatalf("report overwrote shared profile: %+v", got)
	}
}

func TestDoSkillMaintainerUnknownActivityDoesNotInheritAnotherRepository(t *testing.T) {
	for _, status := range []string{"unknown", "", "unrecognized"} {
		t.Run("status="+status, func(t *testing.T) {
			w, scan := costCapFixture(t, 0)
			if err := w.DB.Model(&db.Skill{}).Where("id = ?", *scan.SkillID).
				Updates(map[string]any{"name": "maintainers", "output_kind": "maintainers"}).Error; err != nil {
				t.Fatal(err)
			}
			runMaintainerActivityJob(t, w, scan.RepositoryID, *scan.SkillID, "active")
			other := db.Repository{URL: "https://example.com/other", Name: "other"}
			if err := w.DB.Create(&other).Error; err != nil {
				t.Fatal(err)
			}
			runMaintainerActivityJob(t, w, other.ID, *scan.SkillID, status)
			requireMaintainerActivity(t, w, other.ID, db.MaintainerUnknown)
			var activity db.MaintainerActivity
			if err := w.DB.Where("repository_id = ?", other.ID).First(&activity).Error; err != nil {
				t.Fatal(err)
			}
			if activity.Status != db.MaintainerUnknown {
				t.Fatalf("persisted activity = %q, want unknown", activity.Status)
			}
			runMaintainerActivityJob(t, w, other.ID, *scan.SkillID, "active")
			runMaintainerActivityJob(t, w, other.ID, *scan.SkillID, status)
			requireMaintainerActivity(t, w, other.ID, db.MaintainerActive)
			requireMaintainerActivity(t, w, scan.RepositoryID, db.MaintainerActive)
		})
	}
}

func runMaintainerActivityJob(t *testing.T, w *Worker, repositoryID, skillID uint, status string) {
	t.Helper()
	scan := db.Scan{RepositoryID: repositoryID, SkillID: &skillID, Kind: JobSkill, Status: db.ScanQueued, Model: "fake"}
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	report := fmt.Sprintf(`{"maintainers":[{"login":"person","name":"Reported name","email":"reported@example.org","role":"lead","status":%q,"evidence":"repository activity"}]}`, status)
	w.Runner = fakeRunner{skillRes: SkillResult{Report: report}}
	if got := runCapScan(t, w, &scan); got.Status != db.ScanDone {
		t.Fatalf("maintainers scan: status=%s error=%s", got.Status, got.Error)
	}
}

func requireMaintainerActivity(t *testing.T, w *Worker, repositoryID uint, want db.MaintainerStatus) {
	t.Helper()
	rows, err := db.RepositoryMaintainers(w.DB, repositoryID)
	if err != nil || len(rows) != 1 || rows[0].Status != want {
		t.Fatalf("repository %d maintainers = %+v, err=%v, want %s", repositoryID, rows, err, want)
	}
}
