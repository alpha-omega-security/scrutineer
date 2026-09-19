package worker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
)

func TestFindingFeedbackSkillScope(t *testing.T) {
	fixture := newControlsFixtureInSubPath(t, "", "parse.go:12", "lib")
	if err := db.RejectFinding(fixture.gdb, fixture.finding.ID, "false_positive", "guarded at parse.go:10", "reviewer"); err != nil {
		t.Fatal(err)
	}
	w := Worker{DB: fixture.gdb}
	work := t.TempDir()
	if err := stageDiffFiles(work, "patch", []changedFile{{Status: "R100", Path: "lib/new.go", Old: "lib/parse.go"}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, mode, exploration string
		finding                 bool
		want                    int
	}{
		{"revalidate", "", "", true, 1},
		{"revalidate", "", "", false, 0},
		{"verify", "", "", true, 0},
		{"security-deep-dive", db.ScanRescanModeDiff, "", false, 1},
		{"security-deep-dive", "", "", false, 0},
		{"security-deep-dive", db.ScanRescanModeDiff, "random-dig", false, 0},
	} {
		t.Run(tc.name+tc.mode+tc.exploration, func(t *testing.T) {
			scan := db.Scan{RepositoryID: fixture.repo.ID, Repository: fixture.repo, RescanMode: tc.mode, ExplorationMode: tc.exploration}
			if tc.finding {
				scan.FindingID = &fixture.finding.ID
			}
			rows, err := w.findingFeedback(context.Background(), work, &scan, &db.Skill{Name: tc.name})
			if err != nil || len(rows) != tc.want {
				t.Fatalf("rows = %+v, err = %v", rows, err)
			}
		})
	}
	scan := db.Scan{RepositoryID: fixture.repo.ID + 1, FindingID: &fixture.finding.ID}
	if _, err := w.findingFeedback(context.Background(), work, &scan, &db.Skill{Name: "revalidate"}); err == nil {
		t.Fatal("accepted foreign finding")
	}
}

func TestFindingFeedbackStagedInBothContexts(t *testing.T) {
	fixture := newControlsFixtureInSubPath(t, "", "parse.go:12", "lib")
	if err := db.RejectFinding(fixture.gdb, fixture.finding.ID, "false_positive", "guarded", "reviewer"); err != nil {
		t.Fatal(err)
	}
	w := Worker{DB: fixture.gdb}
	work := t.TempDir()
	skillDir := filepath.Join(work, ".claude", "skills", "security-deep-dive")
	if err := stageDiffFiles(work, "patch", []changedFile{{Status: "M", Path: "lib/parse.go"}}); err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: fixture.repo.ID, Repository: fixture.repo, RescanMode: db.ScanRescanModeDiff}
	skill := db.Skill{Name: "security-deep-dive", Body: "# Test", Source: "ui"}
	doc, err := w.stageWorkspace(context.Background(), work, skillDir, &scan, &skill)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Scrutineer.AnalystFeedback) != 1 {
		t.Fatalf("context = %+v", doc)
	}
	for _, dir := range []string{work, skillDir} {
		data, err := os.ReadFile(filepath.Join(dir, "context.json"))
		if err != nil {
			t.Fatal(err)
		}
		var stored skillContext
		if err := json.Unmarshal(data, &stored); err != nil {
			t.Fatal(err)
		}
		if len(stored.Scrutineer.AnalystFeedback) != 1 || stored.Scrutineer.AnalystFeedback[0].Reason != "guarded" {
			t.Fatalf("missing feedback in %s: %s", dir, data)
		}
	}
}

func TestFindingFeedbackFailsOnUnavailableEvidence(t *testing.T) {
	fixture := newControlsFixture(t, "", "parse.go:12")
	w := Worker{DB: fixture.gdb}
	scan := db.Scan{RepositoryID: fixture.repo.ID, RescanMode: db.ScanRescanModeDiff}
	if _, err := w.findingFeedback(context.Background(), t.TempDir(), &scan, &db.Skill{Name: "security-deep-dive"}); err == nil {
		t.Fatal("missing diff accepted")
	}
	if err := fixture.gdb.Migrator().DropTable(&db.FindingReview{}); err != nil {
		t.Fatal(err)
	}
	scan.FindingID = &fixture.finding.ID
	if _, err := w.findingFeedback(context.Background(), t.TempDir(), &scan, &db.Skill{Name: "revalidate"}); err == nil {
		t.Fatal("missing reviews table accepted")
	}
}
