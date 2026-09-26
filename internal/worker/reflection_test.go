package worker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/reflection"
)

func reflectionFixture(t *testing.T) (*Worker, *db.Scan, *db.Scan) {
	t.Helper()
	w := newPreflightWorker(t)
	scan := seedPreflightFixtures(t, w, "")
	if err := w.DB.Model(&db.Repository{}).Where("id = ?", scan.RepositoryID).Update("threat_model", `{"known_non_findings":[],"controls":[]}`).Error; err != nil {
		t.Fatal(err)
	}
	triage := db.Scan{RepositoryID: scan.RepositoryID, SkillName: "triage", Status: db.ScanDone}
	if err := w.DB.Create(&triage).Error; err != nil {
		t.Fatal(err)
	}
	scan.SkillName, scan.TriageScanID = "reflect", &triage.ID
	if err := w.DB.Save(scan).Error; err != nil {
		t.Fatal(err)
	}
	if err := w.DB.Model(&db.Skill{}).Where("id = ?", scan.SkillID).Update("name", "reflect").Error; err != nil {
		t.Fatal(err)
	}
	child := db.Scan{RepositoryID: scan.RepositoryID, SkillName: "verify", Status: db.ScanDone, TriageScanID: &triage.ID, Log: "error: libfoo not found"}
	if err := w.DB.Create(&child).Error; err != nil {
		t.Fatal(err)
	}
	return w, scan, &child
}

func TestPrepareReflectionWaitsAndSnapshots(t *testing.T) {
	w, scan, child := reflectionFixture(t)
	for _, status := range []db.ScanStatus{db.ScanQueued, db.ScanRunning, db.ScanPaused} {
		if err := w.DB.Model(child).Update("status", status).Error; err != nil {
			t.Fatal(err)
		}
		pending, err := w.prepareReflection(scan)
		if err != nil || !pending || len(scan.ImportPayload) != 0 {
			t.Fatalf("%s: pending=%v err=%v", status, pending, err)
		}
	}
	if err := w.DB.Model(child).Update("status", db.ScanFailed).Error; err != nil {
		t.Fatal(err)
	}
	w.running = map[uint]*runningScan{child.ID: {}}
	if pending, err := w.prepareReflection(scan); err != nil || !pending {
		t.Fatalf("finalizer must block: %v %v", pending, err)
	}
	delete(w.running, child.ID)
	if pending, err := w.prepareReflection(scan); err != nil || pending {
		t.Fatalf("failed child must settle: %v %v", pending, err)
	}
	var input reflection.Input
	if err := json.Unmarshal(scan.ImportPayload, &input); err != nil {
		t.Fatal(err)
	}
	if len(input.Sources) != 1 || input.Sources[0].ScanID != child.ID || !strings.Contains(input.Sources[0].Excerpt, "libfoo") {
		t.Fatalf("bad input: %+v", input)
	}
	root := t.TempDir()
	if err := stageImportPayload(root, scan.ImportPayload); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "import", "report"))
	if err != nil || string(raw) != string(scan.ImportPayload) {
		t.Fatalf("staged input: %s %v", raw, err)
	}
	first := string(scan.ImportPayload)
	if err := w.DB.Model(child).Update("log", "different").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := w.prepareReflection(scan); err != nil || string(scan.ImportPayload) != first {
		t.Fatalf("snapshot changed: %v", err)
	}
}

func TestReflectionValidatesAndParsesSameReport(t *testing.T) {
	w, scan, child := reflectionFixture(t)
	if _, err := w.prepareReflection(scan); err != nil {
		t.Fatal(err)
	}
	schema, err := os.ReadFile("../../skills/reflect/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	report, err := json.Marshal(reflection.Report{Notes: []reflection.Note{{Stage: "verify", ScanID: child.ID, Kind: "missing_dependency", Summary: "libfoo unavailable", Evidence: "libfoo not found"}}})
	if err != nil {
		t.Fatal(err)
	}
	if detail := ValidateReportSchema(string(schema), string(report)); detail != "" {
		t.Fatal(detail)
	}
	if err := w.parseSkillOutput(t.Context(), &db.Skill{Name: "reflect", OutputKind: "reflection", SchemaJSON: string(schema)}, scan, string(report), func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var repo db.Repository
	if err := w.DB.First(&repo, scan.RepositoryID).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(repo.ThreatModel, "reflection_notes") || !strings.Contains(repo.ThreatModel, "known_non_findings") {
		t.Fatal(repo.ThreatModel)
	}
	before := repo.ThreatModel
	bad := strings.ReplaceAll(string(report), "libfoo not found", "invented evidence")
	if err := w.parseReflectionOutput(scan, bad); err == nil {
		t.Fatal("accepted invented evidence")
	}
	if err := w.DB.First(&repo, scan.RepositoryID).Error; err != nil || repo.ThreatModel != before {
		t.Fatalf("modified model on invalid report: %v", err)
	}
}

func TestPrepareReflectionScopeAndMissing(t *testing.T) {
	w, scan, child := reflectionFixture(t)
	scan.Ref = "other"
	if _, err := w.prepareReflection(scan); err == nil {
		t.Fatal("accepted nondefault scope")
	}
	scan.Ref = ""
	if err := w.DB.Model(child).Update("log", "").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := w.prepareReflection(scan); err != nil {
		t.Fatal(err)
	}
	var input reflection.Input
	if err := json.Unmarshal(scan.ImportPayload, &input); err != nil {
		t.Fatal(err)
	}
	if !input.Sources[0].Missing {
		t.Fatal("missing transcript was not recorded")
	}
}

func TestPreflightReflectionDefersAndPinsRecipe(t *testing.T) {
	w, scan, child := reflectionFixture(t)
	if err := w.DB.Model(child).Update("status", db.ScanPaused).Error; err != nil {
		t.Fatal(err)
	}
	deferred, err := w.preflightSkill(t.Context(), scan, 0)
	if err != nil || !deferred || len(scan.ImportPayload) != 0 {
		t.Fatalf("deferred=%v err=%v", deferred, err)
	}
	if err := w.DB.Model(child).Update("status", db.ScanCancelled).Error; err != nil {
		t.Fatal(err)
	}
	deferred, err = w.preflightSkill(t.Context(), scan, 1)
	if err != nil || deferred || len(scan.ImportPayload) == 0 {
		t.Fatalf("deferred=%v err=%v", deferred, err)
	}
	raw, err := buildScanRecipe(scan, "claude", "", "")
	if err != nil {
		t.Fatal(err)
	}
	var recipe ScanRecipe
	if err := json.Unmarshal([]byte(raw), &recipe); err != nil {
		t.Fatal(err)
	}
	if recipe.ReflectionInputSHA256 != textDigest(string(scan.ImportPayload)) {
		t.Fatal("snapshot missing from recipe")
	}
}

func TestReflectionSchemaRejectsBadShapes(t *testing.T) {
	schema := loadBundledSchema(t, "../../skills/reflect/schema.json")
	for _, report := range []string{
		`{}`, `{"notes":[]}`, `{"notes":null}`,
		`{"notes":[{"stage":"verify","scan_id":1,"kind":"known_non_finding","summary":"safe","evidence":""}]}`,
		`{"notes":[{"stage":"verify","scan_id":0,"kind":"no_observation","summary":"none","evidence":""}]}`,
		`{"notes":[{"stage":"verify","scan_id":1,"kind":"no_observation","summary":"none","evidence":"","extra":true}]}`,
	} {
		if detail := ValidateReportSchema(schema, report); detail == "" {
			t.Fatalf("accepted %s", report)
		}
	}
}

func TestPrepareReflectionExcludesForeignScopes(t *testing.T) {
	w, scan, child := reflectionFixture(t)
	for _, other := range []db.Scan{
		{RepositoryID: scan.RepositoryID, SkillName: "verify", Status: db.ScanRunning, TriageScanID: scan.TriageScanID, SubPath: "pkg"},
		{RepositoryID: scan.RepositoryID, SkillName: "verify", Status: db.ScanRunning, TriageScanID: scan.TriageScanID, Ref: "branch"},
		{RepositoryID: scan.RepositoryID, SkillName: "verify", Status: db.ScanRunning},
	} {
		if err := w.DB.Create(&other).Error; err != nil {
			t.Fatal(err)
		}
	}
	if pending, err := w.prepareReflection(scan); err != nil || pending {
		t.Fatalf("pending=%v err=%v", pending, err)
	}
	var input reflection.Input
	if err := json.Unmarshal(scan.ImportPayload, &input); err != nil {
		t.Fatal(err)
	}
	if len(input.Sources) != 1 || input.Sources[0].ScanID != child.ID {
		t.Fatalf("unexpected sources: %+v", input)
	}
}

func TestPrepareReflectionBoundsCohort(t *testing.T) {
	w, scan, _ := reflectionFixture(t)
	rows := make([]db.Scan, reflection.MaxScans)
	for i := range rows {
		rows[i] = db.Scan{RepositoryID: scan.RepositoryID, SkillName: "verify", Status: db.ScanDone, TriageScanID: scan.TriageScanID}
	}
	if err := w.DB.Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := w.prepareReflection(scan); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected bounded cohort error, got %v", err)
	}
	if len(scan.ImportPayload) != 0 {
		t.Fatal("silently truncated input")
	}
}

func TestReflectionCohortComparison(t *testing.T) {
	before := []db.Scan{{ID: 1, Status: db.ScanDone}}
	if !sameReflectionSources(before, before) {
		t.Fatal("unchanged cohort differs")
	}
	if sameReflectionSources(before, append(before, db.Scan{ID: 2, Status: db.ScanQueued})) {
		t.Fatal("late fan-out was missed")
	}
	if sameReflectionSources(before, []db.Scan{{ID: 1, Status: db.ScanQueued}}) {
		t.Fatal("resume was missed")
	}
}

func TestReflectionRetryUsesFrozenSnapshot(t *testing.T) {
	for _, action := range []string{"paused_source", "deleted_sources"} {
		t.Run(action, func(t *testing.T) {
			w, scan, child := reflectionFixture(t)
			if _, err := w.prepareReflection(scan); err != nil {
				t.Fatal(err)
			}
			frozen := string(scan.ImportPayload)
			if action == "paused_source" {
				if err := w.DB.Model(child).Update("status", db.ScanPaused).Error; err != nil {
					t.Fatal(err)
				}
			} else {
				if err := w.DB.Delete(child).Error; err != nil {
					t.Fatal(err)
				}
				if err := w.DB.Delete(&db.Scan{}, *scan.TriageScanID).Error; err != nil {
					t.Fatal(err)
				}
			}
			pending, err := w.prepareReflection(scan)
			if err != nil || pending || string(scan.ImportPayload) != frozen {
				t.Fatalf("frozen retry pending=%v err=%v", pending, err)
			}
		})
	}
}
