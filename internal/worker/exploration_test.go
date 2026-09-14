package worker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/skills"
)

func TestExploratoryDirectories(t *testing.T) {
	src := t.TempDir()
	for _, name := range []string{"main.go", "lib/parser.c", "lib/more.h", "cmd/tool.rs", "docs/readme.md", ".git/hooks/test.py", "outside/other.py"} {
		writeDiffTestFile(t, src, name, "source")
	}
	for _, dir := range []string{"vendor", "third_party", "testdata", "tests", "examples", "fixtures", "__tests__", "Vendor"} {
		writeDiffTestFile(t, src, filepath.Join(dir, "nested", "fixture.go"), "source")
		writeDiffTestFile(t, src, filepath.Join("lib", dir, "nested", "fixture.go"), "source")
	}
	if err := os.Symlink(filepath.Join(src, "outside"), filepath.Join(src, "lib", "linked")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(src, "main.go"), filepath.Join(src, "lib", "alias.go")); err != nil {
		t.Fatal(err)
	}
	got, err := exploratoryDirectories(t.Context(), src, "")
	if err != nil || !reflect.DeepEqual(got, []string{".", "cmd", "lib", "outside"}) {
		t.Fatalf("directories=%v err=%v", got, err)
	}
	got, err = exploratoryDirectories(t.Context(), src, "lib")
	if err != nil || !reflect.DeepEqual(got, []string{"lib"}) {
		t.Fatalf("subproject directories=%v err=%v", got, err)
	}
	if _, err := exploratoryDirectories(t.Context(), src, "../outside"); err == nil {
		t.Fatal("accepted escaping subproject")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := exploratoryDirectories(ctx, src, ""); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestPrepareExplorationPreservesTargetAndFilters(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "exploration.db"))
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	for _, file := range []string{"lib/main.go", "skip/secret.go", "docs/readme.md"} {
		writeDiffTestFile(t, filepath.Join(work, "src"), file, "source")
	}
	skill := db.Skill{Name: deepDiveSkillName, OutputKind: "findings"}
	config := "skip: [skip/**]\n"
	if err := applyRepositoryPathFilters(work, &skill, config, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/exploration"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, SkillName: deepDiveSkillName, Status: db.ScanQueued, ExplorationMode: ExplorationRandomDig}
	if err := gdb.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	w := Worker{DB: gdb}
	if err := w.prepareExploration(t.Context(), work, &scan); err != nil {
		t.Fatal(err)
	}
	if scan.ExplorationPath != "lib" {
		t.Fatalf("target=%q", scan.ExplorationPath)
	}
	var saved db.Scan
	if err := gdb.First(&saved, scan.ID).Error; err != nil || saved.ExplorationPath != "lib" {
		t.Fatalf("target not persisted: %+v err=%v", saved, err)
	}
	writeDiffTestFile(t, filepath.Join(work, "src"), "new/app.py", "pass")
	if err := w.prepareExploration(t.Context(), work, &saved); err != nil || saved.ExplorationPath != "lib" {
		t.Fatalf("retry changed target=%q err=%v", saved.ExplorationPath, err)
	}
	if err := os.Remove(filepath.Join(work, "src", "lib", "main.go")); err != nil {
		t.Fatal(err)
	}
	if err := w.prepareExploration(t.Context(), work, &saved); err == nil {
		t.Fatal("missing retry target silently replaced")
	}
}

func TestStageExplorationOmitsModelInputs(t *testing.T) {
	parsed, err := skills.ParseFile("../../skills/security-deep-dive/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	skill, err := parsed.ToModel("disk")
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	skillDir := filepath.Join(work, ".claude", "skills", deepDiveSkillName)
	scan := db.Scan{
		ID: 12, RepositoryID: 1, SkillName: deepDiveSkillName, APIToken: "validation-token",
		ExplorationMode: ExplorationRandomDig, ExplorationPath: "lib", SubPath: "lib",
		Repository: db.Repository{URL: "https://example.com/repo", ThreatModel: `{"secret":"MODEL-CANARY"}`, ScanConfig: "attack_surface: CONFIG-CANARY"},
	}
	if err := StageWorkspace(work, skillDir, "http://localhost/api", "", "metadata-canary", &scan, skill); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{work, skillDir} {
		b, err := os.ReadFile(filepath.Join(dir, "context.json"))
		if err != nil {
			t.Fatal(err)
		}
		var got skillContext
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if got.Scrutineer.ScanConfig != nil || got.Scrutineer.Exploration == nil || got.Scrutineer.Exploration.Path != "lib" || got.Scrutineer.ScanSubPath != "lib" {
			t.Fatalf("wrong context: %s", b)
		}
		if strings.Contains(string(b), "CANARY") || strings.Contains(string(b), "metadata-canary") {
			t.Fatalf("model input leaked: %s", b)
		}
	}
	if _, err := os.Stat(filepath.Join(work, "threat_model.json")); !os.IsNotExist(err) {
		t.Fatalf("threat model staged: %v", err)
	}
	prompt := buildLoggedPrompt(skill, "claude")
	if !strings.Contains(prompt, "Independent Source Audit") || strings.Contains(prompt, "## Phase 1: Inventory") {
		t.Fatal("logged prompt does not match blind instructions")
	}
	if !strings.Contains(scan.Repository.ThreatModel, "CANARY") || scan.Repository.ScanConfig == "" {
		t.Fatal("staging mutated repository guidance")
	}
}

func TestExplorationCannotBeDiffBaseline(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "baseline.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/baseline"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	planned := db.Scan{RepositoryID: repo.ID, SkillName: deepDiveSkillName, Status: db.ScanDone, Commit: "abcdef123"}
	extra := planned
	extra.ExplorationMode = ExplorationRandomDig
	for _, scan := range []*db.Scan{&planned, &extra} {
		if err := gdb.Create(scan).Error; err != nil {
			t.Fatal(err)
		}
	}
	w := Worker{DB: gdb}
	current := db.Scan{RepositoryID: repo.ID, SkillName: deepDiveSkillName}
	got, ok := w.diffBaseline(&current)
	if !ok || got.ID != planned.ID {
		t.Fatalf("automatic baseline=%d ok=%v", got.ID, ok)
	}
	current.DiffBaseScanID = &extra.ID
	if _, ok := w.diffBaseline(&current); ok {
		t.Fatal("accepted explicit exploratory baseline")
	}
}

func TestValidateExploration(t *testing.T) {
	for _, tc := range []struct {
		name, skill, mode, target, focus, rescan string
		finding                                  *uint
		valid                                    bool
	}{
		{name: "ordinary", skill: "verify", valid: true},
		{name: "pending", skill: deepDiveSkillName, mode: ExplorationRandomDig, valid: true},
		{name: "root", skill: deepDiveSkillName, mode: ExplorationRandomDig, target: ".", valid: true},
		{name: "subdir", skill: deepDiveSkillName, mode: ExplorationRandomDig, target: "lib/parser", valid: true},
		{name: "wrong skill", skill: "verify", mode: ExplorationRandomDig},
		{name: "unknown mode", skill: deepDiveSkillName, mode: "other"},
		{name: "orphan path", skill: deepDiveSkillName, target: "lib"},
		{name: "escape", skill: deepDiveSkillName, mode: ExplorationRandomDig, target: "../lib"},
		{name: "absolute", skill: deepDiveSkillName, mode: ExplorationRandomDig, target: "/lib"},
		{name: "focus", skill: deepDiveSkillName, mode: ExplorationRandomDig, focus: "{}"},
		{name: "diff", skill: deepDiveSkillName, mode: ExplorationRandomDig, rescan: db.ScanRescanModeDiff},
		{name: "finding", skill: deepDiveSkillName, mode: ExplorationRandomDig, finding: new(uint(1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scan := db.Scan{ExplorationMode: tc.mode, ExplorationPath: tc.target, FocusArea: tc.focus, RescanMode: tc.rescan, FindingID: tc.finding}
			err := ValidateExploration(&scan, tc.skill)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}

func TestExplorationRejectsHostRunner(t *testing.T) {
	for _, runner := range []SkillRunner{
		LocalClaude{}, &LocalClaude{},
		HostSplitRunner{Host: LocalClaude{}, HostSkills: []string{deepDiveSkillName}},
		&HostSplitRunner{Host: LocalClaude{}, HostSkills: []string{deepDiveSkillName}},
	} {
		w := Worker{Runner: runner}
		if err := w.ValidateExplorationRunner(deepDiveSkillName); err == nil {
			t.Fatalf("accepted host runner %T", runner)
		}
		scan := db.Scan{SkillName: deepDiveSkillName, ExplorationMode: ExplorationRandomDig}
		if err := w.prepareExploration(t.Context(), t.TempDir(), &scan); err == nil || !strings.Contains(err.Error(), "host execution") {
			t.Fatalf("worker did not reject host exploration before preparing source: %v", err)
		}
	}
	w := Worker{Runner: HostSplitRunner{Container: &ContainerRunner{}, Host: LocalClaude{}, HostSkills: []string{"verify"}}}
	if err := w.ValidateExplorationRunner(deepDiveSkillName); err != nil {
		t.Fatal(err)
	}
}

func TestExplorationEmptySourceAndMissingReferenceFail(t *testing.T) {
	work := t.TempDir()
	writeDiffTestFile(t, filepath.Join(work, "src"), "README.md", "docs only")
	scan := db.Scan{SkillName: deepDiveSkillName, ExplorationMode: ExplorationRandomDig}
	w := Worker{}
	if err := w.prepareExploration(t.Context(), work, &scan); err == nil {
		t.Fatal("accepted source-free workspace")
	}
	scan.ExplorationPath = "."
	skill := db.Skill{Name: deepDiveSkillName, SourcePath: t.TempDir()}
	if err := StageWorkspace(work, filepath.Join(work, "skill"), "", "", "", &scan, &skill); err == nil {
		t.Fatal("silently fell back to planned instructions without the reference")
	}
}

func TestExplorationPrereqsAndRecipe(t *testing.T) {
	scan := db.Scan{SkillID: new(uint(1)), ExplorationMode: ExplorationRandomDig, ExplorationPath: "lib", TriageScanID: new(uint(12))}
	w := Worker{}
	if deferred, err := w.preflightSkill(t.Context(), &scan, 1); err != nil || deferred {
		t.Fatalf("blind audit gated on reports it cannot read: deferred=%v err=%v", deferred, err)
	}
	raw, err := buildScanRecipe(&scan, "claude", "ignored model", "retained path exclusions")
	if err != nil {
		t.Fatal(err)
	}
	var recipe ScanRecipe
	if err := json.Unmarshal([]byte(raw), &recipe); err != nil {
		t.Fatal(err)
	}
	if recipe.ThreatModelSHA256 != "" || recipe.ScanConfigSHA256 == "" || recipe.ExplorationPath != "lib" || recipe.ExplorationMode != ExplorationRandomDig || recipe.TriageScanID == nil || *recipe.TriageScanID != 12 {
		t.Fatalf("wrong exploratory recipe: %s", raw)
	}
}
