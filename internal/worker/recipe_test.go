package worker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
)

// backendRunner reports a backend the way the real harnesses do, so the claim
// resolves one instead of falling back to the value stored at enqueue.
type backendRunner struct{ backend string }

func (backendRunner) RunSkill(context.Context, SkillJob, func(Event)) (SkillResult, error) {
	return SkillResult{}, nil
}

func (backendRunner) SkillDir(workRoot, name string) string {
	return ClaudeHarness{}.SkillDir(workRoot, name)
}

func (b backendRunner) Backend() string { return b.backend }

func newRecipeWorker(t *testing.T, threatModel, scanConfig, backend string) (*Worker, db.Scan, uint) {
	t.Helper()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "recipe.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{
		URL:         "https://example.com/x",
		Name:        "x",
		ThreatModel: threatModel,
		ScanConfig:  scanConfig,
	}
	gdb.Create(&repo)
	skill := db.Skill{Name: "deep-dive", Description: "x", Body: "b", Active: true, Source: "ui", Version: 7}
	gdb.Create(&skill)
	scan := db.Scan{
		RepositoryID:       repo.ID,
		Kind:               JobSkill,
		Status:             db.ScanQueued,
		SkillID:            &skill.ID,
		SkillName:          "deep-dive",
		SkillVersion:       7,
		SkillSchemaVersion: 3,
		Model:              "sonnet",
		Effort:             "high",
		Ref:                "release-2.1",
		Profile:            "ruby",
		SubPath:            "core",
		SkillsRepoSHA:      "abc123",
		// The backend recorded at enqueue, which the claim re-resolves.
		Backend: "codex",
	}
	gdb.Create(&scan)
	w := &Worker{
		DB:             gdb,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir:        t.TempDir(),
		Runner:         backendRunner{backend: backend},
		PrepareRepoSrc: stubPrepareRepoSrc,
	}
	return w, scan, repo.ID
}

func recipeOf(t *testing.T, w *Worker, scanID uint) ScanRecipe {
	t.Helper()
	var got db.Scan
	if err := w.DB.First(&got, scanID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Recipe == "" {
		t.Fatal("no recipe was written at claim")
	}
	var r ScanRecipe
	if err := json.Unmarshal([]byte(got.Recipe), &r); err != nil {
		t.Fatalf("recipe is not valid JSON: %v (%s)", err, got.Recipe)
	}
	return r
}

func TestStartScan_writesRecipeSnapshotAtClaim(t *testing.T) {
	w, scan, _ := newRecipeWorker(t, "threats: sql injection", "paths:\n  - core", "claude")
	if err := w.startScan(&scan); err != nil {
		t.Fatalf("startScan: %v", err)
	}

	r := recipeOf(t, w, scan.ID)
	if r.Ref != "release-2.1" {
		t.Errorf("ref = %q, want release-2.1", r.Ref)
	}
	if r.Skill != "deep-dive" || r.SkillVersion != 7 || r.SkillSchemaVersion != 3 {
		t.Errorf("skill pin = %q/%d/%d, want deep-dive/7/3", r.Skill, r.SkillVersion, r.SkillSchemaVersion)
	}
	if r.Profile != "ruby" || r.SubPath != "core" || r.SkillsRepoSHA != "abc123" {
		t.Errorf("profile/subpath/skills sha = %q/%q/%q", r.Profile, r.SubPath, r.SkillsRepoSHA)
	}
	// The backend the worker resolved, not the one the row carried in.
	if r.Backend != "claude" {
		t.Errorf("backend = %q, want the claim-time claude, not the enqueued codex", r.Backend)
	}
	if r.ThreatModelSHA256 == "" || r.ScanConfigSHA256 == "" {
		t.Errorf("digests = %q/%q, want both set", r.ThreatModelSHA256, r.ScanConfigSHA256)
	}
	if r.ThreatModelSHA256 == r.ScanConfigSHA256 {
		t.Error("threat model and scan config digest the same value")
	}
}

// The recipe exists to record what the worker started from, and a paused scan
// returns to `queued` on the same row rather than as a new one, so the claim
// runs again on a scan that already has a recipe. Without the write-once guard
// the second claim overwrites the first pickup's snapshot with the state at
// resume time, which is precisely the history the column is for. The backend is
// the sharpest case: it is re-resolved on every claim, so a -backend switch
// across the pause would silently restamp the original recipe.
func TestStartScan_recipeSurvivesAPausedScanResuming(t *testing.T) {
	w, scan, repoID := newRecipeWorker(t, "threats: sql injection", "paths:\n  - core", "claude")
	if err := w.startScan(&scan); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	first := recipeOf(t, w, scan.ID)

	// Pause, then edit both things the recipe pins, then resume the same row
	// the way scansResume and the account-pause auto-resume do.
	if err := w.DB.Model(&db.Scan{}).Where("id = ?", scan.ID).
		Update("status", db.ScanPaused).Error; err != nil {
		t.Fatal(err)
	}
	if err := w.DB.Model(&db.Repository{}).Where("id = ?", repoID).
		Update("threat_model", "threats: sql injection AND ssrf").Error; err != nil {
		t.Fatal(err)
	}
	w.Runner = backendRunner{backend: "codex"}
	if err := w.DB.Model(&db.Scan{}).Where("id = ?", scan.ID).
		Update("status", db.ScanQueued).Error; err != nil {
		t.Fatal(err)
	}

	var requeued db.Scan
	if err := w.DB.First(&requeued, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := w.startScan(&requeued); err != nil {
		t.Fatalf("second claim: %v", err)
	}

	second := recipeOf(t, w, scan.ID)
	if second.Backend != first.Backend {
		t.Errorf("backend = %q after resume, want the first pickup's %q", second.Backend, first.Backend)
	}
	if second.ThreatModelSHA256 != first.ThreatModelSHA256 {
		t.Errorf("threat model digest = %q after resume, want the first pickup's %q",
			second.ThreatModelSHA256, first.ThreatModelSHA256)
	}
}

// #773 lists `commit` first in the recipe, but Scan.Commit is resolved from
// gitHead after the clone, which is well after the claim. A recipe written at
// pickup can only ever record the empty string for it, so the field is left out
// and Scan.Commit stays the record of what the ref resolved to. This pins the
// premise: if the commit ever becomes known at claim time, this test fails and
// the omission should be revisited.
func TestStartScan_commitIsNotKnownAtClaimTime(t *testing.T) {
	w, scan, _ := newRecipeWorker(t, "", "", "claude")
	if err := w.startScan(&scan); err != nil {
		t.Fatalf("startScan: %v", err)
	}
	var got db.Scan
	if err := w.DB.First(&got, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Commit != "" {
		t.Fatalf("commit = %q at claim time; the recipe could carry it after all", got.Commit)
	}
	if got.StartedAt == nil {
		t.Error("the scan did claim, so this is a real claim-time observation")
	}
}

func TestBuildScanRecipe_digestsAndOptionalFields(t *testing.T) {
	base := &db.Scan{Kind: JobSkill, SkillName: "deep-dive"}

	// An unset threat model is absent rather than recorded as the digest of
	// the empty string, so "no threat model" cannot be mistaken for one.
	empty, err := buildScanRecipe(base, "claude", "", "")
	if err != nil {
		t.Fatal(err)
	}
	var r ScanRecipe
	if err := json.Unmarshal([]byte(empty), &r); err != nil {
		t.Fatal(err)
	}
	if r.ThreatModelSHA256 != "" || r.ScanConfigSHA256 != "" {
		t.Errorf("digests = %q/%q for unset text, want both absent", r.ThreatModelSHA256, r.ScanConfigSHA256)
	}

	// An edit to the threat model has to change the digest, or a rerun
	// before and after the edit stays indistinguishable — the thing #773
	// exists to fix.
	before, err := buildScanRecipe(base, "claude", "threats: a", "")
	if err != nil {
		t.Fatal(err)
	}
	after, err := buildScanRecipe(base, "claude", "threats: a and b", "")
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Error("recipe is unchanged across a threat-model edit")
	}

	// A focus area is embedded as JSON so a recipe diff shows which focus
	// fields moved; invalid JSON is dropped rather than failing the claim.
	withFocus := *base
	withFocus.FocusArea = `{"area":"auth"}`
	out, err := buildScanRecipe(&withFocus, "claude", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	if string(r.FocusArea) != `{"area":"auth"}` {
		t.Errorf("focus_area = %s, want embedded JSON", r.FocusArea)
	}

	broken := *base
	broken.FocusArea = "not json"
	out, err = buildScanRecipe(&broken, "claude", "", "")
	if err != nil {
		t.Fatalf("a malformed focus area must not fail the claim: %v", err)
	}
	if !json.Valid([]byte(out)) {
		t.Errorf("recipe is not valid JSON with a malformed focus area: %s", out)
	}
}
