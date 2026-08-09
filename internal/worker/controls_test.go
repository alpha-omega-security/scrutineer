package worker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/threatmodel"
)

const controlsModel = `{
  "controls": [
    {
      "id": "web-authz",
      "kind": "authorization",
      "protects": {"paths": ["internal/web/**"]},
      "assumptions": ["requests reach these handlers only through the authenticated router"],
      "provenance": "documented",
      "source": "internal/web/server.go:120"
    },
    {
      "id": "parser-sandbox",
      "kind": "sandbox",
      "protects": {"paths": ["internal/parser/**"]},
      "provenance": "inferred"
    }
  ]
}`

type controlsFixture struct {
	gdb     *gorm.DB
	repo    db.Repository
	finding db.Finding
}

func newControlsFixture(t *testing.T, model, location string) controlsFixture {
	t.Helper()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "controls.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "file:///fixture", Name: "fixture", ThreatModel: model}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone}
	if err := gdb.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	finding := db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, Title: "handler issue",
		Severity: "High", Status: db.FindingNew, Location: location,
	}
	if err := gdb.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}
	return controlsFixture{gdb: gdb, repo: repo, finding: finding}
}

func (f controlsFixture) resolve(t *testing.T, skillName, subPath string) *skillContextControls {
	t.Helper()
	fid := f.finding.ID
	scan := &db.Scan{
		RepositoryID: f.repo.ID,
		Repository:   f.repo,
		FindingID:    &fid,
		SubPath:      subPath,
	}
	got, err := (&Worker{DB: f.gdb}).controlsContext(scan, &db.Skill{Name: skillName})
	if err != nil {
		t.Fatalf("controlsContext: %v", err)
	}
	return got
}

func TestControlsContextMatchesFindingFile(t *testing.T) {
	fixture := newControlsFixture(t, controlsModel, "internal/web/server.go:120")

	got := fixture.resolve(t, verifySkillName, "")
	if got == nil {
		t.Fatal("controls = nil, want a resolved block")
	}
	if got.UnavailableWhy != "" {
		t.Fatalf("unavailable_reason = %q, want empty", got.UnavailableWhy)
	}
	if got.FindingFile != "internal/web/server.go" {
		t.Errorf("finding_file = %q, want the location's file", got.FindingFile)
	}
	if len(got.IDs) != 1 || got.IDs[0] != "web-authz" {
		t.Fatalf("ids = %v, want only the control scoped to internal/web", got.IDs)
	}
	if len(got.Matched) != 1 || got.Matched[0].Kind != threatmodel.KindAuthorization {
		t.Fatalf("matched = %+v, want the authorization control", got.Matched)
	}
	// The assumption is the thing a bypass argument attacks, so it has to
	// survive into the staged block rather than being reduced to an id.
	if len(got.Matched[0].Assumptions) != 1 {
		t.Errorf("matched control lost its assumptions: %+v", got.Matched[0])
	}
}

func TestControlsContextReportsAnUnprotectedFile(t *testing.T) {
	fixture := newControlsFixture(t, controlsModel, "internal/worker/skill.go:42")

	got := fixture.resolve(t, verifySkillName, "")
	if got == nil {
		t.Fatal("controls = nil, want a block recording that nothing matched")
	}
	if len(got.Matched) != 0 || len(got.IDs) != 0 {
		t.Fatalf("matched = %+v, want empty for a file no control claims", got.Matched)
	}
	if got.FindingFile != "internal/worker/skill.go" {
		t.Errorf("finding_file = %q, want the file that was matched against", got.FindingFile)
	}
}

// A subpath-scoped scan reports locations relative to the sub-folder, while
// control globs are authored against the repository root. The rebase is what
// makes the two meet; this test fails without it, which is the point.
func TestControlsContextRebasesSubpathLocation(t *testing.T) {
	fixture := newControlsFixture(t, controlsModel, "web/server.go:120")

	got := fixture.resolve(t, verifySkillName, "internal")
	if got == nil {
		t.Fatal("controls = nil, want a resolved block")
	}
	if got.FindingFile != "internal/web/server.go" {
		t.Fatalf("finding_file = %q, want the subpath-rebased root-relative path", got.FindingFile)
	}
	if len(got.IDs) != 1 || got.IDs[0] != "web-authz" {
		t.Fatalf("ids = %v, want the control matched after the rebase", got.IDs)
	}

	// Demonstrate the rebase is load-bearing rather than incidental: the raw
	// subpath-relative location matches nothing against the same model.
	model, err := threatmodel.Parse(controlsModel)
	if err != nil {
		t.Fatal(err)
	}
	if unrebased := model.MatchPath("web/server.go"); len(unrebased) != 0 {
		t.Fatalf("unrebased path matched %+v; the rebase would be redundant", unrebased)
	}
}

func TestControlsContextRejectsEscapingLocation(t *testing.T) {
	fixture := newControlsFixture(t, controlsModel, "../../etc/passwd:1")

	got := fixture.resolve(t, verifySkillName, "")
	if got == nil || got.UnavailableWhy != controlsNoLocation {
		t.Fatalf("controls = %+v, want the no-location reason for a parent-escaping path", got)
	}
	if len(got.Matched) != 0 {
		t.Errorf("matched = %+v, want no match for a rejected path", got.Matched)
	}
}

func TestControlsContextSkipsSkillsThatAreNotVerify(t *testing.T) {
	fixture := newControlsFixture(t, controlsModel, "internal/web/server.go:120")

	if got := fixture.resolve(t, "revalidate", ""); got != nil {
		t.Fatalf("controls = %+v for revalidate, want nil", got)
	}
}

func TestControlsContextSkipsModelWithoutControls(t *testing.T) {
	fixture := newControlsFixture(t, `{"entry_points": [{"name": "http"}]}`, "internal/web/server.go:120")

	if got := fixture.resolve(t, verifySkillName, ""); got != nil {
		t.Fatalf("controls = %+v for a model with no controls, want nil", got)
	}
}

// A malformed model must not cost the operator the verify run: the reason is
// reported in the block instead of failing the scan.
func TestControlsContextDegradesOnMalformedModel(t *testing.T) {
	for name, model := range map[string]string{
		"unparseable":  `{"controls": [`,
		"duplicate id": `{"controls":[{"id":"a","kind":"sandbox","protects":{"paths":["x/**"]},"provenance":"inferred"},{"id":"a","kind":"sandbox","protects":{"paths":["y/**"]},"provenance":"inferred"}]}`,
		"unscoped":     `{"controls":[{"id":"a","kind":"sandbox","protects":{},"provenance":"inferred"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newControlsFixture(t, model, "internal/web/server.go:120")
			got := fixture.resolve(t, verifySkillName, "")
			if got == nil || got.UnavailableWhy == "" {
				t.Fatalf("controls = %+v, want a reported unavailable reason", got)
			}
			if len(got.Matched) != 0 {
				t.Errorf("matched = %+v, want no match from a model that could not be read", got.Matched)
			}
		})
	}
}

func TestControlsContextStagesIntoContextJSON(t *testing.T) {
	fixture := newControlsFixture(t, controlsModel, "internal/web/server.go:120")
	got := fixture.resolve(t, verifySkillName, "")

	dir := t.TempDir()
	scan := &db.Scan{ID: 11, RepositoryID: fixture.repo.ID, APIToken: "tok"}
	if err := stageContextWithInputs(
		dir, "", "http://127.0.0.1:8080/api", "", DefaultMetadataDir,
		scan, &fixture.repo, nil, nil, got,
	); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	var staged skillContext
	if err := json.Unmarshal(data, &staged); err != nil {
		t.Fatal(err)
	}
	if staged.Scrutineer.Controls == nil {
		t.Fatal("staged context.json has no controls block")
	}
	if staged.Scrutineer.Controls.FindingFile != got.FindingFile {
		t.Errorf("staged finding_file = %q, want %q",
			staged.Scrutineer.Controls.FindingFile, got.FindingFile)
	}
	if len(staged.Scrutineer.Controls.Matched) != 1 {
		t.Fatalf("staged matched = %+v, want the host-resolved control",
			staged.Scrutineer.Controls.Matched)
	}
	if staged.Scrutineer.Controls.Matched[0].ID != "web-authz" {
		t.Errorf("staged control id = %q, want web-authz", staged.Scrutineer.Controls.Matched[0].ID)
	}
}

// A skill other than verify must not gain a controls block just because the
// repository has a threat model; the whole point of resolving on the host is
// that the block is finding-scoped.
func TestStagedContextOmitsControlsWhenUnresolved(t *testing.T) {
	dir := t.TempDir()
	repo := db.Repository{URL: "file:///fixture", ThreatModel: controlsModel}
	scan := &db.Scan{ID: 12, RepositoryID: 3, APIToken: "tok"}
	if err := stageContextWithInputs(
		dir, "", "http://127.0.0.1:8080/api", "", DefaultMetadataDir,
		scan, &repo, nil, nil, nil,
	); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"controls"`) {
		t.Fatalf("context.json carries a controls key with nothing resolved:\n%s", data)
	}
}
