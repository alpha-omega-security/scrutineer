package worker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

const maintainersReport = `{"maintainers":[
  {"login":"alice","name":"Alice","email":"alice@example.com","role":"lead","status":"active","evidence":"80% of past-year commits"},
  {"login":"bob","role":"contributor","status":"inactive","evidence":"last commit 2022"}
],"disclosure_channel":"SECURITY.md","notes":""}`

func TestDoSkill_findingsKind(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{
		Name:        "spec-deep",
		Description: "Deep audit",
		Body:        "## Instructions\n\nDo the thing.",
		OutputFile:  "report.json",
		OutputKind:  "findings",
		Version:     1,
		Active:      true,
		Source:      "ui",
	}
	gdb.Create(&skill)

	scan := db.Scan{
		RepositoryID: repo.ID,
		Kind:         JobSkill,
		Status:       db.ScanQueued,
		Model:        "fake",
		SkillID:      &skill.ID,
	}
	gdb.Create(&scan)

	report := `{"repository":"https://example.com/x","commit":"abc","spec_version":10,
	  "model":"t","date":"2026-01-01","languages":["Go"],"boundaries":[{"actor":"u","trusted":"no","controls":"c","source":"derived"}],
	  "inventory":[],"ruled_out":[],
	  "findings":[{"id":"F1","sinks":["S1"],"title":"t","severity":"High","cwe":"CWE-1","location":"x:1",
	    "trace":"t","boundary":"b","validation":"v","rating":"High"}]}`

	w := &Worker{
		DB:      gdb,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir: t.TempDir(),
		Runner:  fakeRunner{skillRes: SkillResult{Commit: "abc", Report: report}},
	}

	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatal(err)
	}

	var got db.Scan
	gdb.First(&got, scan.ID)
	if got.Status != db.ScanDone {
		t.Errorf("status = %s: %s", got.Status, got.Error)
	}
	if got.SkillName != "spec-deep" || got.SkillVersion != 1 {
		t.Errorf("skill denorm fields: %q v=%d", got.SkillName, got.SkillVersion)
	}
	if got.FindingsCount != 1 {
		t.Errorf("findings count: %d", got.FindingsCount)
	}
	if !strings.Contains(got.Prompt, "spec-deep") || !strings.Contains(got.Prompt, "report.json") {
		t.Errorf("prompt missing skill name or output file: %q", got.Prompt)
	}
}

func TestDoSkill_maintainersKind(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{
		Name:        "maintainers",
		Description: "Identify maintainers",
		Body:        "Fetch ecosyste.ms and classify.",
		OutputFile:  "report.json",
		OutputKind:  "maintainers",
		Version:     1,
		Active:      true,
		Source:      "ui",
	}
	gdb.Create(&skill)

	scan := db.Scan{
		RepositoryID: repo.ID,
		Kind:         JobSkill,
		Status:       db.ScanQueued,
		Model:        "fake",
		SkillID:      &skill.ID,
	}
	gdb.Create(&scan)

	w := &Worker{
		DB:      gdb,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir: t.TempDir(),
		Runner:  fakeRunner{skillRes: SkillResult{Commit: "abc", Report: maintainersReport}},
	}

	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatal(err)
	}

	var alice db.Maintainer
	if err := gdb.Where("login = ?", "alice").First(&alice).Error; err != nil {
		t.Fatalf("alice not upserted: %v", err)
	}
	if alice.Status != db.MaintainerActive || alice.Email != "alice@example.com" {
		t.Errorf("alice row: %+v", alice)
	}
	var bob db.Maintainer
	if err := gdb.Where("login = ?", "bob").First(&bob).Error; err != nil {
		t.Fatalf("bob not upserted: %v", err)
	}
	if bob.Status != db.MaintainerInactive {
		t.Errorf("bob status: %s", bob.Status)
	}

	var fresh db.Repository
	gdb.Preload("Maintainers").First(&fresh, repo.ID)
	if len(fresh.Maintainers) != 2 {
		t.Errorf("repo linked to %d maintainers, want 2", len(fresh.Maintainers))
	}
}

func TestStageContext_writesRepoFacts(t *testing.T) {
	dir := t.TempDir()
	repo := &db.Repository{
		URL:           "https://example.com/x",
		HTMLURL:       "https://example.com/x",
		Name:          "x",
		FullName:      "example/x",
		DefaultBranch: "main",
	}
	if err := stageContext(dir, repo); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got skillContext
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Repository.URL != repo.URL || got.Repository.DefaultBranch != "main" {
		t.Errorf("context: %+v", got)
	}
}

func TestStageSkill_writesMarkdownAndSchema(t *testing.T) {
	dst := t.TempDir()
	dir := filepath.Join(dst, "ns")
	skill := &db.Skill{
		Name:        "s",
		Description: "d",
		Body:        "body",
		SchemaJSON:  `{"x":1}`,
		Source:      "ui",
	}
	if err := stageSkill(skill, dir); err != nil {
		t.Fatal(err)
	}
	md, err := os.ReadFile(filepath.Join(dir, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "name: s") || !strings.Contains(string(md), "description: d") {
		t.Errorf("missing frontmatter: %q", string(md))
	}
	if !strings.Contains(string(md), "body") {
		t.Errorf("missing body: %q", string(md))
	}
	sch, err := os.ReadFile(filepath.Join(dir, "schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(sch) != `{"x":1}` {
		t.Errorf("schema: %q", string(sch))
	}
}
