package skills

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func writeSkill(t *testing.T, dir, name, content string) string {
	t.Helper()
	sdir := filepath.Join(dir, name)
	if err := os.MkdirAll(sdir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sdir, "SKILL.md")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseFile_minimal(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "hello", `---
name: hello
description: Say hello to the repository.
---

# hello

Do the thing.
`)
	p, err := ParseFile(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Name != "hello" {
		t.Errorf("name: %q", p.Name)
	}
	if !strings.Contains(p.Body, "Do the thing.") {
		t.Errorf("body did not capture content: %q", p.Body)
	}
	if p.SourceHash == "" {
		t.Error("source hash empty")
	}
	if len(p.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", p.Warnings)
	}
}

func TestParseFile_metadataKeys(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "spec-deep", `---
name: spec-deep
description: Deep audit.
metadata:
  scrutineer.output_file: report.json
  scrutineer.output_kind: findings
  author: example
---

body
`)
	p, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.OutputFile != "report.json" {
		t.Errorf("output_file: %q", p.OutputFile)
	}
	if p.OutputKind != "findings" {
		t.Errorf("output_kind: %q", p.OutputKind)
	}
	if p.Metadata["author"] != "example" {
		t.Errorf("metadata passthrough missing: %v", p.Metadata)
	}
}

func TestParseFile_schemaLoaded(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "s", `---
name: s
description: d
---
body`)
	sch := `{"type":"object"}`
	if err := os.WriteFile(filepath.Join(dir, "s", "schema.json"), []byte(sch), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.SchemaJSON != sch {
		t.Errorf("schema: %q", p.SchemaJSON)
	}
}

func TestParseFile_missingFrontmatter(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "broken", "just a body, no frontmatter\n")
	if _, err := ParseFile(path); err == nil {
		t.Error("expected error")
	}
}

func TestParseFile_missingDescription(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "nd", `---
name: nd
---
body`)
	if _, err := ParseFile(path); err == nil {
		t.Error("expected error")
	}
}

func TestParseFile_namedoesntmatch(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "dirname", `---
name: different
description: d
---
body`)
	p, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range p.Warnings {
		if strings.Contains(w, "does not match directory") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected mismatch warning, got %v", p.Warnings)
	}
}

func TestLoadDirectory_upsertAndVersionBump(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeSkill(t, root, "one", `---
name: one
description: First version.
---
v1`)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	n, err := LoadDirectory(gdb, log, root, "local")
	if err != nil || n != 1 {
		t.Fatalf("first load n=%d err=%v", n, err)
	}
	var s1 db.Skill
	gdb.First(&s1)
	if s1.Version != 1 {
		t.Errorf("version: %d", s1.Version)
	}

	// Re-load unchanged: version stays.
	if _, err := LoadDirectory(gdb, log, root, "local"); err != nil {
		t.Fatal(err)
	}
	var s2 db.Skill
	gdb.First(&s2)
	if s2.Version != 1 {
		t.Errorf("unchanged reload bumped version: %d", s2.Version)
	}

	// Edit the body and reload: version bumps.
	writeSkill(t, root, "one", `---
name: one
description: Second version.
---
v2`)
	if _, err := LoadDirectory(gdb, log, root, "local"); err != nil {
		t.Fatal(err)
	}
	var s3 db.Skill
	gdb.First(&s3)
	if s3.Version != 2 {
		t.Errorf("edited reload did not bump version: %d", s3.Version)
	}
	if !strings.Contains(s3.Body, "v2") {
		t.Errorf("body not updated: %q", s3.Body)
	}
}
