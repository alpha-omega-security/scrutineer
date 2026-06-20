package skills

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
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

func TestParseFile_maxTurns(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "bounded", `---
name: bounded
description: Skill with a turn cap.
metadata:
  scrutineer.output_file: report.json
  scrutineer.max_turns: 50
---

body
`)
	p, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.MaxTurns != 50 {
		t.Errorf("max_turns = %d, want 50", p.MaxTurns)
	}

	m, err := p.ToModel("local")
	if err != nil {
		t.Fatal(err)
	}
	if m.MaxTurns != 50 {
		t.Errorf("model max_turns = %d, want 50", m.MaxTurns)
	}
}

func TestParseFile_requiresRemote(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "remote-only", `---
name: remote-only
description: Skill that needs a forge.
metadata:
  scrutineer.output_file: report.json
  scrutineer.requires_remote: true
---

body
`)
	p, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !p.RequiresRemote {
		t.Error("requires_remote = false, want true")
	}
	m, _ := p.ToModel("local")
	if !m.RequiresRemote {
		t.Error("model RequiresRemote = false, want true")
	}
}

func TestParseFile_requiresRemoteWrongType(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "bad", `---
name: bad
description: Skill with bad requires_remote.
metadata:
  scrutineer.requires_remote: "yes"
---

body
`)
	if _, err := ParseFile(path); err == nil {
		t.Fatal("expected error on non-boolean requires_remote")
	}
}

func TestParseFile_requiresRemoteUnsetDefaultsFalse(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "default", `---
name: default
description: Skill without the key.
---

body
`)
	p, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.RequiresRemote {
		t.Error("RequiresRemote should default to false")
	}
}

func TestParseFile_requiresProfile(t *testing.T) {
	old := ProfileValidator
	t.Cleanup(func() { ProfileValidator = old })
	ProfileValidator = func(s string) bool { return s == "php" }

	dir := t.TempDir()
	path := writeSkill(t, dir, "php-only", `---
name: php-only
description: Skill that needs the PHP runner.
metadata:
  scrutineer.requires_profile: php
---

body
`)
	p, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.RequiresProfile != "php" {
		t.Errorf("RequiresProfile = %q, want php", p.RequiresProfile)
	}
	m, _ := p.ToModel("local")
	if m.RequiresProfile != "php" {
		t.Errorf("model RequiresProfile = %q, want php", m.RequiresProfile)
	}
}

func TestParseFile_requiresProfileUnknown(t *testing.T) {
	old := ProfileValidator
	t.Cleanup(func() { ProfileValidator = old })
	ProfileValidator = func(s string) bool { return s == "php" }

	dir := t.TempDir()
	path := writeSkill(t, dir, "typo", `---
name: typo
description: Skill with a typo'd profile.
metadata:
  scrutineer.requires_profile: pph
---

body
`)
	if _, err := ParseFile(path); err == nil {
		t.Fatal("expected error on unknown requires_profile")
	}
}

func TestParseFile_requiresProfileEmptyOrDefault(t *testing.T) {
	for _, val := range []string{`""`, `"default"`, `"   "`} {
		dir := t.TempDir()
		path := writeSkill(t, dir, "bad", `---
name: bad
description: Skill with empty requires_profile.
metadata:
  scrutineer.requires_profile: `+val+`
---

body
`)
		if _, err := ParseFile(path); err == nil {
			t.Fatalf("expected error on requires_profile = %s", val)
		}
	}
}

func TestParseFile_requiresProfileWrongType(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "bad", `---
name: bad
description: Skill with non-string requires_profile.
metadata:
  scrutineer.requires_profile: 42
---

body
`)
	if _, err := ParseFile(path); err == nil {
		t.Fatal("expected error on non-string requires_profile")
	}
}

func TestParseFile_maxTurnsUnset(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "unbounded", `---
name: unbounded
description: Skill without a turn cap.
---

body
`)
	p, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.MaxTurns != 0 {
		t.Errorf("max_turns = %d, want 0 (unset)", p.MaxTurns)
	}
}

func TestParseFile_model(t *testing.T) {
	old := ModelValidator
	t.Cleanup(func() { ModelValidator = old })
	ModelValidator = func(s string) bool { return s == "claude-sonnet-4-6" }

	dir := t.TempDir()
	path := writeSkill(t, dir, "lite", `---
name: lite
description: Sonnet-friendly skill.
metadata:
  scrutineer.model: claude-sonnet-4-6
---

body
`)
	p, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Model != "claude-sonnet-4-6" {
		t.Errorf("model = %q, want claude-sonnet-4-6", p.Model)
	}
	for _, w := range p.Warnings {
		if strings.Contains(w, "model") {
			t.Errorf("unexpected model warning: %v", w)
		}
	}

	m, err := p.ToModel("local")
	if err != nil {
		t.Fatal(err)
	}
	if m.Model != "claude-sonnet-4-6" {
		t.Errorf("db.Skill.Model = %q, want claude-sonnet-4-6", m.Model)
	}
}

func TestParseFile_modelTier(t *testing.T) {
	old := ModelValidator
	t.Cleanup(func() { ModelValidator = old })
	ModelValidator = func(s string) bool { return s == "high" }

	dir := t.TempDir()
	path := writeSkill(t, dir, "tiered", `---
name: tiered
description: Skill with a model tier.
metadata:
  scrutineer.model: high
---

body
`)
	p, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Model != "high" {
		t.Errorf("model = %q, want high", p.Model)
	}

	m, err := p.ToModel("local")
	if err != nil {
		t.Fatal(err)
	}
	if m.Model != "high" {
		t.Errorf("db.Skill.Model = %q, want high", m.Model)
	}
}

func TestParseFile_modelInvalidIgnoredWithWarning(t *testing.T) {
	old := ModelValidator
	t.Cleanup(func() { ModelValidator = old })
	ModelValidator = func(s string) bool { return s == "claude-sonnet-4-6" }

	dir := t.TempDir()
	path := writeSkill(t, dir, "typo", `---
name: typo
description: Skill with a bad model id.
metadata:
  scrutineer.model: claude-sonnet-typo
---

body
`)
	p, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Model != "" {
		t.Errorf("model = %q, want empty (invalid + ignored)", p.Model)
	}
	found := false
	for _, w := range p.Warnings {
		if strings.Contains(w, "claude-sonnet-typo") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected warning mentioning the rejected model, got %v", p.Warnings)
	}
}

func TestParseFile_modelUnset(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "noprefer", `---
name: noprefer
description: No preferred model.
---

body
`)
	p, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Model != "" {
		t.Errorf("model = %q, want empty (unset)", p.Model)
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

func TestParseFile_rejectsUnknownScrutineerKey(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "typo", `---
name: typo
description: d
metadata:
  scrutineer.outputkind: findings
---
body`)
	_, err := ParseFile(path)
	if err == nil || !strings.Contains(err.Error(), "scrutineer.outputkind") {
		t.Errorf("expected unknown-key error, got %v", err)
	}
}

func TestParseFile_rejectsUnknownOutputKind(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "badkind", `---
name: badkind
description: d
metadata:
  scrutineer.output_kind: finddings
---
body`)
	_, err := ParseFile(path)
	if err == nil || !strings.Contains(err.Error(), "not a recognised parser") {
		t.Errorf("expected output_kind error, got %v", err)
	}
}

func TestParseFile_rejectsUnsupportedVersion(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "future", `---
name: future
description: d
metadata:
  scrutineer.version: 2
---
body`)
	_, err := ParseFile(path)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Errorf("expected version error, got %v", err)
	}
}

func TestParseFile_acceptsVersion1(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "v1", `---
name: v1
description: d
metadata:
  scrutineer.version: 1
  scrutineer.output_kind: findings
---
body`)
	if _, err := ParseFile(path); err != nil {
		t.Errorf("version 1 should parse: %v", err)
	}
}

func TestParseFile_allowsNonScrutineerMetadata(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "extra", `---
name: extra
description: d
metadata:
  author: someone
  unrelated.key: value
---
body`)
	if _, err := ParseFile(path); err != nil {
		t.Errorf("non-scrutineer keys should pass through: %v", err)
	}
}

func TestParseFile_rejectsNonIntegerMaxTurns(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "badturns", `---
name: badturns
description: d
metadata:
  scrutineer.max_turns: fifty
---
body`)
	_, err := ParseFile(path)
	if err == nil || !strings.Contains(err.Error(), "must be an integer") {
		t.Errorf("expected max_turns type error, got %v", err)
	}
}

func TestParseFile_thresholdKeys(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "thresh", `---
name: thresh
description: d
metadata:
  scrutineer.min_confidence: medium
  scrutineer.report_on: Low
  scrutineer.fail_on: High
---
body`)
	p, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.MinConfidence != "medium" || p.ReportOn != "Low" || p.FailOn != "High" {
		t.Errorf("thresholds not extracted: %+v", p)
	}
	m, _ := p.ToModel("local")
	if m.MinConfidence != "medium" || m.FailOn != "High" {
		t.Errorf("ToModel did not carry thresholds: %+v", m)
	}
}

func TestParseFile_rejectsBadThresholdValues(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "badconf", `---
name: badconf
description: d
metadata:
  scrutineer.min_confidence: maybe
---
body`)
	if _, err := ParseFile(path); err == nil || !strings.Contains(err.Error(), "not a valid level") {
		t.Errorf("expected min_confidence enum error, got %v", err)
	}

	path = writeSkill(t, dir, "badfail", `---
name: badfail
description: d
metadata:
  scrutineer.fail_on: extreme
---
body`)
	if _, err := ParseFile(path); err == nil || !strings.Contains(err.Error(), "not a valid level") {
		t.Errorf("expected fail_on enum error, got %v", err)
	}
}

func TestLoadDirectory_bundledSkillsAreValid(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	n, err := LoadDirectory(gdb, log, "../../skills", "local")
	if err != nil {
		t.Fatalf("bundled skills failed validation: %v", err)
	}
	if n == 0 {
		t.Fatal("no skills loaded from ../../skills")
	}
	var patch db.Skill
	if err := gdb.Where("name = ?", "patch").First(&patch).Error; err != nil {
		t.Fatalf("patch skill not loaded: %v", err)
	}
	if patch.MaxTurns != 50 {
		t.Errorf("patch max_turns = %d, want 50", patch.MaxTurns)
	}
}

func TestLoadDirectory_failsOnInvalidSkill(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeSkill(t, root, "good", `---
name: good
description: d
---
body`)
	writeSkill(t, root, "bad", `---
name: bad
description: d
metadata:
  scrutineer.output_kind: nope
---
body`)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err = LoadDirectory(gdb, log, root, "local")
	if err == nil {
		t.Error("expected LoadDirectory to fail on invalid skill")
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

func TestParseFile_pathsAndIgnorePaths(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "scoped", `---
name: scoped
description: Skill with path scoping.
metadata:
  scrutineer.paths:
    - src/**
    - lib/**
  scrutineer.ignore_paths:
    - "**/*.test.*"
---

body
`)
	p, err := ParseFile(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := p.Paths, []string{"src/**", "lib/**"}; !slices.Equal(got, want) {
		t.Errorf("Paths = %v, want %v", got, want)
	}
	if got, want := p.IgnorePaths, []string{"**/*.test.*"}; !slices.Equal(got, want) {
		t.Errorf("IgnorePaths = %v, want %v", got, want)
	}
	m, err := p.ToModel("local")
	if err != nil {
		t.Fatal(err)
	}
	if m.Paths != "src/**\nlib/**" {
		t.Errorf("db Paths = %q", m.Paths)
	}
	if m.IgnorePaths != "**/*.test.*" {
		t.Errorf("db IgnorePaths = %q", m.IgnorePaths)
	}
}

func TestParseFile_pathsWrongType(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "bad-paths", `---
name: bad-paths
description: Skill with non-list paths.
metadata:
  scrutineer.paths: "src/**"
---

body
`)
	if _, err := ParseFile(path); err == nil {
		t.Fatal("expected error when scrutineer.paths is not a list")
	}
}

func TestParseFile_pathsItemWrongType(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "bad-item", `---
name: bad-item
description: Skill with a non-string list entry.
metadata:
  scrutineer.ignore_paths:
    - "**/*.js"
    - 42
---

body
`)
	if _, err := ParseFile(path); err == nil {
		t.Fatal("expected error when scrutineer.ignore_paths contains a non-string")
	}
}

func TestParseFile_pathsMalformedGlob(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "bad-glob", `---
name: bad-glob
description: Skill with a malformed glob pattern.
metadata:
  scrutineer.paths:
    - "src/**"
    - "[unclosed"
---

body
`)
	_, err := ParseFile(path)
	if err == nil {
		t.Fatal("expected error when scrutineer.paths contains a malformed glob")
	}
	if !strings.Contains(err.Error(), "[unclosed") {
		t.Errorf("expected the offending pattern in the error, got: %v", err)
	}
}

func TestParseFile_pathsUnsetDefaultsNil(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "no-paths", `---
name: no-paths
description: Skill without path scoping.
---

body
`)
	p, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Paths != nil || p.IgnorePaths != nil {
		t.Errorf("paths defaults: %v / %v", p.Paths, p.IgnorePaths)
	}
}

func TestParseFile_requires(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "gated", `---
name: gated
description: Skill with declared prereqs.
metadata:
  scrutineer.requires:
    - threat-model
    - semgrep
---

body
`)
	p, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Requires, []string{"threat-model", "semgrep"}) {
		t.Errorf("Requires = %v, want [threat-model semgrep]", p.Requires)
	}
	m, _ := p.ToModel("local")
	if !slices.Equal(SplitPatterns(m.Requires), []string{"threat-model", "semgrep"}) {
		t.Errorf("model Requires roundtrip = %q", m.Requires)
	}
}

func TestParseFile_requiresWrongType(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "bad-req", `---
name: bad-req
description: Requires must be a list.
metadata:
  scrutineer.requires: threat-model
---

body
`)
	if _, err := ParseFile(path); err == nil || !strings.Contains(err.Error(), "list of strings") {
		t.Errorf("expected list-of-strings error, got %v", err)
	}
}

func TestParseFile_requiresEmptyEntry(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "empty-req", `---
name: empty-req
description: Empty entries reject so a typo surfaces.
metadata:
  scrutineer.requires:
    - threat-model
    - ""
---

body
`)
	if _, err := ParseFile(path); err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("expected empty-entry error, got %v", err)
	}
}

func TestParseFile_requiresUnsetDefaultsNil(t *testing.T) {
	dir := t.TempDir()
	path := writeSkill(t, dir, "no-req", `---
name: no-req
description: Skill without requires.
---

body
`)
	p, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Requires != nil {
		t.Errorf("Requires default = %v, want nil", p.Requires)
	}
}
