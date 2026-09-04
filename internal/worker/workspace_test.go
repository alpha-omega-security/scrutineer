package worker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceWorkspaceFile_replacesPlantedDirectory(t *testing.T) {
	work := t.TempDir()
	planted := filepath.Join(work, "CLAUDE.md")
	if err := os.MkdirAll(filepath.Join(planted, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := replaceWorkspaceFile(work, "CLAUDE.md", []byte("guide\n")); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(planted); err != nil || string(got) != "guide\n" {
		t.Errorf("replacement = %q, %v", got, err)
	}
}

func TestReplaceWorkspaceFile_refusesNonLocalPath(t *testing.T) {
	parent := t.TempDir()
	work := filepath.Join(parent, "work")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"../escape.md", "/etc/escape.md", ""} {
		if err := replaceWorkspaceFile(work, rel, nil); err == nil {
			t.Errorf("rel %q: expected a refusal", rel)
		}
	}
	if _, err := os.Lstat(filepath.Join(parent, "escape.md")); !os.IsNotExist(err) {
		t.Errorf("wrote outside the workspace: lstat err = %v", err)
	}
}

func TestResetWorkspace_emptiesAnExistingTree(t *testing.T) {
	parent := t.TempDir()
	work := filepath.Join(parent, "work")
	if err := os.MkdirAll(filepath.Join(work, "src", "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../victim", filepath.Join(work, "context.json")); err != nil {
		t.Fatal(err)
	}
	if err := resetWorkspace(work); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(work)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("workspace not emptied: %d entries", len(entries))
	}
	if _, err := os.Lstat(filepath.Join(parent, "victim")); !os.IsNotExist(err) {
		t.Errorf("reset touched the link target: lstat err = %v", err)
	}
	if err := resetWorkspace(filepath.Join(parent, "fresh")); err != nil {
		t.Errorf("reset of a missing workspace: %v", err)
	}
}
