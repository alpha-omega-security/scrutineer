package worker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareLocalSrc(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(srcDir, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "pkg", "doc.go"), []byte("package pkg\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	workRoot := t.TempDir()
	if err := prepareLocalSrc(srcDir, workRoot, func(Event) {}); err != nil {
		t.Fatalf("prepareLocalSrc: %v", err)
	}
	for _, rel := range []string{"src/main.go", "src/pkg/doc.go"} {
		if _, err := os.Stat(filepath.Join(workRoot, rel)); err != nil {
			t.Errorf("expected %s under workRoot: %v", rel, err)
		}
	}
}

func TestPrepareLocalSrcRejectsNonDir(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "f.txt")
	if err := os.WriteFile(file, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := prepareLocalSrc(file, t.TempDir(), func(Event) {}); err == nil {
		t.Fatal("expected error on non-directory source")
	}
}

func TestPrepareLocalSrcWithoutGitDir(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	workRoot := t.TempDir()
	if err := prepareLocalSrc(srcDir, workRoot, func(Event) {}); err != nil {
		t.Fatalf("dir with no .git should still be copied: %v", err)
	}
	if commit := gitHead(filepath.Join(workRoot, "src")); commit != "" {
		t.Errorf("gitHead on non-git dir = %q, want empty string (Scan.Commit will be blank)", commit)
	}
}

func TestPrepareLocalSrcFollowsSymlinkRoot(t *testing.T) {
	realDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(realDir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}

	workRoot := t.TempDir()
	if err := prepareLocalSrc(link, workRoot, func(Event) {}); err != nil {
		t.Fatalf("prepareLocalSrc on symlink root: %v", err)
	}

	if _, err := os.Stat(filepath.Join(workRoot, "src", "main.go")); err != nil {
		t.Errorf("expected src/main.go after copying through symlink root: %v", err)
	}
}

func TestPrepareLocalSrcRejectsMissing(t *testing.T) {
	if err := prepareLocalSrc("/does/not/exist/scrutineer-test", t.TempDir(), func(Event) {}); err == nil {
		t.Fatal("expected error on missing source")
	}
}

func TestValidateGitURL(t *testing.T) {
	good := []string{
		"https://github.com/splitrb/split",
		"https://gitlab.com/foo/bar.git",
	}
	for _, u := range good {
		if err := validateGitURL(u); err != nil {
			t.Errorf("should allow %q: %v", u, err)
		}
	}

	bad := []string{
		"http://github.com/foo/bar",
		"git@github.com:foo/bar.git",
		"ssh://git@host/repo",
		"file:///etc/passwd",
		"--upload-pack=/bin/sh",
		"-c core.fsmonitor=evil",
		"ext::sh -c evil",
		"",
	}
	for _, u := range bad {
		if err := validateGitURL(u); err == nil {
			t.Errorf("should reject %q", u)
		}
	}
}
