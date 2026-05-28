package worker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirSize_SumsRegularFilesAcrossSubdirs(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "nested", "deep")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a"), make([]byte, 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "b"), make([]byte, 512), 0o600); err != nil {
		t.Fatal(err)
	}

	n, err := dirSize(root)
	if err != nil {
		t.Fatalf("dirSize: %v", err)
	}
	if n != 1536 {
		t.Errorf("dirSize = %d, want 1536", n)
	}
}

func TestDirSize_ErrorsOnMissingRoot(t *testing.T) {
	// Walk on a missing path returns an error. The hardened cap relies
	// on this propagation to fail closed: an unverifiable workspace
	// must not slip past the size check.
	_, err := dirSize(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("dirSize on missing path returned no error")
	}
}

func TestDirSize_IgnoresIrregularEntries(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file"), make([]byte, 256), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file", filepath.Join(root, "link")); err != nil {
		// Symlink creation can fail on filesystems that don't support
		// it; skip rather than fail since the assertion below covers
		// the regular-file case either way.
		t.Skipf("symlink not supported: %v", err)
	}
	n, err := dirSize(root)
	if err != nil {
		t.Fatalf("dirSize: %v", err)
	}
	if n != 256 {
		t.Errorf("dirSize = %d, want 256 (symlinks must not be counted)", n)
	}
}
