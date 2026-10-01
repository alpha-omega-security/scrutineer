//go:build !windows

package poc

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestCaptureRejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if files, err := captureTestDir(t, dir); err == nil || files != nil {
		t.Fatalf("accepted FIFO: %+v, %v", files, err)
	}
}
