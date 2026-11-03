//go:build !windows

package worker

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestStageVIDFileRejectsFIFO(t *testing.T) {
	src := t.TempDir()
	path := filepath.Join(src, "pipe.c")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	sourceRoot, err := os.OpenRoot(src)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sourceRoot.Close() }()
	stageRoot, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stageRoot.Close() }()
	result := make(chan error, 1)
	remaining := int64(vidStageMaxBytes)
	go func() { result <- stageVIDFile(sourceRoot, stageRoot, "pipe.c", &remaining) }()
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrInvalid) {
			t.Fatalf("stage FIFO: %v, want invalid file", err)
		}
	case <-time.After(time.Second):
		fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NONBLOCK, 0)
		if err == nil {
			t.Logf("unblocked FIFO read: %v", <-result)
			_ = syscall.Close(fd)
		}
		t.Fatal("VID staging blocked on a FIFO")
	}
	if _, err := stageRoot.Stat("pipe.c"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("FIFO produced a staged file: %v", err)
	}
}
