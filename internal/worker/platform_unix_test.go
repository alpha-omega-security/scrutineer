//go:build unix

package worker

import (
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSetNewProcessGroupSetsPgid(t *testing.T) {
	cmd := exec.Command("true")
	setNewProcessGroup(cmd)
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		t.Fatalf("SysProcAttr = %+v, want Setpgid", cmd.SysProcAttr)
	}
}

// A grandchild outlives the child that spawned it until its process group is
// signalled. It inherits the pipe's write end, so EOF on the read end is its
// exit whether or not an ancestor reaps it.
func TestTerminateProcessGroupReapsGrandchild(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	cmd := exec.Command("sh", "-c", "sleep 30 >/dev/null 2>&1 & echo $!")
	cmd.ExtraFiles = []*os.File{w}
	setNewProcessGroup(cmd)
	t.Cleanup(func() { terminateProcessGroup(cmd) })
	out, err := cmd.Output()
	_ = w.Close()
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("grandchild pid from %q: %v", out, err)
	}
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("grandchild %d not running before terminate: %v", pid, err)
	}

	terminateProcessGroup(cmd)

	exited := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, r)
		close(exited)
	}()
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		t.Fatalf("grandchild %d still alive after terminateProcessGroup", pid)
	}
}
