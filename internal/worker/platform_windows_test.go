//go:build windows

package worker

import (
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSetNewProcessGroupDetachesConsoleGroup(t *testing.T) {
	cmd := exec.Command("cmd")
	setNewProcessGroup(cmd)
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.CreationFlags&syscall.CREATE_NEW_PROCESS_GROUP == 0 {
		t.Fatalf("SysProcAttr = %+v, want CREATE_NEW_PROCESS_GROUP", cmd.SysProcAttr)
	}
}

// A descendant started with Start-Process outlives the child that spawned it,
// so it is still running once Wait returns and only the job's kill-on-close
// limit brings it down.
func TestSuperviseProcessGroupKillsDescendant(t *testing.T) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"(Start-Process -PassThru -WindowStyle Hidden powershell.exe -ArgumentList '-NoProfile','-Command','Start-Sleep 30').Id")
	setNewProcessGroup(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	terminate := sync.OnceFunc(superviseProcessGroup(cmd))
	t.Cleanup(terminate)
	out, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("powershell: %v (%q)", err, out)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("descendant pid from %q: %v", out, err)
	}

	// Held across terminate so the pid cannot be recycled under the wait.
	proc, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		t.Fatalf("descendant %d not running before terminate: %v", pid, err)
	}
	defer func() { _ = windows.CloseHandle(proc) }()

	terminate()

	switch event, err := windows.WaitForSingleObject(proc, 5000); {
	case err != nil:
		t.Fatalf("waiting on descendant %d: %v", pid, err)
	case event != windows.WAIT_OBJECT_0:
		t.Fatalf("descendant %d still alive after terminate: event %#x", pid, event)
	}
}
