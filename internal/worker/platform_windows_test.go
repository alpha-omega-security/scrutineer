//go:build windows

package worker

import (
	"os/exec"
	"syscall"
	"testing"
)

func TestSetNewProcessGroupDetachesConsoleGroup(t *testing.T) {
	cmd := exec.Command("cmd")
	setNewProcessGroup(cmd)
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.CreationFlags&syscall.CREATE_NEW_PROCESS_GROUP == 0 {
		t.Fatalf("SysProcAttr = %+v, want CREATE_NEW_PROCESS_GROUP", cmd.SysProcAttr)
	}
}
