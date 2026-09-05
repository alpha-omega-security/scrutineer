//go:build windows

package worker

import (
	"os/exec"
	"syscall"
)

// setNewProcessGroup detaches cmd from the console's Ctrl+C group, the
// Windows counterpart of Setpgid: the interrupt reaches scrutineer's shutdown
// path, which cancels the context and kills the child.
func setNewProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

// terminateProcessGroup is a no-op: Windows has no signalable process groups,
// and Wait has already collected the direct child, so descendants a dead CLI
// left behind are not reaped here.
func terminateProcessGroup(*exec.Cmd) {}

// containerUserArgs is empty on Windows: os.Getuid reports -1 there, so the
// container keeps the runner image's own non-root user.
func containerUserArgs() []string {
	return nil
}
