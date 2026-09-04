//go:build !windows

package worker

import (
	"os/exec"
	"syscall"
)

// setProcGroup puts the child in its own process group so killProcGroup can
// signal the whole tree, not just the direct child.
func setProcGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcGroup best-effort SIGTERMs the started command's process group.
func killProcGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
}
