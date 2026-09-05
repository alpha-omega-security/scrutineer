//go:build unix

package worker

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// setNewProcessGroup starts cmd in its own process group, so a terminal
// interrupt reaches scrutineer's shutdown path rather than the child, and so
// terminateProcessGroup can signal every descendant at once.
func setNewProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// terminateProcessGroup sends SIGTERM to cmd's process group once Wait has
// returned, reaping children the runtime or harness CLI left running.
func terminateProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
}

// containerUserArgs maps the container user onto the invoking host user so
// bind-mount writes stay host-owned.
func containerUserArgs() []string {
	return []string{"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())}
}
