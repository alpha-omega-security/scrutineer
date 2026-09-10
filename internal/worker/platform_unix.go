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
// the terminator can signal every descendant at once.
func setNewProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// superviseProcessGroup returns the func that sends SIGTERM to cmd's process
// group, reaping children the runtime or harness CLI left running. Call it
// once Wait has returned.
func superviseProcessGroup(cmd *exec.Cmd) func() {
	return func() {
		if cmd.Process == nil {
			return
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
}

// containerUserArgs maps the container user onto the invoking host user so
// bind-mount writes stay host-owned.
func containerUserArgs() []string {
	return []string{"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())}
}
