//go:build windows

package worker

import "os/exec"

// setProcGroup is a no-op probe stub: Windows has no Setpgid and this branch
// exists to see what the test suite does on windows-latest, not to ship.
func setProcGroup(*exec.Cmd) {}

// killProcGroup kills only the direct child. Grandchildren survive; good
// enough for a CI probe.
func killProcGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
