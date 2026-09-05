package worker

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"testing"
)

func skipOnWindows(t *testing.T, why string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip(why)
	}
}

// skipWithoutPOSIXShell skips a test whose fake binary is a shell script:
// Windows cannot exec a shebang file.
func skipWithoutPOSIXShell(t *testing.T) {
	t.Helper()
	skipOnWindows(t, "the fake binary is a POSIX shell script")
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("needs a POSIX shell to run the fake binary")
	}
}

func TestContainerUserArgs(t *testing.T) {
	got := containerUserArgs()
	if runtime.GOOS == "windows" {
		if len(got) != 0 {
			t.Fatalf("containerUserArgs() = %v, want none: no host uid to map", got)
		}
		return
	}
	want := []string{"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())}
	if !slices.Equal(got, want) {
		t.Fatalf("containerUserArgs() = %v, want %v", got, want)
	}
}

// A command that never started has no process to signal.
func TestTerminateProcessGroupBeforeStart(t *testing.T) {
	terminateProcessGroup(exec.Command("scrutineer-never-started"))
}
