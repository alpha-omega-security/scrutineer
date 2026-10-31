package worker

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A fake binary on PATH stands in for git, a container runtime or an agent
// CLI. On unix the installed file is the shell script itself. Windows launches
// neither a shebang file nor a .cmd shim through CreateProcess, so there the
// fake is a copy of this test binary: it re-enters TestMain, finds the script
// stored beside itself and hands it to the shell named in the companion file.
const (
	fakeBinScriptExt = ".fake-script"
	fakeBinShellExt  = ".fake-shell"
)

// fakeBinArgsPrelude rebuilds the arguments from the environment, where
// runFakeBin puts them because the MSYS shell on Windows splits its command
// line by its own rules and mangles an argument holding a double quote.
const fakeBinArgsPrelude = `set --
i=0
while [ "$i" -lt "$FAKEBIN_ARGC" ]; do
 eval "set -- \"\$@\" \"\${FAKEBIN_ARG_$i}\""
 i=$((i+1))
done
unset i
`

// hostShell is empty when the machine has no POSIX shell. It is resolved in
// TestMain because a test that narrows PATH would otherwise hide it, and the
// fake needs an absolute path to hand CreateProcess.
var hostShell string

func TestMain(m *testing.M) {
	hostShell, _ = exec.LookPath("sh")
	if self, err := os.Executable(); err == nil {
		if shell, err := os.ReadFile(self + fakeBinShellExt); err == nil {
			os.Exit(runFakeBin(string(shell), self+fakeBinScriptExt))
		}
	}
	os.Exit(m.Run())
}

func runFakeBin(shell, script string) int {
	cmd := exec.Command(shell, script)
	cmd.Env = append(os.Environ(), fmt.Sprintf("FAKEBIN_ARGC=%d", len(os.Args)-1))
	for i, arg := range os.Args[1:] {
		cmd.Env = append(cmd.Env, fmt.Sprintf("FAKEBIN_ARG_%d=%s", i, arg))
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := cmd.Run()
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	fmt.Fprintln(os.Stderr, err)
	return 127
}

// writeFakeBin installs body as an executable called name in dir and returns
// the path the runner under test will resolve.
func writeFakeBin(t *testing.T, dir, name, body string) string {
	t.Helper()
	skipWithoutPOSIXShell(t)
	if runtime.GOOS != "windows" {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".exe")
	for ext, content := range map[string]string{fakeBinScriptExt: fakeBinArgsPrelude + body, fakeBinShellExt: hostShell} {
		if err := os.WriteFile(path+ext, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(self, path); err != nil {
		copyFakeBin(t, self, path)
	}
	return path
}

// TestFakeBinKeepsArguments pins that a fake binary receives each argument
// unchanged, quotes, spaces, backslashes and empty ones included.
func TestFakeBinKeepsArguments(t *testing.T) {
	bin := writeFakeBin(t, t.TempDir(), "echo-args", "#!/bin/sh\nprintf '[%s]\\n' \"$@\"\n")
	args := []string{`model_reasoning_effort="high"`, "two words", `C:\work\src`, "", "--", "a'b"}
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		t.Fatal(err)
	}
	var want strings.Builder
	for _, arg := range args {
		want.WriteString("[" + arg + "]\n")
	}
	if string(out) != want.String() {
		t.Errorf("fake binary saw %q, want %q", out, want.String())
	}
}

func copyFakeBin(t *testing.T, self, path string) {
	t.Helper()
	src, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	dst, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
}
