package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const stubPerm = 0o755

// WriteStub writes a #!/bin/sh script as an executable named `name` under
// `dir` and returns its full path. Tests use it to put a fake `git`,
// `docker`, `claude`, etc. on PATH so the code under test execs the stub
// instead of the real binary.
//
// On Windows the test is skipped: exec.LookPath resolves via PATHEXT, so a
// bare-named file with a shebang is never found, and there is no /bin/sh to
// run it if it were.
func WriteStub(tb testing.TB, dir, name, script string) string {
	tb.Helper()
	if runtime.GOOS == "windows" {
		tb.Skipf("test uses a #!/bin/sh stub for %q", name)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), stubPerm); err != nil {
		tb.Fatal(err)
	}
	return path
}
