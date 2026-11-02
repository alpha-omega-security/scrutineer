package worker

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestRubyExtDualInterpreterParity keeps the ruby-ext image's two ASan
// interpreters in lockstep with the PROFILE.md that orients the agent about
// them. The Dockerfile builds a default `ruby` (3.4.x -> /usr/local/ruby-asan)
// and a second `ruby4` (4.0.x -> /usr/local/ruby-asan-40); the PROFILE.md tells
// the reproduction skills when to use each and to test both for layout-sensitive
// memory bugs. Drift between them — an interpreter the image ships but the guide
// never names, or one the guide advertises but the image lacks — makes the agent
// either miss coverage or chase a binary that isn't there, so this pins them.
func TestRubyExtDualInterpreterParity(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(b)
	}
	argValue := func(dockerfile, name string) string {
		m := regexp.MustCompile(`(?m)^ARG ` + regexp.QuoteMeta(name) + `=(\S+)`).FindStringSubmatch(dockerfile)
		if m == nil {
			return ""
		}
		return m[1]
	}

	wd, _ := os.Getwd()
	dir := filepath.Join(wd, "..", "..", "docker", "profiles", "ruby-ext")
	dockerfile := read(filepath.Join(dir, "Dockerfile"))
	profile := read(filepath.Join(dir, "PROFILE.md"))

	// Both Ruby refs are pinned as ARGs. 4.0.x release tags use dots (v4.0.6);
	// 3.4.x use underscores (v3_4_9) — so assert only that the 4.0 ref is a 4.x
	// tag, never that the two share a separator convention.
	if argValue(dockerfile, "RUBY_GIT_REF") == "" {
		t.Error("ruby-ext Dockerfile: ARG RUBY_GIT_REF (3.4 interpreter) not found")
	}
	ref40 := argValue(dockerfile, "RUBY_GIT_REF_40")
	if ref40 == "" {
		t.Error("ruby-ext Dockerfile: ARG RUBY_GIT_REF_40 (4.0 interpreter) not found")
	} else if !strings.HasPrefix(ref40, "v4") {
		t.Errorf("ruby-ext Dockerfile: RUBY_GIT_REF_40=%q is not a 4.x tag (want v4.y.z)", ref40)
	}

	// Every ASan interpreter the image ships must be documented in PROFILE.md and
	// vice versa: the Dockerfile builds the 4.0 interpreter to a fixed prefix and
	// exposes it as `ruby4`, and the guide must name both so the agent uses it.
	for _, token := range []string{"/usr/local/ruby-asan-40", "ruby4"} {
		if !strings.Contains(dockerfile, token) {
			t.Errorf("ruby-ext Dockerfile: expected to build/expose %q for the 4.0 ASan interpreter", token)
		}
		if !strings.Contains(profile, token) {
			t.Errorf("ruby-ext PROFILE.md: 4.0 ASan interpreter %q is undocumented (Dockerfile and guide drifted)", token)
		}
	}

	// The default interpreter prefix is shared by both files; a rename in one
	// without the other is caught here.
	if !strings.Contains(dockerfile, "/usr/local/ruby-asan") {
		t.Error("ruby-ext Dockerfile: default ASan interpreter prefix /usr/local/ruby-asan not found")
	}

	// The `ruby4` symlink is what puts the 4.0 interpreter on PATH; without it the
	// PROFILE.md guidance to run `ruby4 ...` would not resolve.
	if !regexp.MustCompile(`ln -s\s+\S*ruby-asan-40\S*\s+/usr/local/bin/ruby4`).MatchString(dockerfile) {
		t.Error("ruby-ext Dockerfile: `ruby4` is not symlinked onto PATH (ln -s .../ruby-asan-40/... /usr/local/bin/ruby4)")
	}
}
