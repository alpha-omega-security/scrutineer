package worker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRubyExtGuideDocumentsInterpreters fails if the ruby-ext image ships an ASan
// interpreter the PROFILE.md never names (the agent would be told to use a binary
// that is not there, or miss one that is). Each interpreter's build-time
// correctness is covered by the Dockerfile's own probes, not here.
func TestRubyExtGuideDocumentsInterpreters(t *testing.T) {
	dir := filepath.Join("..", "..", "docker", "profiles", "ruby-ext")
	df, err := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	guide, err := os.ReadFile(filepath.Join(dir, "PROFILE.md"))
	if err != nil {
		t.Fatal(err)
	}
	// The 4.0 interpreter's binary and prefix must be documented when the image builds them.
	for _, tok := range []string{"ruby4", "/usr/local/ruby-asan-40"} {
		if strings.Contains(string(df), tok) && !strings.Contains(string(guide), tok) {
			t.Errorf("ruby-ext: Dockerfile ships %q but PROFILE.md does not document it", tok)
		}
	}
}
