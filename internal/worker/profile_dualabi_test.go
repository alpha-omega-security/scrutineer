package worker

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestRubyExtGuideDocumentsInterpreters fails if the ruby-ext image ships an
// interpreter prefix or shims dir the PROFILE.md never names (the agent would be
// told to use a binary that is not there, or miss one that is). Each interpreter's
// build-time correctness is covered by the Dockerfile's own probes, not here.
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
	// Every /usr/local/ruby-* prefix or shims dir the Dockerfile builds, plus the
	// one-off entry points it links into /usr/local/bin.
	seen := map[string]bool{}
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`/usr/local/ruby-[a-z0-9-]+(?:/shims)?`),
		regexp.MustCompile(`ln -s \S+ /usr/local/bin/(\S+)`),
	} {
		for _, m := range re.FindAllStringSubmatch(string(df), -1) {
			tok := m[len(m)-1]
			if strings.HasSuffix(tok, "/shims") {
				tok = strings.TrimSuffix(tok, "/shims")
			}
			seen[tok] = true
		}
	}
	var toks []string
	for tok := range seen {
		toks = append(toks, tok)
	}
	sort.Strings(toks)
	if len(toks) < 3 {
		t.Fatalf("ruby-ext: expected at least the 3.4, 4.0 and stock prefixes in the Dockerfile, found %v", toks)
	}
	for _, tok := range toks {
		if !strings.Contains(string(guide), tok) {
			t.Errorf("ruby-ext: Dockerfile ships %q but PROFILE.md does not document it", tok)
		}
	}
}
