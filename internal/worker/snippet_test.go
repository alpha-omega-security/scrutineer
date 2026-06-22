package worker

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeNumberedFile(t *testing.T, srcDir, rel string, lines int) {
	t.Helper()
	var b strings.Builder
	for i := 1; i <= lines; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	p := filepath.Join(srcDir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadSnippet(t *testing.T) {
	srcDir := t.TempDir()
	writeNumberedFile(t, srcDir, "a.go", 20)
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	join := func(from, to int) string {
		var parts []string
		for i := from; i <= to; i++ {
			parts = append(parts, fmt.Sprintf("line %d", i))
		}
		return strings.Join(parts, "\n")
	}

	t.Run("mid file captures five lines either side", func(t *testing.T) {
		if got, want := readSnippet(srcDir, "a.go:10"), join(5, 15); got != want {
			t.Errorf("readSnippet = %q\nwant %q", got, want)
		}
	})
	t.Run("clamps at start of file", func(t *testing.T) {
		if got, want := readSnippet(srcDir, "a.go:2"), join(1, 7); got != want {
			t.Errorf("readSnippet = %q\nwant %q", got, want)
		}
	})
	t.Run("clamps at end of file", func(t *testing.T) {
		got := readSnippet(srcDir, "a.go:19")
		if !strings.Contains(got, "line 14") || !strings.Contains(got, "line 20") {
			t.Errorf("readSnippet near EOF = %q, want lines 14..20", got)
		}
		if strings.Contains(got, "line 13") {
			t.Errorf("readSnippet near EOF leaked line 13: %q", got)
		}
	})
	t.Run("tolerates ./ prefix, column, and range suffixes", func(t *testing.T) {
		want := join(5, 15)
		for _, loc := range []string{"./a.go:10", "a.go:10:4", "a.go:10-12"} {
			if got := readSnippet(srcDir, loc); got != want {
				t.Errorf("readSnippet(%q) = %q\nwant %q", loc, got, want)
			}
		}
	})

	// Unhappy paths: every one must degrade to "" so the finding is still
	// saved without a snippet rather than erroring.
	t.Run("returns empty when unreadable or unsafe", func(t *testing.T) {
		cases := map[string]string{
			"no line number":     "a.go",
			"empty location":     "",
			"line past EOF":      "a.go:999",
			"missing file":       "missing.go:1",
			"path traversal":     "../secret:1",
			"absolute path":      "/etc/passwd:1",
			"directory not file": "sub:1",
		}
		for name, loc := range cases {
			if got := readSnippet(srcDir, loc); got != "" {
				t.Errorf("%s: readSnippet(%q) = %q, want \"\"", name, loc, got)
			}
		}
	})

	t.Run("rejects symlink escaping the checkout", func(t *testing.T) {
		outside := filepath.Join(t.TempDir(), "host-secret")
		if err := os.WriteFile(outside, []byte("secret\nsecret\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(srcDir, "evil.go")); err != nil {
			t.Fatal(err)
		}
		if got := readSnippet(srcDir, "evil.go:1"); got != "" {
			t.Errorf("readSnippet via escaping symlink = %q, want \"\"", got)
		}
	})
}
