package worker

import (
	"os"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/skills"
)

func writeScopeFile(t *testing.T, root, rel string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func gone(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected %s pruned, stat err = %v", path, err)
	}
}

func present(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected %s kept, stat err = %v", path, err)
	}
}

func TestPruneToSubPath_topLevel(t *testing.T) {
	src := t.TempDir()
	writeScopeFile(t, src, ".git/HEAD")
	writeScopeFile(t, src, "activesupport/lib/foo.rb")
	writeScopeFile(t, src, "actionpack/lib/bar.rb")
	writeScopeFile(t, src, "README.md")

	if err := pruneToSubPath(src, "activesupport"); err != nil {
		t.Fatal(err)
	}
	present(t, filepath.Join(src, "activesupport/lib/foo.rb"))
	present(t, filepath.Join(src, ".git/HEAD")) // git preserved for git-based skills
	gone(t, filepath.Join(src, "actionpack"))
	gone(t, filepath.Join(src, "README.md"))
}

func TestPruneToSubPath_nested(t *testing.T) {
	src := t.TempDir()
	writeScopeFile(t, src, ".git/HEAD")
	writeScopeFile(t, src, "packages/core/index.js")
	writeScopeFile(t, src, "packages/other/index.js")
	writeScopeFile(t, src, "apps/web/index.js")

	if err := pruneToSubPath(src, "packages/core"); err != nil {
		t.Fatal(err)
	}
	present(t, filepath.Join(src, "packages/core/index.js"))
	present(t, filepath.Join(src, ".git/HEAD"))
	gone(t, filepath.Join(src, "packages/other"))
	gone(t, filepath.Join(src, "apps"))
}

func TestPruneToSubPath_missing(t *testing.T) {
	src := t.TempDir()
	writeScopeFile(t, src, "README.md")
	if err := pruneToSubPath(src, "nope"); err == nil {
		t.Error("expected error for a sub_path that does not exist")
	}
}

func TestScanScopeHard(t *testing.T) {
	hard := &Worker{SubprojectScope: "hard"}
	soft := &Worker{SubprojectScope: "soft"}
	unset := &Worker{}
	fid := uint(5)
	cases := []struct {
		name       string
		w          *Worker
		scan       db.Scan
		outputKind string
		want       bool
	}{
		{"root scan never hard", hard, db.Scan{SubPath: ""}, "findings", false},
		{"subpath + hard default", hard, db.Scan{SubPath: "as"}, "findings", true},
		{"subpath + soft default", soft, db.Scan{SubPath: "as"}, "findings", false},
		{"subpath + unset default is soft", unset, db.Scan{SubPath: "as"}, "findings", false},
		{"override soft beats hard default", hard, db.Scan{SubPath: "as", ScopeMode: "soft"}, "findings", false},
		{"override hard beats soft default", soft, db.Scan{SubPath: "as", ScopeMode: "hard"}, "findings", true},
		{"finding-scoped stays soft", hard, db.Scan{SubPath: "as", FindingID: &fid}, "findings", false},
		{"diff rescan stays soft", hard, db.Scan{SubPath: "as", RescanMode: "diff"}, "findings", false},
		// Repo-wide projection kinds never hard-scope even under a hard default
		// with an explicit hard override — pruning would let their parser wipe
		// the other sub-packages' rows.
		{"subprojects opts out", hard, db.Scan{SubPath: "as"}, "subprojects", false},
		{"dependencies opts out", hard, db.Scan{SubPath: "as"}, "dependencies", false},
		{"maintainers opts out", hard, db.Scan{SubPath: "as"}, "maintainers", false},
		{"repo-wide beats explicit hard override", hard, db.Scan{SubPath: "as", ScopeMode: "hard"}, "subprojects", false},
		{"code audit still hard under hard default", hard, db.Scan{SubPath: "as"}, "threat_model", true},
	}
	for _, tc := range cases {
		if got := tc.w.scanScopeHard(&tc.scan, tc.outputKind); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

// TestRepoWideProjectionKinds_everyOutputKindClassified forces a deliberate
// choice for every recognised output kind: it is either a repo-wide projection
// (repoWideProjectionKinds, opts out of hard scope) or a per-scope kind that may
// hard-scope. A new kind added to skills.OutputKinds without a home in exactly
// one of these fails here rather than silently defaulting to hard-scopable —
// which for a repo-wide, wholesale-replace parser would let a scoped run wipe
// sibling rows. If this fails, classify the new kind, do not just add it below.
func TestRepoWideProjectionKinds_everyOutputKindClassified(t *testing.T) {
	// Kinds that describe one scope (a finding, a dependent, or a sub-folder of
	// code) and so may legitimately hard-scope, plus the no-parser kinds.
	perScopeKinds := map[string]bool{
		"":                true, // stored verbatim, no parser
		"freeform":        true, // stored verbatim, no parser
		"findings":        true, // code audits: security-deep-dive, semgrep, ...
		"advisory_audit":  true, // per-advisory code reproduction
		"threat_model":    true, // per-subproject threat model
		"exposure":        true, // per-dependent reachability
		"verify":          true, // finding-scoped
		"revalidate":      true, // finding-scoped
		"breaking_change": true, // finding-scoped
		"mitigation":      true, // finding-scoped
		"disclose":        true, // finding-scoped
		"release_watch":   true, // finding-scoped
		"patch":           true, // finding-scoped
		"reattack":        true, // finding-scoped
	}
	for kind := range skills.OutputKinds {
		repoWide := repoWideProjectionKinds[kind]
		perScope := perScopeKinds[kind]
		if repoWide == perScope {
			t.Errorf("output kind %q must be classified in exactly one of repoWideProjectionKinds or the per-scope set (repoWide=%v perScope=%v)", kind, repoWide, perScope)
		}
	}
}

func TestIsDependencyResolutionFailure(t *testing.T) {
	pos := []string{
		`Bundler could not find compatible versions for gem "activesupport"`,
		"npm ERR! code ERESOLVE\nnpm ERR! unable to resolve dependency tree",
		"ERROR: Could not find a version that satisfies the requirement foo",
		"error: failed to select a version for `foo`",
		"go: no required module provides package example.com/x",
		"[ERROR] No solution found, exiting",
		"Your requirements could not be resolved to an installable set of packages.",
	}
	neg := []string{
		"",
		"SyntaxError: unexpected token",
		"undefined method `foo' for nil:NilClass",
		"2 failing tests",
		"segmentation fault",
	}
	for _, s := range pos {
		if !isDependencyResolutionFailure(s) {
			t.Errorf("want dependency-resolution failure for %q", s)
		}
	}
	for _, s := range neg {
		if isDependencyResolutionFailure(s) {
			t.Errorf("false positive for %q", s)
		}
	}
}
