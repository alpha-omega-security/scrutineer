package worker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
	"scrutineer/internal/testutil"
)

// seedCacheFile writes a file of n bytes into the clone cache for url under
// dataDir, so RepoDiskUsage reports a known non-zero size.
func seedCacheFile(t *testing.T, dataDir, url string, n int) {
	t.Helper()
	dir := RepoCacheRoot(dataDir, url)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blob"), make([]byte, n), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshRepoDiskUsage_storesComputedSize(t *testing.T) {
	dataDir := t.TempDir()
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/a", Name: "a"}
	gdb.Create(&repo)
	seedCacheFile(t, dataDir, repo.URL, 2048)

	w := &Worker{DB: gdb, DataDir: dataDir, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w.refreshRepoDiskUsage(repo.ID)

	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.DiskBytes != 2048 {
		t.Errorf("DiskBytes = %d, want 2048", got.DiskBytes)
	}
}

func TestBackfillRepoDiskUsage_fillsZeroRowsSkipsLocal(t *testing.T) {
	dataDir := t.TempDir()
	gdb := dbtest.Open(t)
	remote := db.Repository{URL: "https://example.com/remote", Name: "remote"}
	local := db.Repository{URL: "file:///tmp/local", Name: "local"}
	uncached := db.Repository{URL: "https://example.com/uncached", Name: "uncached"}
	gdb.Create(&remote)
	gdb.Create(&local)
	gdb.Create(&uncached)
	seedCacheFile(t, dataDir, remote.URL, 4096)
	// A local repo with a stray cache dir must still be skipped on IsLocal.
	seedCacheFile(t, dataDir, local.URL, 9999)

	BackfillRepoDiskUsage(gdb, dataDir)

	sizeOf := func(id uint) int64 {
		var r db.Repository
		gdb.First(&r, id)
		return r.DiskBytes
	}
	if got := sizeOf(remote.ID); got != 4096 {
		t.Errorf("remote DiskBytes = %d, want 4096", got)
	}
	if got := sizeOf(local.ID); got != 0 {
		t.Errorf("local DiskBytes = %d, want 0 (local repos skipped)", got)
	}
	if got := sizeOf(uncached.ID); got != 0 {
		t.Errorf("uncached DiskBytes = %d, want 0 (no cache dir)", got)
	}
}

func TestBackfillRepoDiskUsage_leavesNonZeroAlone(t *testing.T) {
	dataDir := t.TempDir()
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/keep", Name: "keep", DiskBytes: 123}
	gdb.Create(&repo)
	// Cache on disk says 4096, but the row already carries a value; the
	// backfill only touches rows at 0, so the stored value must be kept.
	seedCacheFile(t, dataDir, repo.URL, 4096)

	BackfillRepoDiskUsage(gdb, dataDir)

	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.DiskBytes != 123 {
		t.Errorf("DiskBytes = %d, want 123 (non-zero rows are not re-walked)", got.DiskBytes)
	}
}

func TestRepoCacheRoot(t *testing.T) {
	a := RepoCacheRoot("/data", "https://github.com/a/b")
	b := RepoCacheRoot("/data", "https://github.com/a/b")
	c := RepoCacheRoot("/data", "https://github.com/c/d")
	if a != b {
		t.Errorf("same URL should produce same path: %q vs %q", a, b)
	}
	if a == c {
		t.Errorf("different URLs should produce different paths, both %q", a)
	}
	// Pin the sha256(url) layout so a clone.Cache release that changes Dir()
	// fails here rather than silently re-keying every existing cache dir on
	// disk (docs/skills.md documents this layout, and RemoveAll on the old
	// path would leave orphans).
	want := filepath.Join("/data", "repo-cache",
		"426415da6467c87a94a513112f24b70d4b6adf406b39e4b9e74ac984d9221813")
	if a != want {
		t.Errorf("path %q, want %q", a, want)
	}
}

func newEmbeddedNativeOrigin(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	if runtime.GOOS == "windows" {
		// clone.Ensure's submodule update --init step and Submodules() report
		// a gitlink/commit mismatch on Windows; the top-level clone is fine.
		t.Skip("submodule init under the file:// insteadOf fixture fails on Windows")
	}

	submoduleDir := t.TempDir()
	testGit(t, submoduleDir, "init", "--quiet", "-b", "main")
	if err := os.WriteFile(filepath.Join(submoduleDir, "native.c"), []byte("int native(void) { return 1; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, submoduleDir, "add", "native.c")
	testGit(t, submoduleDir, "commit", "--quiet", "-m", "native source")

	originDir := t.TempDir()
	testGit(t, originDir, "init", "--quiet", "-b", "main")
	if err := os.WriteFile(filepath.Join(originDir, "host.py"), []byte("print('host')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, originDir, "add", "host.py")
	testGit(t, originDir, "commit", "--quiet", "-m", "host source")
	url := "https://clone.test/embedded-native"
	submoduleURL := "https://github.com/example/native.git"
	t.Setenv("GIT_CONFIG_COUNT", "3")
	t.Setenv("GIT_CONFIG_KEY_0", "url.file://"+originDir+".insteadOf")
	t.Setenv("GIT_CONFIG_VALUE_0", url)
	t.Setenv("GIT_CONFIG_KEY_1", "url.file://"+submoduleDir+".insteadOf")
	t.Setenv("GIT_CONFIG_VALUE_1", submoduleURL)
	t.Setenv("GIT_CONFIG_KEY_2", "protocol.file.allow")
	t.Setenv("GIT_CONFIG_VALUE_2", "always")
	t.Setenv("GIT_ALLOW_PROTOCOL", "https:file")
	testGit(t, originDir, "-c", "protocol.file.allow=always", "submodule", "add", "--quiet",
		submoduleURL, "vendor/native")
	testGit(t, originDir, "commit", "--quiet", "-m", "native submodule")
	return url
}

func TestPrepareRepoSrcWithOptionsKeepsSubmodulesOptIn(t *testing.T) {
	url := newEmbeddedNativeOrigin(t)

	w := &Worker{DataDir: t.TempDir()}
	withSubmodules := t.TempDir()
	if _, err := w.prepareRepoSrcWithOptions(
		context.Background(), url, "", withSubmodules, true, func(Event) {},
	); err != nil {
		t.Fatalf("prepare with submodules: %v", err)
	}
	nativePath := filepath.Join(withSubmodules, "src", "vendor", "native", "native.c")
	if _, err := os.Stat(nativePath); err != nil {
		t.Fatalf("submodule source missing: %v", err)
	}

	withoutSubmodules := t.TempDir()
	if _, err := w.PrepareSrc(context.Background(), url, "", withoutSubmodules, func(Event) {}); err != nil {
		t.Fatalf("prepare without submodules: %v", err)
	}
	plainNativePath := filepath.Join(withoutSubmodules, "src", "vendor", "native", "native.c")
	if _, err := os.Stat(plainNativePath); !os.IsNotExist(err) {
		t.Fatalf("ordinary source preparation included submodule content: %v", err)
	}
}

func TestEmbeddedNativeBriefSeesPreparedSubmodule(t *testing.T) {
	_, err := exec.LookPath("brief")
	if err != nil {
		t.Skip("brief not installed")
	}
	url := newEmbeddedNativeOrigin(t)
	w := &Worker{DataDir: t.TempDir()}
	workRoot := t.TempDir()
	if _, err := w.prepareRepoSrcWithOptions(
		context.Background(), url, "", workRoot, true, func(Event) {},
	); err != nil {
		t.Fatal(err)
	}
	if err := stageEmbeddedNativeComponents(context.Background(), workRoot, ""); err != nil {
		t.Fatal(err)
	}

	script, err := filepath.Abs("../../skills/embedded-native/scripts/scan.sh")
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(workRoot, "report.json")
	cmd := exec.Command("bash", script, filepath.Join(workRoot, "src"), reportPath)
	cmd.Dir = workRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("embedded-native scan: %v\n%s", err, out)
	}
	reportJSON, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := ValidateReportSchema(loadBundledSchema(t, "../../skills/embedded-native/schema.json"), string(reportJSON)); got != "" {
		t.Fatalf("schema: %s\n%s", got, reportJSON)
	}
	type briefReport struct {
		Languages []struct {
			Name string `json:"name"`
		} `json:"languages"`
		Tools map[string][]struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	var report struct {
		SchemaVersion int                       `json:"schema_version"`
		Root          briefReport               `json:"root"`
		Components    []embeddedNativeComponent `json:"components"`
		Submodules    []briefReport             `json:"submodules"`
	}
	if err := json.Unmarshal(reportJSON, &report); err != nil {
		t.Fatalf("decode embedded-native report: %v\n%s", err, reportJSON)
	}
	if report.SchemaVersion != 1 || len(report.Submodules) != 1 {
		t.Fatalf("report version = %d, submodules = %d", report.SchemaVersion, len(report.Submodules))
	}
	if len(report.Components) != 1 {
		t.Fatalf("components = %+v, want one", report.Components)
	}
	component := report.Components[0]
	wantCommit := testGit(t, filepath.Join(workRoot, "src", "vendor", "native"), "rev-parse", "HEAD")
	if component.Path != "vendor/native" || component.URL != "https://github.com/example/native.git" ||
		component.Commit != wantCommit || component.PURL != "pkg:github/example/native@"+wantCommit ||
		!component.Initialized || component.Status != "initialized" || component.Error != "" {
		t.Errorf("component = %+v", component)
	}
	for name, languages := range map[string][]struct {
		Name string `json:"name"`
	}{"root": report.Root.Languages, "submodule": report.Submodules[0].Languages} {
		want := map[string]string{"root": "Python", "submodule": "C"}[name]
		found := false
		for _, language := range languages {
			if language.Name == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s Brief languages = %v, missing %s", name, languages, want)
		}
	}
	var foundSubmodules bool
	for _, tool := range report.Root.Tools["dependency_bot"] {
		if tool.Name == "Git Submodules" {
			foundSubmodules = true
		}
	}
	if !foundSubmodules {
		t.Errorf("root Brief dependency_bot tools = %v, missing Git Submodules", report.Root.Tools["dependency_bot"])
	}
}

func TestEmbeddedNativeComponentInScope(t *testing.T) {
	for _, tt := range []struct {
		name          string
		componentPath string
		subPath       string
		want          bool
	}{
		{name: "root", componentPath: "vendor/native", want: true},
		{name: "inside scope", componentPath: "packages/app/vendor/native", subPath: "packages/app", want: true},
		{name: "contains scope", componentPath: "vendor/native", subPath: "vendor/native/src", want: true},
		{name: "sibling", componentPath: "packages/other/vendor/native", subPath: "packages/app", want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := embeddedNativeComponentInScope(tt.componentPath, tt.subPath); got != tt.want {
				t.Errorf("embeddedNativeComponentInScope(%q, %q) = %t, want %t", tt.componentPath, tt.subPath, got, tt.want)
			}
		})
	}
}

func TestEmbeddedNativeBriefFailureWritesErrorReport(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeBrief := filepath.Join(bin, "brief")
	if err := os.WriteFile(fakeBrief, []byte("#!/usr/bin/env bash\necho 'brief failed' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	script, err := filepath.Abs("../../skills/embedded-native/scripts/scan.sh")
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(root, "report.json")
	cmd := exec.Command("bash", script, src, reportPath)
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("embedded-native scan: %v\n%s", err, out)
	}
	reportJSON, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := ValidateReportSchema(loadBundledSchema(t, "../../skills/embedded-native/schema.json"), string(reportJSON)); got != "" {
		t.Fatalf("schema: %s\n%s", got, reportJSON)
	}
	var report struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(reportJSON, &report); err != nil {
		t.Fatal(err)
	}
	if report.Error != "brief root scan failed" {
		t.Errorf("error = %q, want brief root scan failed", report.Error)
	}
	if !strings.Contains(string(out), "brief failed") {
		t.Errorf("stderr = %q, want Brief failure", out)
	}
}

func TestEnsureCommit_noCacheIsNoOp(t *testing.T) {
	w := &Worker{DataDir: t.TempDir()}
	if err := w.EnsureCommit(context.Background(), "https://example.com/x", "deadbeef"); err != nil {
		t.Errorf("EnsureCommit with no cache: %v", err)
	}
}

func TestEnsureCommit_reachableCommitIsNoOp(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dataDir := t.TempDir()
	url := "https://example.com/repo"
	cacheSrc := filepath.Join(RepoCacheRoot(dataDir, url), "src")
	if err := os.MkdirAll(cacheSrc, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", cacheSrc}, args...)...)
		cmd.Env = testutil.GitEnv()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "--quiet", "-b", "main")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(cacheSrc, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "f")
	run("commit", "--quiet", "-m", "first")
	head := run("rev-parse", "HEAD")

	w := &Worker{DataDir: dataDir}
	if err := w.EnsureCommit(context.Background(), url, head); err != nil {
		t.Errorf("EnsureCommit with reachable commit: %v", err)
	}
	if err := w.EnsureCommit(context.Background(), url, strings.ToUpper(head)); err != nil {
		t.Errorf("EnsureCommit with uppercase commit: %v", err)
	}
}

func TestEnsureCommit_unreachableNonShallowIsNoOp(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dataDir := t.TempDir()
	url := "https://example.com/repo"
	cacheSrc := filepath.Join(RepoCacheRoot(dataDir, url), "src")
	if err := os.MkdirAll(cacheSrc, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "-C", cacheSrc, "init", "--quiet", "-b", "main")
	cmd.Env = testutil.GitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	w := &Worker{DataDir: dataDir}
	if err := w.EnsureCommit(context.Background(), url, "0000000000000000000000000000000000000000"); err != nil {
		t.Errorf("EnsureCommit on non-shallow without commit should be no-op: %v", err)
	}
}
