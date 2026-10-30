package ossscanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSameRepo(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"https://github.com/curl/curl", "https://github.com/curl/curl", true},
		{"https://github.com/curl/curl#main", "https://github.com/curl/curl", true},
		{"https://github.com/curl/curl.git", "https://github.com/curl/curl", true},
		{"https://github.com/curl/curl/", "https://github.com/curl/curl", true},
		{"https://GitHub.com/Curl/CURL", "https://github.com/curl/curl", true},
		{"http://github.com/curl/curl", "https://github.com/curl/curl", true},
		{"https://github.com/curl/curl", "https://github.com/curl/other", false},
		{"https://github.com/curl/curl", "https://gitlab.com/curl/curl", false},
		{"", "", false},
		{"https://github.com/curl/curl", "", false},
		{"not a url", "not a url", false},
	}
	for _, tt := range tests {
		if got := SameRepo(tt.a, tt.b); got != tt.want {
			t.Errorf("SameRepo(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

const repoURL = "https://github.com/example/project"

func registryWith(t *testing.T, yamlBody string) string {
	t.Helper()
	reg := t.TempDir()
	write(t, reg, "projects/proj/project.yaml", yamlBody)
	return reg
}

func TestResolveRegistryFilesWin(t *testing.T) {
	reg := registryWith(t, "repo: "+repoURL+"#main\ndockerfile: ci/Dockerfile\nthreat_model: docs/tm.md\nunknown: x\n")
	write(t, reg, "projects/proj/threat_model.md", "registry tm")
	write(t, reg, "projects/proj/Dockerfile", "FROM scratch")
	src := t.TempDir()
	write(t, src, "ci/Dockerfile", "FROM other")
	write(t, src, "docs/tm.md", "repo tm")

	e, err := Resolve(reg, src, repoURL+".git")
	if err != nil || e == nil {
		t.Fatalf("Resolve = %v, %v", e, err)
	}
	if !e.Registry || e.Project != "proj" {
		t.Fatalf("enrollment = %+v", e)
	}
	if e.ThreatModel.Origin != OriginRegistry || e.ThreatModel.Path != "projects/proj/threat_model.md" {
		t.Fatalf("threat model = %+v", e.ThreatModel)
	}
	if e.Dockerfile.Origin != OriginRegistry {
		t.Fatalf("dockerfile = %+v", e.Dockerfile)
	}
	data, err := ReadSource(reg, src, e.ThreatModel)
	if err != nil || string(data) != "registry tm" {
		t.Fatalf("ReadSource = %q, %v", data, err)
	}
}

func TestResolveRegistryFallsBackToKeyPaths(t *testing.T) {
	reg := registryWith(t, "repo: "+repoURL+"\ndisabled: true\ndockerfile: ./ci/Dockerfile\nthreat_model: docs/tm.md\n")
	src := t.TempDir()
	write(t, src, "ci/Dockerfile", "FROM other")
	write(t, src, "docs/tm.md", "repo tm")

	e, err := Resolve(reg, src, repoURL)
	if err != nil || e == nil {
		t.Fatalf("Resolve = %v, %v", e, err)
	}
	if !e.Disabled {
		t.Error("disabled not carried")
	}
	if e.Dockerfile == nil || e.Dockerfile.Origin != OriginRepository || e.Dockerfile.Path != "ci/Dockerfile" {
		t.Fatalf("dockerfile = %+v", e.Dockerfile)
	}
	if e.ThreatModel == nil || e.ThreatModel.Path != "docs/tm.md" {
		t.Fatalf("threat model = %+v", e.ThreatModel)
	}
}

func TestResolveUnenrolledFallback(t *testing.T) {
	reg := registryWith(t, "repo: https://github.com/someone/else\n")
	src := t.TempDir()
	write(t, src, ".oss-scanner/threat_model.md", "tm")

	e, err := Resolve(reg, src, repoURL)
	if err != nil || e == nil {
		t.Fatalf("Resolve = %v, %v", e, err)
	}
	if e.Registry || e.Project != "" || e.Dockerfile != nil {
		t.Fatalf("enrollment = %+v", e)
	}
	if e.ThreatModel == nil || e.ThreatModel.Path != ".oss-scanner/threat_model.md" {
		t.Fatalf("threat model = %+v", e.ThreatModel)
	}
}

func TestResolveRegistryRootEmptyStillFallsBack(t *testing.T) {
	src := t.TempDir()
	write(t, src, ".oss-scanner/Dockerfile", "FROM scratch")
	e, err := Resolve("", src, repoURL)
	if err != nil || e == nil || e.Dockerfile == nil || e.Registry {
		t.Fatalf("Resolve = %+v, %v", e, err)
	}
}

func TestResolveNoMatch(t *testing.T) {
	reg := registryWith(t, "repo: https://github.com/someone/else\n")
	e, err := Resolve(reg, t.TempDir(), repoURL)
	if err != nil || e != nil {
		t.Fatalf("Resolve = %+v, %v", e, err)
	}
}

func TestResolveSkipsMalformedProject(t *testing.T) {
	reg := t.TempDir()
	write(t, reg, "projects/aaa/project.yaml", "repo: [unterminated\n")
	write(t, reg, "projects/bbb/project.yaml", "repo: "+repoURL+"\n")
	write(t, reg, "projects/ccc/project.yaml", "repo: "+repoURL+"\n")
	e, err := Resolve(reg, t.TempDir(), repoURL)
	if err != nil || e == nil || e.Project != "bbb" {
		t.Fatalf("Resolve = %+v, %v", e, err)
	}
}

func TestResolveIgnoresTraversalKeys(t *testing.T) {
	for _, key := range []string{"../x", "/etc/passwd", "a/../../x", `a\b`, "."} {
		parent := t.TempDir()
		src := filepath.Join(parent, "src")
		write(t, parent, "x", "outside")
		write(t, src, "keep", "")
		reg := registryWith(t, "repo: "+repoURL+"\ndockerfile: '"+key+"'\nthreat_model: '"+key+"'\n")
		e, err := Resolve(reg, src, repoURL)
		if err != nil || e == nil {
			t.Fatalf("%q: Resolve = %+v, %v", key, e, err)
		}
		if e.Dockerfile != nil || e.ThreatModel != nil {
			t.Errorf("%q accepted: %+v", key, e)
		}
	}
}

func TestSymlinkedThreatModelRejected(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, ".oss-scanner"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(src, ".oss-scanner/threat_model.md")); err != nil {
		t.Skip("symlinks unavailable")
	}
	e, err := Resolve("", src, repoURL)
	if err != nil || e != nil {
		t.Fatalf("Resolve = %+v, %v", e, err)
	}
	s := &Source{Origin: OriginRepository, Path: ".oss-scanner/threat_model.md"}
	if _, err := ReadSource("", src, s); err == nil {
		t.Fatal("symlink read accepted")
	}
}

func TestReadSourceRejectsOversize(t *testing.T) {
	src := t.TempDir()
	write(t, src, ".oss-scanner/threat_model.md", strings.Repeat("a", MaxFileBytes+1))
	s := &Source{Origin: OriginRepository, Path: ".oss-scanner/threat_model.md"}
	if _, err := ReadSource("", src, s); err == nil {
		t.Fatal("oversize file accepted")
	}
}
