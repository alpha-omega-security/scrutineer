package main

import (
	"bytes"
	"flag"
	"runtime/debug"
	"strings"
	"testing"
)

func TestResolveBuildMetadata(t *testing.T) {
	const revision = "0123456789abcdef0123456789abcdef01234567"
	const commitDate = "2026-09-30T08:59:54Z"
	clean := &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: revision},
		{Key: "vcs.time", Value: commitDate},
		{Key: "vcs.modified", Value: "false"},
	}}
	dirty := &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs.modified", Value: "true"},
		{Key: "vcs.time", Value: commitDate},
		{Key: "vcs.revision", Value: revision},
	}}
	for _, tt := range []struct {
		name     string
		injected string
		info     *debug.BuildInfo
		want     buildMetadata
	}{
		{name: "no build info"},
		{name: "no VCS stamp", info: &debug.BuildInfo{}},
		{name: "container", injected: revision, want: buildMetadata{Commit: revision}},
		{name: "clean checkout", info: clean, want: buildMetadata{Commit: revision, CommitDate: commitDate}},
		{name: "dirty checkout", info: dirty, want: buildMetadata{Commit: revision + "-dirty", CommitDate: commitDate}},
		{name: "matching injected commit", injected: revision, info: dirty, want: buildMetadata{Commit: revision + "-dirty", CommitDate: commitDate}},
		{name: "injected commit wins", injected: "other-revision", info: dirty, want: buildMetadata{Commit: "other-revision"}},
		{name: "dirty without revision", info: &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.modified", Value: "true"}}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveBuildMetadata(tt.injected, tt.info); got != tt.want {
				t.Fatalf("build metadata = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDispatchVersion(t *testing.T) {
	oldVersion, oldCommit, oldBuildDate, oldRunner := version, commit, buildDate, defaultRunnerImage
	version = "2026.07.12.1"
	commit = "0123456789abcdef"
	buildDate = "2026-07-11T20:00:00Z"
	defaultRunnerImage = "ghcr.io/example/runner@sha256:abc"
	t.Cleanup(func() {
		version, commit, buildDate, defaultRunnerImage = oldVersion, oldCommit, oldBuildDate, oldRunner
	})

	for _, arg := range []string{"version", "--version", "-version"} {
		t.Run(arg, func(t *testing.T) {
			var out bytes.Buffer
			handled, err := dispatch([]string{arg}, &out)
			if err != nil {
				t.Fatal(err)
			}
			if !handled {
				t.Fatalf("%s was not handled", arg)
			}
			for _, want := range []string{
				"scrutineer 2026.07.12.1",
				"commit: 0123456789abcdef",
				"built: 2026-07-11T20:00:00Z",
				"runner: ghcr.io/example/runner@sha256:abc",
			} {
				if !strings.Contains(out.String(), want) {
					t.Errorf("version output %q missing %q", out.String(), want)
				}
			}
		})
	}
}

func TestValueOrUnknown(t *testing.T) {
	if got := valueOrUnknown(""); got != "unknown" {
		t.Fatalf("empty value = %q, want unknown", got)
	}
	if got := valueOrUnknown("value"); got != "value" {
		t.Fatalf("non-empty value = %q, want value", got)
	}
}

func TestRegisterFlagsUsesBuildDefaultRunnerImage(t *testing.T) {
	oldRunner := defaultRunnerImage
	defaultRunnerImage = "ghcr.io/example/runner@sha256:abc"
	t.Cleanup(func() { defaultRunnerImage = oldRunner })

	f := &flags{}
	fset := flag.NewFlagSet("test", flag.ContinueOnError)
	registerFlags(fset, f)
	if err := fset.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if f.runnerImage != defaultRunnerImage {
		t.Fatalf("runner image default = %q, want release-injected %q", f.runnerImage, defaultRunnerImage)
	}
}
