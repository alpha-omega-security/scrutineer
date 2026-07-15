package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

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
