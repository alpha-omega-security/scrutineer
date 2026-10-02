package main

import (
	"fmt"
	"io"
	"runtime/debug"
	"strings"

	"scrutineer/internal/worker"
)

// Release builds replace these values with -ldflags -X.
var (
	version            = "dev"
	commit             string
	buildDate          string
	defaultRunnerImage = worker.DefaultRunnerImage
)

type buildMetadata struct {
	Commit     string
	CommitDate string
}

func readBuildMetadata() buildMetadata {
	info, _ := debug.ReadBuildInfo()
	return resolveBuildMetadata(commit, info)
}

func resolveBuildMetadata(injectedCommit string, info *debug.BuildInfo) buildMetadata {
	metadata := buildMetadata{Commit: injectedCommit}
	if info == nil {
		return metadata
	}
	var revision, commitDate string
	var modified bool
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.time":
			commitDate = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if metadata.Commit == "" {
		metadata.Commit = revision
	}
	// VCS details only describe the stamped revision, not a different injected commit.
	if metadata.Commit == revision {
		metadata.CommitDate = commitDate
		if modified && metadata.Commit != "" {
			metadata.Commit += "-dirty"
		}
	}
	return metadata
}

func runVersion(out io.Writer) error {
	build := readBuildMetadata()
	_, err := fmt.Fprintf(out, "scrutineer %s\ncommit: %s\nbuilt: %s\nrunner: %s\n",
		valueOrUnknown(version), valueOrUnknown(build.Commit), valueOrUnknown(buildDate), defaultRunnerImage)
	return err
}

func valueOrUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}
