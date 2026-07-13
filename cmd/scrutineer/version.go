package main

import (
	"fmt"
	"io"
	"strings"

	"scrutineer/internal/worker"
)

// These values are replaced in release builds with -ldflags -X. Development
// builds retain useful defaults and still pick up their commit from Go's VCS
// build information through buildCommit.
var (
	version            = "dev"
	buildDate          string
	defaultRunnerImage = worker.DefaultRunnerImage
)

func runVersion(out io.Writer) error {
	_, err := fmt.Fprintf(out, "scrutineer %s\ncommit: %s\nbuilt: %s\nrunner: %s\n",
		valueOrUnknown(version), valueOrUnknown(buildCommit()), valueOrUnknown(buildDate), defaultRunnerImage)
	return err
}

func valueOrUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}
