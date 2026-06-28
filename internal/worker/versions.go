package worker

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
)

// RunnerImageName returns the container image the given runner uses for scans,
// or "" when the runner is not container-backed (e.g. LocalClaude under
// --no-container), where there is no fixed image to interrogate.
func RunnerImageName(r SkillRunner) string {
	if d, ok := r.(ContainerRunner); ok {
		return d.image()
	}
	return ""
}

// RuntimeOf returns the container runtime the given runner uses, or the docker
// zero value when the runner is not container-backed (LocalClaude under
// --no-container). The web settings page passes it to the version probes so a
// podman host queries podman rather than a non-existent docker daemon.
func RuntimeOf(r SkillRunner) ContainerRuntime {
	if d, ok := r.(ContainerRunner); ok {
		return d.Runtime
	}
	return ContainerRuntime{}
}

// RuntimeServerVersion returns a human-readable engine version for the settings
// page, e.g. "docker 24.0.7" or "podman 4.9.4", or "" when the runtime is
// unavailable or the command fails. docker exposes the daemon version at
// {{.Server.Version}}; podman's version schema has no .Server, so the engine
// version lives at {{.Version}}. The caller supplies a context so the settings
// page can bound how long it waits.
func RuntimeServerVersion(ctx context.Context, rt ContainerRuntime) string {
	format := "{{.Server.Version}}"
	if rt.Bin == "podman" {
		format = "{{.Version}}"
	}
	out, err := exec.CommandContext(ctx, rt.bin(), "version", "--format", format).Output()
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return ""
	}
	return rt.bin() + " " + v
}

// RunnerToolVersions holds the versions of the analysis tools baked into the
// runner image. Any field is "" when its tool could not be queried.
type RunnerToolVersions struct {
	Zizmor  string
	Semgrep string
	Claude  string
}

// queryToolsScript prints each tool's version as a key=value line so the
// output parses unambiguously regardless of each tool's own format. stderr
// is dropped so update notices and warnings don't pollute the value.
const queryToolsScript = `echo "zizmor=$(zizmor --version 2>/dev/null)"; ` +
	`echo "semgrep=$(semgrep --version 2>/dev/null)"; ` +
	`echo "claude=$(claude --version 2>/dev/null)"`

// QueryRunnerToolVersions starts one short-lived container off the runner
// image and reads back the versions of the scanner tools it ships. The
// deployed image is the source of truth (it can drift from the Dockerfile's
// pinned ARGs), so we interrogate the image rather than parse the Dockerfile.
//
// --pull never means a missing image fails fast instead of triggering a slow
// registry pull, so the settings page never blocks on a download. The caller
// must pass a context with a timeout to bound a hung daemon. Returns a zero
// value (all fields "") for an empty image name or any failure.
func QueryRunnerToolVersions(ctx context.Context, rt ContainerRuntime, image string) RunnerToolVersions {
	if image == "" {
		return RunnerToolVersions{}
	}
	out, err := exec.CommandContext(ctx, rt.bin(), "run", "--rm",
		"--pull", "never", "--entrypoint", "sh", "--", image, "-c", queryToolsScript).Output()
	if err != nil {
		return RunnerToolVersions{}
	}
	return parseToolVersions(string(out))
}

// versionRe matches the first dotted-numeric version token in a string, so
// "zizmor 1.26.1" and "2.1.123 (Claude Code)" both reduce to the bare number.
var versionRe = regexp.MustCompile(`\d+\.\d+[\w.\-+]*`)

func parseToolVersions(out string) RunnerToolVersions {
	var v RunnerToolVersions
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		val = versionRe.FindString(val)
		switch key {
		case "zizmor":
			v.Zizmor = val
		case "semgrep":
			v.Semgrep = val
		case "claude":
			v.Claude = val
		}
	}
	return v
}
