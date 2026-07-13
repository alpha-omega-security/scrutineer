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
// page, e.g. "docker 24.0.7", "podman 4.9.4", or "Apple container 1.0.0", or ""
// when the runtime is unavailable or the command fails. docker exposes the
// daemon version at {{.Server.Version}}; podman's version schema has no
// .Server, so the engine version lives at {{.Version}}; Apple's container CLI
// reports its version from `container --version`. The caller supplies a context
// so the settings page can bound how long it waits.
func RuntimeServerVersion(ctx context.Context, rt ContainerRuntime) string {
	if rt.Bin == runtimeApple {
		out, err := exec.CommandContext(ctx, rt.bin(), "--version").Output()
		if err != nil {
			return ""
		}
		v := firstDottedVersion(string(out))
		if v == "" {
			return ""
		}
		// Display the product identity ("Apple container"), not just the bare
		// executable, so the settings row is traceable to --runtime apple.
		return "Apple " + rt.bin() + " " + v
	}
	format := "{{.Server.Version}}"
	if rt.Bin == runtimePodman {
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

// RunnerImageRevision returns the git commit the runner image was built from,
// read from the org.opencontainers.image.revision OCI label that
// docker/metadata-action bakes in during the runner-image workflow. This is far
// more useful on the settings page than the image's ":latest" tag, which never
// changes. Returns "" when the image isn't present locally, carries no revision
// label (e.g. a locally built --runner-image), or inspect fails -- the settings
// page then shows "unavailable" rather than a misleading value. The caller
// supplies a context to bound a hung daemon.
func RunnerImageRevision(ctx context.Context, rt ContainerRuntime, image string) string {
	if image == "" {
		return ""
	}
	const format = `{{index .Config.Labels "org.opencontainers.image.revision"}}`
	out, err := exec.CommandContext(ctx, rt.bin(), "image", "inspect", "--format", format, "--", image).Output()
	if err != nil {
		return ""
	}
	rev := strings.TrimSpace(string(out))
	// A missing label renders as the literal "<no value>"; treat it as absent.
	if rev == "" || rev == "<no value>" {
		return ""
	}
	return rev
}

// RunnerToolVersions holds the versions of the analysis tools baked into the
// runner image. Any field is "" when its tool could not be queried. Harness
// is the version of whichever agent CLI -backend selected; the caller passes
// that binary's name to QueryRunnerToolVersions so adding a harness needs no
// change here.
type RunnerToolVersions struct {
	Zizmor  string
	Semgrep string
	Harness string
}

// queryToolsScript builds the sh script that prints each tool's version as a
// key=value line so the output parses unambiguously regardless of each
// tool's own format. stderr is dropped so update notices and warnings don't
// pollute the value. harnessBin is the active backend's binary name (e.g.
// "claude", "codex"); it is a code-supplied constant from Harness.Binary(),
// never user input, so plain interpolation is fine.
func queryToolsScript(harnessBin string) string {
	return `echo "zizmor=$(zizmor --version 2>/dev/null)"; ` +
		`echo "semgrep=$(semgrep --version 2>/dev/null)"; ` +
		`echo "harness=$(` + harnessBin + ` --version 2>/dev/null)"`
}

// QueryRunnerToolVersions starts one short-lived container off the runner
// image and reads back the versions of the scanner tools it ships. The
// deployed image is the source of truth (it can drift from the Dockerfile's
// pinned ARGs), so we interrogate the image rather than parse the Dockerfile.
//
// --pull never means a missing image fails fast instead of triggering a slow
// registry pull, so the settings page never blocks on a download. Apple's
// container CLI lacks a pull-policy flag, so that path checks the local image
// cache first and only runs the image when it is already present. The caller
// must pass a context with a timeout to bound a hung daemon. Returns a zero
// value (all fields "") for an empty image name or any failure.
func QueryRunnerToolVersions(ctx context.Context, rt ContainerRuntime, image, harnessBin string) RunnerToolVersions {
	if image == "" {
		return RunnerToolVersions{}
	}
	args := rt.runArgs("--rm")
	if rt.supportsPullNever() {
		args = append(args, "--pull", "never")
	} else if !imageExistsLocally(ctx, rt, image) {
		return RunnerToolVersions{}
	}
	args = append(args, "--entrypoint", "sh", "--", image, "-c", queryToolsScript(harnessBin))
	out, err := exec.CommandContext(ctx, rt.bin(), args...).Output()
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
		case "harness":
			v.Harness = val
		}
	}
	return v
}
