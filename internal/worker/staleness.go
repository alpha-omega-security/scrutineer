package worker

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// RunnerStaleThresholdDays is how old the locally pulled runner image must be,
// with a newer build available in the registry, before scrutineer nags about
// it. The runner image's :latest tag moves on every merge to scrutineer's main
// branch, so a digest mismatch alone means a newer build exists; the age gate
// keeps the nag from firing on a one- or two-day-old image when the mismatch is
// just normal churn. Only an image that is both behind and at least this old is
// worth surfacing.
const RunnerStaleThresholdDays = 7

// hoursPerDay converts the image's age from hours to whole days.
const hoursPerDay = 24

// RunnerStalenessTimeout bounds the registry round-trip the boot check makes so
// a slow or unreachable registry never delays anything. The check runs in its
// own goroutine and fails soft to silence on timeout, so this only caps how
// long that background goroutine lingers.
const RunnerStalenessTimeout = 15 * time.Second

// RunnerImageStatus is the result of the boot-time runner-image staleness
// check, surfaced in the boot log and as a banner on the Settings page. The
// zero value (Stale=false) renders nothing, which is also the fail-soft
// outcome: when the check can't reach a verdict it reports "not stale" rather
// than alarming the operator.
type RunnerImageStatus struct {
	Image       string
	AgeDays     int    // age of the local image, days since it was built
	Stale       bool   // a newer image exists AND AgeDays >= RunnerStaleThresholdDays
	PullCommand string // e.g. "docker pull ghcr.io/...": the suggested update
}

// RunnerImageStaleness compares the locally pulled runner image against the
// :latest manifest in the registry and reports whether it is stale: a newer
// digest exists in the registry AND the local image is at least
// RunnerStaleThresholdDays old.
//
// It is best-effort and fails soft. The second return value is false -- and the
// caller stays silent -- whenever the comparison can't be made: no container
// runtime in use, a local-only image with no registry digest (e.g. a
// locally-built --runner-image), an image that has never been pulled, a missing
// inspect tool, or an unreachable registry. None of these are errors worth
// alarming the operator about; they just mean "can't tell," which is treated as
// "not stale." The caller must pass a context with a timeout to bound the
// registry round-trip.
func RunnerImageStaleness(ctx context.Context, rt ContainerRuntime, image string) (RunnerImageStatus, bool) {
	if image == "" {
		return RunnerImageStatus{}, false
	}
	localDigest, created, ok := localRunnerImage(ctx, rt, image)
	if !ok || localDigest == "" || created.IsZero() {
		return RunnerImageStatus{}, false
	}
	remoteDigest, ok := remoteRunnerDigest(ctx, rt, image)
	if !ok || remoteDigest == "" {
		return RunnerImageStatus{}, false
	}
	return evalRunnerStaleness(image, localDigest, remoteDigest, created, time.Now(), rt.bin()), true
}

// evalRunnerStaleness is the pure staleness decision, split out so it can be
// tested without a registry: the image is stale when the registry digest has
// moved away from the local one AND the local image is at least
// RunnerStaleThresholdDays old. now is passed in so tests can pin "today."
func evalRunnerStaleness(image, localDigest, remoteDigest string, created, now time.Time, bin string) RunnerImageStatus {
	status := RunnerImageStatus{
		Image:       image,
		AgeDays:     int(now.Sub(created).Hours()) / hoursPerDay,
		PullCommand: bin + " pull " + image,
	}
	status.Stale = localDigest != remoteDigest && status.AgeDays >= RunnerStaleThresholdDays
	return status
}

// localRunnerImage reads the locally stored runner image's registry digest and
// build timestamp via `image inspect`. The RepoDigest is the manifest the image
// was pulled by -- the multi-arch index digest when pulled by tag, which is the
// same thing remoteRunnerDigest fetches -- and created comes from the
// org.opencontainers.image.created OCI label baked in at build time. Returns
// ok=false when the image isn't present locally or inspect fails. Returns an
// empty digest for a locally built image that was never pushed (no RepoDigests)
// and a zero time for an image without the created label; the caller treats
// either as "can't tell."
func localRunnerImage(ctx context.Context, rt ContainerRuntime, image string) (digest string, created time.Time, ok bool) {
	// Two newline-separated lines keep parsing trivial and avoid a separator
	// colliding with a digest or timestamp that contains one. A missing
	// RepoDigests yields an empty first line; a missing label yields "<no value>"
	// on the second, which time.Parse rejects into a zero time.
	const format = `{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}` + "\n" +
		`{{index .Config.Labels "org.opencontainers.image.created"}}`
	out, err := exec.CommandContext(ctx, rt.bin(), "image", "inspect", "--format", format, "--", image).Output()
	if err != nil {
		return "", time.Time{}, false
	}
	digest, created = parseImageInspect(string(out))
	return digest, created, true
}

// parseImageInspect parses the two-line `image inspect` output (digest line,
// then created line) localRunnerImage's format template produces. A missing
// RepoDigest leaves an empty first line and an empty digest; a missing or
// unparseable created label leaves a zero time. Split out for testing.
func parseImageInspect(out string) (digest string, created time.Time) {
	digestLine, createdLine, _ := strings.Cut(strings.TrimRight(out, "\r\n"), "\n")
	// RepoDigests entries look like "repo@sha256:..."; keep just the digest.
	if _, d, found := strings.Cut(strings.TrimSpace(digestLine), "@"); found {
		digest = d
	}
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(createdLine)); err == nil {
		created = t
	}
	return digest, created
}

// remoteRunnerDigest fetches the registry digest of the image's current tag
// (typically :latest) without pulling layers, as a "sha256:<hex>" string
// directly comparable to the RepoDigest localRunnerImage reads. It delegates to
// resolveBaseDigest -- the same registry-manifest hash the profile cache keys on
// -- and prepends the "sha256:" prefix the RepoDigest carries. Keeping the
// single registry-digest path here means #513 (and anything else that extends
// runtime coverage) only has to touch resolveBaseDigest. Best-effort: returns
// false (fail soft) when the tool is missing or the registry is unreachable.
func remoteRunnerDigest(ctx context.Context, rt ContainerRuntime, image string) (string, bool) {
	digest := resolveBaseDigest(ctx, rt, image)
	if digest == "" {
		return "", false
	}
	return "sha256:" + digest, true
}
