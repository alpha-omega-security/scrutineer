package worker

// SELinux bind-mount relabeling. On hosts with SELinux enabled -- the default on
// Fedora, RHEL, CentOS Stream, Rocky and Alma, which is where rootless podman
// most often runs -- the scan container runs as the confined type `container_t`
// while bind-mounted host paths keep their own labels (user_home_t, var_lib_t,
// ...). The base container-selinux policy denies container_t access to those
// types, so without intervention the runner cannot read the clone at /work or
// /src and cannot write its output: every scan fails with EACCES even though the
// uid/gid (DAC) ownership is correct. This file owns the engine-agnostic
// detection and the decision to append the ":z" relabel option that fixes it.
//
// This is orthogonal to --userns=keep-id (runtime.go): keep-id fixes DAC
// ownership of bind-mount writes; relabeling fixes SELinux/MAC access. A
// rootless-podman scan on an enforcing host needs both.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SELinux relabel modes accepted by the --selinux switch / `selinux:` config
// key. They gate whether the runner appends the ":z" relabel option to its host
// bind mounts.
const (
	// SELinuxAuto relabels only when the host has SELinux enabled. It is the
	// default and the empty-string fallback, so non-SELinux hosts are wholly
	// unaffected (no relabel option, no smoke test, byte-for-byte the previous
	// behaviour).
	SELinuxAuto = "auto"
	// SELinuxOn forces relabeling regardless of detection -- an escape hatch for
	// a host where selinuxfs is not visible to scrutineer but the engine still
	// labels containers. Harmless on a non-SELinux host: the engine ignores the
	// relabel request.
	SELinuxOn = "on"
	// SELinuxOff disables relabeling entirely -- an escape hatch for operators
	// who pre-label the data dir themselves (semanage/chcon to container_file_t)
	// or run the engine with `--security-opt label=disable`.
	SELinuxOff = "off"
)

// selinuxfsEnforcePath is the kernel's SELinux status node. selinuxfs is mounted
// at /sys/fs/selinux only when SELinux is enabled, so this file exists exactly in
// that case -- it is the engine-agnostic signal scrutineer uses instead of
// parsing `docker info` / `podman info`. scrutineer execs the runtime locally and
// relabels local paths, so the host's own state is authoritative for either
// engine.
const selinuxfsEnforcePath = "/sys/fs/selinux/enforce"

// selinuxProbeFileMode is the mode for the throwaway file the SELinux smoke test
// seeds for the container to read. World-readable is fine: it lives in a private
// temp dir that is removed when the check returns.
const selinuxProbeFileMode os.FileMode = 0o644

// HostSELinuxEnabled reports whether the host has SELinux enabled (enforcing or
// permissive). Best-effort filesystem probe, no libselinux dependency.
// Permissive counts as enabled: relabeling is harmless there and keeps behaviour
// stable if the host is later switched to enforcing.
func HostSELinuxEnabled() bool {
	_, err := os.Stat(selinuxfsEnforcePath)
	return err == nil
}

// SELinux host modes reported by HostSELinuxState (distinct from the
// auto/on/off relabel switch above).
const (
	SELinuxStateEnforcing  = "enforcing"
	SELinuxStatePermissive = "permissive"
	SELinuxStateDisabled   = "disabled"
)

// HostSELinuxState reports the host's SELinux mode for the startup diagnostic,
// reading the selinuxfs status node: "enforcing" (enforce==1) or "permissive"
// (enforce==0) when SELinux is enabled, "disabled" when selinuxfs is not mounted
// (the node is absent or unreadable). The human-readable companion to
// HostSELinuxEnabled, which it agrees with (disabled iff not enabled).
func HostSELinuxState() string {
	b, err := os.ReadFile(selinuxfsEnforcePath)
	if err != nil {
		return SELinuxStateDisabled
	}
	if strings.TrimSpace(string(b)) == "1" {
		return SELinuxStateEnforcing
	}
	return SELinuxStatePermissive
}

// ResolveSELinuxRelabel turns the --selinux switch into the concrete decision of
// whether to add the ":z" relabel option to runner bind mounts. See the mode
// constants for each value; "auto" (and the empty string) consult
// HostSELinuxEnabled so the fix turns itself on exactly on the hosts that need
// it and stays invisible everywhere else.
func ResolveSELinuxRelabel(mode string) bool {
	switch mode {
	case SELinuxOn:
		return true
	case SELinuxOff:
		return false
	default: // SELinuxAuto, ""
		return HostSELinuxEnabled()
	}
}

// bindMount builds a `-v` value "src:dst[:opts]" for a runner bind mount,
// appending the SELinux relabel option "z" when relabel is true. opts carries
// any non-SELinux options (e.g. "ro"); "z" joins that comma-separated group, so
// an SELinux host gets "src:dst:ro,z" while every other host gets the spec
// unchanged.
//
// Why ":z" (shared) and not ":Z" (private):
//
//   - Host read-back. After a scan the scrutineer host process reads the output
//     report back out of /work (readCappedReport). ":z" relabels to the shared
//     type container_file_t with no MCS category, so the host can still read it;
//     ":Z" stamps a private per-container category that a host process in a
//     confined SELinux domain could be denied -- locking scrutineer out of the
//     very report it asked for.
//   - Overlapping mounts. /work and /src point at the same clone tree; one
//     shared label keeps the two relabels consistent instead of churning a
//     private category between them.
//   - Isolation model. scrutineer separates scans with per-scan work roots and,
//     under --hardened, per-scan --internal networks -- not SELinux MCS. ":Z"'s
//     extra container-to-container separation is not load-bearing here. The cost
//     ":z" accepts is that any container_t on the host could read a scan's
//     ephemeral workspace; that is outside the threat model (the concern is a
//     hostile repo escaping the sandbox, not a sibling local container reading a
//     throwaway clone).
//
// Operators who want the stricter per-scan MCS isolation can pre-label their data
// dir and run with --selinux=off; ":Z" is intentionally not exposed as a switch
// so the host read-back guarantee stays simple.
func bindMount(src, dst string, relabel bool, opts ...string) string {
	if relabel {
		opts = append(opts, "z")
	}
	spec := src + ":" + dst
	if len(opts) > 0 {
		spec += ":" + strings.Join(opts, ",")
	}
	return spec
}

// VerifySELinuxMount smoke-tests a relabeled bind mount the way real scans use
// one, so an SELinux denial fails once at startup with an actionable message
// instead of silently breaking every scan's file passing. It runs only when
// relabel is true -- the case where SELinux access is in play. When relabeling is
// disabled it is a no-op: the operator has taken ownership of labeling, and a
// fresh unlabeled temp dir would be a misleading probe (it would fail even where
// the operator's pre-labeled data dir works). Like VerifyKeepID it is also
// skipped when the runner image is not present locally -- the first scan pulls it
// and would surface the same issue then -- so startup never eagerly pulls.
//
// The probe seeds a host-written file the container must READ (the clone path)
// and has the container WRITE a file the host must READ BACK (the output path),
// mirroring both directions a scan needs, and reuses --user plus (rootless)
// --userns=keep-id so it exercises the same uid mapping as a real run.
func VerifySELinuxMount(ctx context.Context, rt ContainerRuntime, image string, relabel bool) error {
	if !relabel {
		return nil
	}
	if image == "" || !imageExistsLocally(ctx, rt, image) {
		return nil
	}
	dir, err := os.MkdirTemp("", "scrutineer-selinux-")
	if err != nil {
		return fmt.Errorf("selinux mount smoke test: temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.WriteFile(filepath.Join(dir, "in"), []byte("ok\n"), selinuxProbeFileMode); err != nil {
		return fmt.Errorf("selinux mount smoke test: seed file: %w", err)
	}

	args := []string{
		"run", "--rm", "--pull", "never",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
	}
	if rt.needsKeepID() {
		args = append(args, "--userns=keep-id")
	}
	args = append(args,
		"-v", bindMount(dir, "/probe", true),
		"--entrypoint", "sh", "--", image, "-c",
		"cat /probe/in >/dev/null && printf out > /probe/out")

	if out, err := exec.CommandContext(ctx, rt.bin(), args...).CombinedOutput(); err != nil {
		return fmt.Errorf("relabeled bind-mount smoke test failed: the container could not "+
			"access a host dir mounted with ':z' on this SELinux host (ensure container-selinux "+
			"is installed and the runner can relabel, or set --selinux=off if you pre-label paths "+
			"yourself): %w: %s", err, strings.TrimSpace(string(out)))
	}
	// The container wrote /probe/out; confirm the host can read it back. ":z"
	// keeps it host-readable -- this guards the read-back path readCappedReport
	// depends on, and would catch a regression to a private (":Z") relabel.
	if _, err := os.ReadFile(filepath.Join(dir, "out")); err != nil {
		return fmt.Errorf("selinux mount smoke test: host could not read back the container's "+
			"output through a ':z' mount: %w", err)
	}
	return nil
}
