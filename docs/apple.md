# Apple `container` runtime (experimental)

Scrutineer can run scans under Apple's
[`container`](https://github.com/apple/container) CLI on macOS 26 (Tahoe),
selected with `--runtime apple` (or `runtime: apple` in the config). Apple
supports `container` only on macOS 26 and will not address issues that cannot be
reproduced there, so older macOS is out of scope for this runtime. It sits
alongside docker and rootless podman as a third engine, and supports both
ordinary scans and `--hardened`. It is still labelled experimental because it is new and Apple's
networking has known rough edges (see below), not because of a capability gap.
This document records where it is at parity with docker/podman and where its
security model differs by design.

## Where the runtime sits

Like docker and podman, the scrutineer process runs on the host (not in a
container) and execs the `container` CLI directly. Each scan is an ephemeral
container with the per-scan workspace mounted at `/work` (plus the resumable
Claude session store at `/harness-state` when configured), run as the invoking
non-root user with `--cap-drop ALL`. The difference is the isolation boundary:
Apple runs every container in its own lightweight VM, so "Each container has the
isolation properties of a full VM"
([technical-overview](https://github.com/apple/container/blob/main/docs/technical-overview.md)).
That is a real boundary, not namespace separation: the host filesystem and SSH
keys are absent inside the VM unless mounted. The one credential that does cross
the boundary is the Anthropic token (`ANTHROPIC_API_KEY` /
`CLAUDE_CODE_OAUTH_TOKEN`), passed in as an env var so the model can
authenticate and readable by in-container code exactly as under docker/podman
(the T1 residual in `threatmodel.md`).

Selection is explicit opt-in. There is no auto-detection: a docker-less Mac left
at the default still reports docker unavailable, by design.

## Parity matrix

| Capability | docker | podman | apple |
| --- | --- | --- | --- |
| Ordinary scans | yes | yes | yes |
| Baseline isolation (`--cap-drop ALL`, non-root `--user`, `/tmp` tmpfs) | yes | yes | yes |
| Egress proxy + allowlist | yes | yes | yes |
| Per-ecosystem profiles | yes | yes | yes |
| SBOM / tool / version probes | yes | yes | yes |
| Runtime detection | yes | yes | yes |
| `--hardened`: read-only rootfs | yes | yes | yes |
| `--hardened`: per-scan `--internal` egress enforcement | yes | yes; rootless verified, may fail closed | yes (verified per scan) |
| `--hardened`: container-to-container isolation | yes | yes | yes (vmnet default) |
| `--hardened`: `--security-opt no-new-privileges` | yes | yes | no (VM boundary substitutes) |
| `--hardened-runtime-only` | yes | yes | n/a (use `--hardened`) |

Per-ecosystem profiles use the same code paths as docker/podman: profile images
build with `container build --pull`, and profile auto-detection runs `brief` in
a `--network none` container. Both were verified on `container` 1.0.0.

## Why no `no-new-privileges`, and why that is fine here

Apple's `container` CLI does not expose `--security-opt` at all, so the
`no-new-privileges` bit cannot be set from the CLI. The bit *is* implemented in
the runtime (`apple/containerization` plumbs it through the OCI spec and the
in-VM `vmexec`), but it is never surfaced, and there is no upstream request to
surface it. The reason is the threat model: on a VM-per-container runtime, the
VM is the isolation, not in-guest privilege hardening. A process that escalates
via a setuid binary inside the VM is still trapped in a disposable VM with no
host filesystem or credentials. Docker and podman need `no-new-privileges`
because they share the host kernel; Apple does not.

Apple's own reference sandbox for running untrusted code,
[`containerization/examples/sandboxy`](https://github.com/apple/containerization/tree/main/examples/sandboxy)
("runs AI coding agents in sandboxed Linux environments"), hardens exactly the
way scrutineer does and sets no `no-new-privileges`, no seccomp, no special
capabilities: VM + read-only mounts + a host-only network + an allowlisting
HTTP CONNECT proxy on the host gateway. Scrutineer treats the VM boundary as the
substitute for `no-new-privileges` and applies everything else `--hardened`
promises.

## How `--hardened` works on Apple

`container network create --internal` is a vmnet host-only network: containers
on it have no internet route, but the host gateway is still reachable. That is
exactly the per-scan enforcement `--hardened` needs, and it is verified live on
`container` 1.0.0:

- external egress to a literal IP from the internal network is **blocked**;
- the host gateway (where the egress proxy listens) is **reachable**;
- vmnet isolates containers from one another by default, so concurrent scans
  cannot reach each other.

Because Apple has no `--add-host` to repoint a `host.docker.internal` alias, the
per-scan `--internal` network gets its own gateway (for example `192.168.128.1`,
distinct from the default network's `192.168.64.1`), and the runner points the
container's `HTTPS_PROXY`/`HTTP_PROXY` at that gateway IP directly. As with
rootless podman, each hardened scan first **proves the network fail-closed**
(`needsHardenedNetVerify`): two throwaway probes confirm external egress is
blocked yet the host proxy is still reachable, and the scan is refused
otherwise. This guards against Apple's known networking rough edges (DNS quirks,
the host-access caveat in
[apple/container#1320](https://github.com/apple/container/issues/1320), nftables
filtering still pending).

One quirk worth knowing: under `--hardened` the skill API base advertised to the
container (in `context.json`) stays `host.docker.internal`, not the gateway IP
that non-hardened apple advertises. That name does not resolve inside the VM, but
it never has to: hardened routes everything through the proxy, which recognises
the alias and rewrites it to `127.0.0.1`. Only the `HTTPS_PROXY` address itself
is the per-scan gateway IP.

`--hardened-runtime-only` (the rootless-podman non-network half) is refused
under `--runtime apple`: Apple's network half works, so `--hardened` is the
right flag.

## Still experimental

The capability is there; the maturity is not yet proven. What would justify
dropping the experimental label:

- [ ] broad testing on macOS 26 across a range of repos (Apple networking has
      DNS/host-routing bugs filed upstream);
- [ ] a decision on whether `192.168.x.1` host-gateway exposure on the internal
      network (apple/container#1320, pending nftables) needs tightening beyond
      what the authenticated proxy token already gives;
- [ ] confirmation that the VM-boundary substitution for `no-new-privileges` is
      acceptable as a documented, permanent divergence rather than a stopgap.

## See also

- `docs/podman.md`: the rootless/hardened model whose fail-closed verification
  Apple's hardened path mirrors.
- `threatmodel.md`: boundary 4 (container to host) and T13 (runner egress).
- `README.md`: the user-facing Apple container section.
