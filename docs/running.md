# Running Scrutineer

Scrutineer normally runs on the host and uses an external container runtime for scans. See the [quick start](../README.md#quick-start) for the default installation and first scan, or select the [Codex](codex.md), [OpenCode](opencode.md), or [Copilot](copilot.md) backend for its credentials and configuration.

## Installation

Install Scrutineer from [Homebrew](https://brew.sh) on macOS or Linux:

    brew install scrutineer

Alternatively, download the Linux or macOS archive for your architecture from [GitHub Releases](https://github.com/alpha-omega-security/scrutineer/releases), verify it against `SHA256SUMS`, and put `scrutineer` on your `PATH`. The macOS archives are currently unsigned and not notarized, so macOS may present a Gatekeeper warning even after you verify the checksum and GitHub build-provenance attestation.

To build or run from source instead, install [Go 1.27+](https://go.dev/dl/):

    git clone https://github.com/alpha-omega-security/scrutineer
    cd scrutineer
    go run -buildvcs=true ./cmd/scrutineer -skills ./skills

The `-skills ./skills` directory overrides the skills embedded in the executable, which is useful while developing skills. It is optional for ordinary use. Open the login link logged at startup; the operator token is stored in `data/operator-token` for scripts calling the [operator API](api.md#operator-api-apiv1).

The `-buildvcs=true` flag includes the source commit in `go run` builds. Settings > About shows that commit, with a `-dirty` suffix for local changes, and its commit date. Ordinary `go build` commands include this metadata automatically in a Git checkout.

You can also build a checkout-independent executable and run it from another directory:

    go build -o scrutineer ./cmd/scrutineer
    mkdir -p ~/.local/bin
    install -m 0755 scrutineer ~/.local/bin/scrutineer
    scrutineer

Precompiled binaries cover Linux and macOS on `amd64` and `arm64`. Run `scrutineer --version` (or `scrutineer version`) to see the application version, source commit, build timestamp, and exact runner-image digest paired with that release.

The executable includes built-in skills and per-ecosystem runner profiles, but does not bundle Docker, Podman, or Apple's `container` CLI. It materialises the embedded profile Dockerfiles under the data directory when `docker/profiles` is not available from a source checkout. Content-addressed skill and profile bundles from older versions are retained because existing skill records may still reference their auxiliary files; incomplete extraction directories older than 24 hours are removed automatically.

Scrutineer uses SQLite by default. For PostgreSQL setup and migration, see [database.md](database.md). See [backup.md](backup.md) for backup and restore instructions.

## Git authentication

Scrutineer shells out to `git clone` with no explicit token passing, so it uses whatever credentials are already configured on the host: SSH keys, credential helpers, `gh auth login`, a `.netrc` file, or the macOS keychain.

To scan private repos, check that `git clone https://github.com/org/repo` works in the same environment you launch scrutineer from before adding the URL.

Common setups:

    # GitHub CLI (easiest)
    gh auth login

    # Git credential helper
    git config --global credential.helper store   # or osxkeychain / manager-core

    # SSH-based clone URLs are not supported -- scrutineer only accepts https:// URLs.
    # Use a credential helper to authenticate HTTPS clones instead.

When running inside Docker (`docker run ...`), the container has no access to host credentials. Mount a credential store or set `GIT_ASKPASS` to provide access to private repos from inside the container.

With the default containerised runner, each scan runs in a separate container but the clone happens on the host before the source is mounted in. Host credentials are used for the clone and never enter the container.

## Container runner

By default, scrutineer runs each scan in an ephemeral container with a read-write workspace mount at `/work`, including `/work/src`, and dropped capabilities. `--hardened` and `--hardened-runtime-only` make the container root filesystem read-only; `/work` remains writable. Startup fails if the selected runtime is unavailable; running on the host requires an explicit `--no-container`. The runner image is published to GHCR as a multi-arch manifest (`linux/amd64` and `linux/arm64`) and pulled automatically on first use:

    go run -buildvcs=true ./cmd/scrutineer -skills ./skills

The analysis tools (semgrep, bandit, zizmor, betterleaks, darnit, git-pkgs and brief) are bundled in the runner image, so they do not need to be installed on the host for container scans.

Use `--runtime podman` to run scans under podman instead of docker (see [Podman setup](podman.md#setup)), `--runtime apple` to run scans under Apple's `container` runtime on macOS (see [Apple container setup](apple.md#setup)), `--no-container` to disable containerised execution entirely, or `--runner-image` to specify a different image. To build the runner locally instead of pulling from GHCR (use `podman build` or `container build` instead if you run scans under those runtimes):

    docker build -t scrutineer-runner -f Dockerfile.runner .
    go run -buildvcs=true ./cmd/scrutineer -skills ./skills --runner-image scrutineer-runner

The runner's bundled Claude Code only moves when a maintainer merges Renovate's update, and Renovate waits until a Claude Code release is seven days old, so a model that needs a newer CLI takes at least a week to become usable. It takes longer on a release binary, whose default runner image only changes with the next scrutineer release. To run a newer Claude Code without falling back to `--no-container`, build the runner from a checkout of the scrutineer version you run and override the `CLAUDE_*_LOCK` build arguments with the Claude Code tag and the SHA-256 of `claude-linux-x64.tar.gz` and `claude-linux-arm64.tar.gz` from that Claude Code release's `SHASUMS256.txt`. Per-ecosystem profile images are cached by a locally built runner's tag alone, so give each version its own tag to have them rebuilt on top of it:

    docker build -t scrutineer-runner:claude-2.1.284 -f Dockerfile.runner --build-arg CLAUDE_AMD64_LOCK=v2.1.284@sha256:<x64 digest> --build-arg CLAUDE_ARM64_LOCK=v2.1.284@sha256:<arm64 digest> .
    go run -buildvcs=true ./cmd/scrutineer -skills ./skills --runner-image scrutineer-runner:claude-2.1.284

The staleness check below never flags a locally built runner, so drop `--runner-image` once the published runner carries the Claude Code release you need.

The runner image is not auto-updated. Release binaries use a release-matched digest; install a newer Scrutineer release to update that default. Pulling `:latest` alone does not change the digest embedded in a release binary. Development builds use `:latest` by default. To use the latest published runner with either build, pull it and select it explicitly:

    docker pull ghcr.io/alpha-omega-security/scrutineer-runner:latest
    scrutineer --runner-image ghcr.io/alpha-omega-security/scrutineer-runner:latest

Scrutineer checks the registry once at startup (in the background, and failing silently if the registry is unreachable) and flags the runner image when it is more than seven days behind the published `:latest`, both in the boot log and as a banner on the Settings page.

On sidecar-backed hardened runtimes, scrutineer also refuses a runner image whose proxy binary does not support the current host-API tunnel policy. Pull or rebuild custom runner images when updating the host binary.

Pull the runner image explicitly before starting new scans when you want to update the toolchain. Scrutineer has no setting to force an image pull on every scan.

### Egress proxy

When the container runner is active, scrutineer starts an authenticated egress proxy on the host and points `HTTPS_PROXY`/`HTTP_PROXY` inside the container at it. The proxy only permits an allowlist of hosts: the active model API, `*.ecosyste.ms`, the major forges (GitHub, GitLab, Codeberg, Bitbucket), common package registries (npm, PyPI, RubyGems, crates.io, Go module proxy, Packagist, Hex, NuGet), advisory sources (semgrep.dev, OSV, NVD, cwe.mitre.org), and the runtime's host endpoint (`host.docker.internal` for docker/podman, the default gateway IP for Apple's `container`) for the local skill API. That API port accepts inspected HTTP proxy requests but refuses raw `CONNECT` tunnels; separately configured host-local model ports remain tunnelable. Requests to anything else get a 403 and are logged. Extend the list with `egress_allow` in the config file. When `-model-base-url` is set (or, for Claude, falls back to the `ANTHROPIC_BASE_URL` env var), its hostname is automatically added to the allowlist. The proxy uses a per-process random token so it isn't an open relay; tools that ignore the proxy env are not blocked at the network layer (see [threatmodel.md](../threatmodel.md)).

### Hardened mode

For deployments that treat skill prompts as untrusted, pass `--hardened` (or `hardened: true` in the config). The flag forces the container runner (`--no-container` is rejected), trims the egress allowlist to the active backend's model API hosts plus the host skill API (so `egress_allow` is ignored, drop the flag if you need to widen it), mounts the container rootfs read-only with `no-new-privileges`, attaches each scan to its own ephemeral network created with `--internal` (removed when the scan ends) so a process that ignores `HTTPS_PROXY` has no route out and concurrent scans cannot reach each other, and refuses scans whose workspace footprint exceeds 2 GiB once the clone completes. The 2 GiB check is post-clone: it bounds what hardened mode accepts, not what can land on disk during the clone itself; use OS-level disk quotas if you need a clone-time guarantee. Bundled skills that hit ecosyste.ms or a package registry directly will fail under hardened mode unless they route through the host skill API. Per-ecosystem runner profiles still apply, but profile images that need writable paths beyond `/work` and `/tmp` are incompatible. Under Docker Desktop and rootless podman the proxy runs as a per-scan sidecar container on the `--internal` network because the host proxy is unreachable there; see [docs/podman.md](podman.md) for the rootless podman path. These runtimes verify that each hardened network blocks external egress while still reaching the sidecar, and refuse the scan if that cannot be confirmed, so the sandbox never silently weakens. Docker Engine refuses `--hardened` at startup, because a scan on its `--internal` network reaches every host service bound to all interfaces through the network gateway without going through the proxy; use `--hardened-runtime-only` there for the non-network half.

### Host skills

To take only some skills out of the container (say `verify` for a project whose build toolchain only exists on the host, while `triage` and the deep-dive skills keep their profile containers), list them under `host_skills` in the config file: those run claude on the host with no egress proxy and reach the skill API on the loopback address, and the option is refused under `--hardened` and with non-claude backends, like `--no-container`.

## Runner profiles

When the container runner is active, scrutineer auto-detects a per-ecosystem **profile** for each scan: it runs `brief` against the clone and matches its structured package-manager, language, and tool detections. If `brief` fails or no selector matches, the scan uses the default runner image. The matched profile selects a runner image (built on demand from `docker/profiles/<name>/Dockerfile`, cached content-addressed by the Dockerfile's hash) and injects that profile's `PROFILE.md` as the agent's orientation. The most specific profile wins, so a native-extension repo resolves to its `*-ext` profile ahead of the plain language profile. Force one with `?profile=<name>` on the scan API (validated against the skill's `requires_profile`); `default` forces the base runner image.

| Profile | Selected when | Adds |
|---------|---------------|------|
| `php` / `php-ext` | `package_manager:Composer` / `tools.native_extension:phpize` | PHP; `php-ext` builds PHP debug + ASan/UBSan for C extensions |
| `python` / `python-ext` | `package_manager:pip` / `Pipenv` / `Poetry` / `uv` / `PDM` / `setuptools`; `python-ext` when `tools.native_extension:setuptools Extension` is present | CPython; `python-ext` builds CPython debug + ASan/UBSan |
| `ruby` | Bundler or RubyGems | Ruby 3.4 + Bundler; metaprogramming / dynamic-dispatch guidance, plus a tripwire that flags an un-instrumented native extension |
| `ruby-ext` | `tools.native_extension:mkmf` | A **superset** of `ruby`: adds an ASan/UBSan Ruby (the default interpreter), valgrind on the stock interpreter, Rust nightly for rb-sys gems, and Brakeman |
| `ruby-rails` | `tools.build:Rails` | A superset of `ruby` plus **Brakeman**, Rails-specific SAST |
| `node` | npm/pnpm/Yarn/Bun | Node.js |
| `go` | Go Modules | Go toolchain |
| `scala` | sbt or Scala language detection | A superset of `java` plus **sbt** and Scala-specific reproducer guidance |
| `java` | Maven/Gradle | JDK |
| `dotnet` | NuGet/dotnet CLI | .NET SDK |
| `beam` | Mix/rebar3 | Erlang/Elixir |
| `rust` | Cargo | Rust stable + nightly, Miri, sanitizers |
| `ocaml` | opam, `tools.build:Dune`, or OCaml language detection | opam + a compiled OCaml 5.x switch + dune |
| `swift` | Swift Package Manager or Swift language detection | Swift toolchain + swiftly |
| `perl` | cpanm or Perl language detection | Perl toolchain |
| `c-cpp` | `tools.build:CMake` / `Make` / `Autotools` / `Meson`, or C/C++ language detection, after language ecosystems have had a chance to match | C/C++ build toolchain |

The three Ruby profiles are mutually exclusive at selection time, but `ruby-ext` and `ruby-rails` are deliberate *supersets* of `ruby` (the same Ruby-level audit, plus their extra coverage), so a detection that errs toward `ruby-ext` costs only build time, never coverage. A native gem that slips through to the plain `ruby` profile is caught by that profile's tripwire, which records that memory-safety scanning needs `ruby-ext`. Add a profile by registering it in `internal/worker/profile.go` and adding `docker/profiles/<name>/{Dockerfile,PROFILE.md}`.

**Refreshing profile images.** Because profile images cache on the Dockerfile's hash, a moved `:latest` base runner -- or an edited `PROFILE.md` -- won't always force a rebuild (without `skopeo` the cache keys on the image ref alone; see [Podman setup](podman.md#setup)). Two helpers give you a clean slate: [`scripts/ruby-image-reset.sh`](../scripts/ruby-image-reset.sh) removes the Ruby profile images (`ruby`, `ruby-ext`, `ruby-rails`), [`scripts/all-images-reset.sh`](../scripts/all-images-reset.sh) removes every ecosystem's, and both then pull the latest `scrutineer-runner` so the next scan rebuilds from a fresh base. Each prompts before removing anything (`--force` skips it) and uses docker if present, otherwise podman; both run under bash 3.2+, so macOS's stock `/bin/bash` works.

## Hosting Scrutineer in Docker

    docker build --build-arg COMMIT="$(git rev-parse HEAD)" -t scrutineer .
    docker run -p 127.0.0.1:8080:8080 -v scrutineer-data:/data \
      -e ANTHROPIC_API_KEY=sk-ant-api03-... \
      -e ANTHROPIC_BASE_URL=https://... \
      scrutineer

Or with a Claude Code OAuth token instead of an API key:

    docker run -p 127.0.0.1:8080:8080 -v scrutineer-data:/data \
      -e CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-... \
      scrutineer

For codex or opencode, pass `-e CODEX_API_KEY=...` / `-e OPENAI_API_KEY=...` (or `ANTHROPIC_API_KEY` for opencode with an Anthropic model) and add `-backend codex` / `-backend opencode` to the command. For copilot, pass `-e GH_TOKEN=...` (a fine-grained PAT or `gh auth token` value; classic `ghp_` PATs are rejected by Copilot CLI) and add `-backend copilot`.

Always bind to `127.0.0.1`: the operator token is the only credential on the UI, so binding to `0.0.0.0` leaves your findings database one leaked token away from anyone on the network. The first-run login link is in `docker logs`, and `docker exec <container> cat /data/operator-token` prints the token later.

## Windows

Scrutineer builds and runs on Windows hosts: every release ships a `windows-amd64` archive, and `go build ./cmd/scrutineer` produces `scrutineer.exe`. Scans run under Docker Desktop with the default `--runtime docker`. `--runtime apple` is macOS-only and `--runtime podman` has not been tested there. What differs from Linux and macOS:

- **Container user**: Windows has no host uid/gid to map, so the runner omits `--user` and each scan runs as the image's own `USER`. The bundled runner and profile images end with `USER runner`. A custom `--runner-image` or profile image that sets no `USER` runs the scan as root, where Linux and macOS would still map it to your uid.
- **Local directory scans**: paste a drive-letter path (`C:\path\to\project`) in the **Add repository** field. Recreating the symlinks of a copied tree needs the symlink privilege, so enable Developer Mode or run as administrator if a local scan fails on one.
- **Git**: run `git config --global core.longpaths true` and keep the data directory path short. The per-scan cache nests a 64-character content hash under it, and while `core.longpaths` lifts the 260-character limit for regular files, Git for Windows still refuses a submodule whose `.git/modules` directory sits past it (`fatal: '$GIT_DIR' too big`).
- **Cancellation**: cancelling a scan (from the UI, the scan timeout or Ctrl+C) terminates the process scrutineer started and every descendant it left behind. Windows has no signalable process group, so each scan process is created suspended, assigned to a job object limited to kill-on-close and only then resumed, which the kernel also closes if scrutineer itself dies. A scan whose job cannot be set up does not start.
- **`--no-container`**: `claude` must resolve to the native `claude.exe` (native installer or WinGet). An npm install puts a `claude.cmd` shim on `PATH`, which `PATHEXT` resolution finds but `CreateProcess` cannot launch, so every scan fails to start with `%1 is not a valid Win32 application`.
- **Credential file modes**: the owner-only permission checks on the OpenCode `state_dir` and on `codex.auth_file` are skipped, since Go file modes carry no ACL on Windows and every file reads back as `0666`. Each `auth.json` inherits the ACL of its parent directory, so keep both under a path only your account can read.

## Sandboxed Claude Code configs

In `--no-container` mode, and for the skills listed in `host_skills`, the `claude` subprocess inherits your `~/.claude/settings.json`, so [sandbox settings](https://code.claude.com/docs/en/sandboxing) that restrict network or filesystem access there will fail skills that need them. Point `claude` at a separate config directory just for scrutineer runs:

    CLAUDE_CONFIG_DIR=~/.claude-scrutineer go run -buildvcs=true ./cmd/scrutineer -skills ./skills

Copy your `settings.json` into that directory and drop the sandbox keys; your normal Claude Code config is untouched. Container mode is not affected for the skills that stay in the container: there `claude` runs inside the container with its own environment regardless of the host config.
