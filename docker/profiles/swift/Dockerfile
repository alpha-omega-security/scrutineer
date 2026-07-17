# Swift profile. Extends the scrutineer runner with a pinned Swift toolchain
# and the swiftly version manager so scans of SwiftPM projects can resolve
# dependencies, build, test, and reproduce findings in-place.
#
# The toolchain is the official swift.org release tarball, sha256-verified
# here (swift.org publishes GPG signatures, not checksums; the hashes below
# were computed once from the verified tarballs and pinned). The tarball is
# built for Debian 12; the runner base is Debian 13 (trixie), which is
# ABI-forward-compatible for the compiler/driver/SwiftPM. lldb from the
# tarball links libpython3.11 and does NOT run on trixie -- see PROFILE.md.
#
# swiftly is installed alongside so the agent can pull a different toolchain
# mid-scan when Package.swift's tools-version outstrips the pinned one; the
# pinned tarball stays the default `swift` on PATH.
#
# At runtime the worker builds this on demand (see internal/worker/profile.go:
# EnsureImage), tagging the result scrutineer-profile-swift:<dockerfile-sha>
# and passing the configured runner image via --build-arg RUNNER_IMAGE.
#
# To build it manually the way the project does, from the repo root:
#
#   # 1. Build the base runner image locally (Debian/glibc, ships brief etc.):
#   docker build -t scrutineer-runner:local -f Dockerfile.runner .
#
#   # 2. Build this Swift profile on top of that local runner:
#   docker build -t scrutineer-profile-swift \
#       -f docker/profiles/swift/Dockerfile \
#       --build-arg RUNNER_IMAGE=scrutineer-runner:local \
#       docker/profiles/swift
#
#   # 3. Smoke-test it:
#   docker run --rm --entrypoint sh scrutineer-profile-swift \
#       -c 'swift --version && swiftly --version'

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest

FROM ${RUNNER_IMAGE}

# Bump SWIFT_VERSION and both checksums together; the content-addressed
# image tag invalidates the cache on any edit to this file. Both arches are
# listed because the worker may build this on an amd64 or arm64 host.
ARG SWIFT_VERSION=6.3.3
ARG SWIFT_SHA256_AMD64=19e0c78cad5418ad48bfa87aa20c53ac9ac9996d1695d04dd94f7c7ea4eb133f
ARG SWIFT_SHA256_ARM64=ecba8ef87b54a5048d466af500f3169c939a6b8a2cb7c600f76b5184457f293a
ARG SWIFTLY_VERSION=1.1.3
ARG SWIFTLY_SHA256_AMD64=4c4adb7b7ad7910f38c52b94a938c309586fe395e1fe1538c397384ee36bfff0
ARG SWIFTLY_SHA256_ARM64=cc4f912fff6c7f53704fc6d22f9e8ee7fdf6bd574ad276998f7502418bf5a45a

USER root

# The pinned tarball's usr/bin comes FIRST so plain `swift` is the pinned,
# reproducible toolchain; swiftly's bin comes after so `swiftly` resolves
# but its shims never shadow the pinned compiler. To use a swiftly-fetched
# toolchain, invoke it explicitly: `swiftly run +<version> swift build`.
# SWIFTLY_HOME_DIR lives under /opt (a real image dir, exec-capable) rather
# than $HOME=/tmp, which the worker mounts noexec -- a swiftly-fetched
# toolchain's compiler must be executable. SwiftPM also compiles Package.swift
# into TMPDIR and executes the resulting manifest, so point TMPDIR at the
# worker's writable, exec-capable /work bind mount. Same known limitation as
# the other profiles: hardened mode mounts the rootfs read-only, so /opt is
# not writable there and a swiftly install would fail.
ENV SWIFTLY_HOME_DIR=/opt/swiftly \
    SWIFTLY_BIN_DIR=/opt/swiftly/bin \
    SWIFTLY_TOOLCHAINS_DIR=/opt/swiftly/toolchains \
    TMPDIR=/work \
    PATH=/opt/swift/usr/bin:/opt/swiftly/bin:$PATH

# Runtime deps are the swift.org Debian list minus binutils-gold (dropped
# from trixie; the bundled clang falls back to bfd ld from plain binutils)
# plus gnupg for swiftly's toolchain signature verification. libpython3-dev
# is deliberately omitted: on trixie it pulls 3.13, which does not satisfy
# the tarball lldb's libpython3.11 link, so it would only add weight.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        binutils \
        gcc \
        git \
        gnupg \
        libc6-dev \
        libcurl4-openssl-dev \
        libedit-dev \
        libicu-dev \
        libncurses-dev \
        libsqlite3-dev \
        libstdc++-14-dev \
        libxml2-dev \
        pkg-config \
        tzdata \
        uuid-dev \
        zlib1g-dev \
 && rm -rf /var/lib/apt/lists/* \
 && case "$(dpkg --print-architecture)" in \
        amd64) sw_plat=debian12;         sw_sha="${SWIFT_SHA256_AMD64}"; sy_arch=x86_64;  sy_sha="${SWIFTLY_SHA256_AMD64}" ;; \
        arm64) sw_plat=debian12-aarch64; sw_sha="${SWIFT_SHA256_ARM64}"; sy_arch=aarch64; sy_sha="${SWIFTLY_SHA256_ARM64}" ;; \
        *) echo "unsupported architecture: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/swift.tar.gz \
        "https://download.swift.org/swift-${SWIFT_VERSION}-release/${sw_plat}/swift-${SWIFT_VERSION}-RELEASE/swift-${SWIFT_VERSION}-RELEASE-${sw_plat}.tar.gz" \
 && echo "${sw_sha}  /tmp/swift.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/swift \
 && tar -xzf /tmp/swift.tar.gz -C /opt/swift --strip-components=1 \
 && rm /tmp/swift.tar.gz \
 && curl -fsSL -o /tmp/swiftly.tar.gz \
        "https://download.swift.org/swiftly/linux/swiftly-${SWIFTLY_VERSION}-${sy_arch}.tar.gz" \
 && echo "${sy_sha}  /tmp/swiftly.tar.gz" | sha256sum -c - \
 && install -d -m 1777 /opt/swiftly /opt/swiftly/bin /opt/swiftly/toolchains \
 && tar -xzf /tmp/swiftly.tar.gz -C /opt/swiftly/bin swiftly \
 && rm /tmp/swiftly.tar.gz \
 # TMPDIR is already /work during the image build, so create it before
 # swiftly init or any SwiftPM command needs temporary storage.
 && install -d -m 1777 /work \
 # --skip-install: the pinned tarball above is the default toolchain, so
 # swiftly only needs its config.json written, not a second download.
 && /opt/swiftly/bin/swiftly init --assume-yes --skip-install --no-modify-profile \
        --platform debian12 \
 && chmod -R a+w /opt/swiftly \
 && swift --version \
 && swiftly --version \
 # Match the runtime TMPDIR/workspace layout so the smoke test exercises
 # SwiftPM's manifest compilation on the exec-capable path used by scans.
 && mkdir /work/smoke && cd /work/smoke \
 && swift package init --type executable --name smoke \
 && swift build \
 && swift run smoke \
 && cd / && rm -rf /work/smoke

USER runner
