# Node.js profile. Extends the scrutineer runner with a pinned Node.js
# interpreter plus npm, pnpm, and yarn so scans of npm/pnpm/yarn projects
# can install their locked dependency set and reproduce in-place.
#
# Node ships official, sha256-verifiable prebuilt binaries (glibc), so the
# interpreter is fetched and checksummed the same way the runner installs
# claude -- not from a moving apt repo. Bump NODE_VERSION and the matching
# checksums together; both arches are listed because the worker may build
# this on amd64 or arm64 hosts.
#
# At runtime the worker builds this on demand (see internal/worker/profile.go:
# EnsureImage), tagging the result scrutineer-profile-node:<dockerfile-sha>
# and passing the configured runner image via --build-arg RUNNER_IMAGE.
#
# To build it manually the way the project does, from the repo root:
#
#   # 1. Build the base runner image locally (Debian/glibc, ships brief etc.):
#   docker build -t scrutineer-runner:local -f Dockerfile.runner .
#
#   # 2. Build this Node profile on top of that local runner:
#   docker build -t scrutineer-profile-node \
#       -f docker/profiles/node/Dockerfile \
#       --build-arg RUNNER_IMAGE=scrutineer-runner:local \
#       docker/profiles/node
#
#   # 3. Smoke-test it:
#   docker run --rm --entrypoint sh scrutineer-profile-node \
#       -c 'node --version && npm --version && pnpm --version && yarn --version'

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest

FROM ${RUNNER_IMAGE}

# Explicit, sha256-verifiable Node version (current 22.x LTS "Jod"). Bump
# NODE_VERSION and both checksums together; the content-addressed image
# tag invalidates the cache on any edit to this file.
ARG NODE_VERSION=22.23.0
ARG NODE_SHA256_X64=14d7de44f235534799f8b171a4050d9a6a4bc99c87e053a25d3d54afa580aa20
ARG NODE_SHA256_ARM64=4018815ac1bed4f18208901bbde524fee881253b591ee7bc952660e69bd057af

# pnpm and yarn pinned to exact versions. Unlike sury's apt repo, the npm
# registry keeps every published version forever, so an exact pin never
# 404s. yarn stays on the 1.x (classic) line, which reads the yarn.lock v1
# format most projects still ship. corepack is intentionally left disabled
# so these globals -- present offline -- are what `pnpm`/`yarn` resolve to,
# rather than corepack reaching out to the network mid-scan.
ARG PNPM_VERSION=11.8.0
ARG YARN_VERSION=1.22.22

USER root

ENV PATH=/usr/local/node/bin:$PATH

# xz-utils to unpack the .tar.xz; build-essential so node-gyp can compile
# native addons when a scan reproduces a project that ships them (python3
# is already in the runner). Toolchain kept in the final image because the
# in-place reproduce step needs it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        xz-utils \
        build-essential \
 && rm -rf /var/lib/apt/lists/* \
 && case "$(dpkg --print-architecture)" in \
        amd64) arch=x64;   sha="${NODE_SHA256_X64}" ;; \
        arm64) arch=arm64; sha="${NODE_SHA256_ARM64}" ;; \
        *) echo "unsupported architecture: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/node.tar.xz \
        "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${arch}.tar.xz" \
 && echo "${sha}  /tmp/node.tar.xz" | sha256sum -c - \
 && mkdir -p /usr/local/node \
 && tar -xJf /tmp/node.tar.xz -C /usr/local/node --strip-components=1 \
 && rm /tmp/node.tar.xz \
 && npm install -g "pnpm@${PNPM_VERSION}" "yarn@${YARN_VERSION}" \
 && node --version \
 && npm --version \
 && pnpm --version \
 && yarn --version

USER runner
