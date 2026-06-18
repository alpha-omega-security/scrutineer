# Go profile. Extends the scrutineer runner with a pinned Go toolchain,
# govulncheck, and a C toolchain (cgo) so scans of Go-module projects can
# build, test, and reproduce findings in-place.
#
# Go ships official, sha256-verifiable release archives, so the toolchain
# is fetched and checksummed the same way the runner installs claude --
# not from a moving apt repo. Bump GO_VERSION and the matching checksums
# together; both arches are listed because the worker may build this on an
# amd64 or arm64 host.
#
# At runtime the worker builds this on demand (see internal/worker/profile.go:
# EnsureImage), tagging the result scrutineer-profile-go:<dockerfile-sha>
# and passing the configured runner image via --build-arg RUNNER_IMAGE.
#
# To build it manually the way the project does, from the repo root:
#
#   # 1. Build the base runner image locally (Debian/glibc, ships brief etc.):
#   docker build -t scrutineer-runner:local -f Dockerfile.runner .
#
#   # 2. Build this Go profile on top of that local runner:
#   docker build -t scrutineer-profile-go \
#       -f docker/profiles/go/Dockerfile \
#       --build-arg RUNNER_IMAGE=scrutineer-runner:local \
#       docker/profiles/go
#
#   # 3. Smoke-test it:
#   docker run --rm --entrypoint sh scrutineer-profile-go \
#       -c 'go version && govulncheck -version'

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest

FROM ${RUNNER_IMAGE}

# Explicit, sha256-verifiable Go version. Bump GO_VERSION and both
# checksums together; the content-addressed image tag invalidates the
# cache on any edit to this file.
ARG GO_VERSION=1.26.4
ARG GO_SHA256_AMD64=1153d3d50e0ac764b447adfe05c2bcf08e889d42a02e0fe0259bd47f6733ad7f
ARG GO_SHA256_ARM64=ef758ae7c6cf9267c9c0ef080b8965f453d89ab2d25d9eb22de4405925238768
# govulncheck reports known vulns in the project's module graph and (with
# source) which are actually reachable. Pinned; built from source below.
ARG GOVULNCHECK_VERSION=v1.4.0

USER root

# GOTOOLCHAIN=local pins the installed toolchain: a project go.mod that
# requires a newer Go would otherwise make `go` download another toolchain
# mid-scan (network + unpinned). The cache/tmp dirs live under /opt (a real
# image dir, exec-capable) rather than $HOME=/tmp, which the worker mounts
# noexec -- `go run`/`go test` exec the binaries they build, so GOTMPDIR
# must sit on an exec-capable path. 1777 so any host uid can write; the
# container is --rm'd after the scan. (Hardened mode mounts the rootfs
# read-only, leaving only /work and /tmp writable, so in that mode point
# these at a /work subdir instead.)
ENV PATH=/usr/local/go/bin:$PATH \
    GOTOOLCHAIN=local \
    GOPATH=/opt/go/path \
    GOMODCACHE=/opt/go/path/pkg/mod \
    GOCACHE=/opt/go/cache \
    GOTMPDIR=/opt/go/tmp

# build-essential for cgo (a project with import "C" needs a C compiler to
# build and test). Kept in the final image because the in-place reproduce
# step compiles.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/* \
 && case "$(dpkg --print-architecture)" in \
        amd64) arch=amd64; sha="${GO_SHA256_AMD64}" ;; \
        arm64) arch=arm64; sha="${GO_SHA256_ARM64}" ;; \
        *) echo "unsupported architecture: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/go.tar.gz \
        "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" \
 && echo "${sha}  /tmp/go.tar.gz" | sha256sum -c - \
 && tar -C /usr/local -xzf /tmp/go.tar.gz \
 && rm /tmp/go.tar.gz \
 && install -d -m 1777 /opt/go/path /opt/go/cache /opt/go/tmp \
 && go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" \
 && install -m 0755 /opt/go/path/bin/govulncheck /usr/local/bin/govulncheck \
 && go version \
 && govulncheck -version \
 && printf 'package main\nimport "fmt"\nfunc main(){fmt.Println("go run ok")}\n' > /tmp/smoke.go \
 && go run /tmp/smoke.go \
 && rm /tmp/smoke.go \
 # A GOCACHE populated during docker build is committed into the image
 # layer and then poisons std-package resolution at scan time (`go list
 # std` reports every std package as "not in std", and `go test` fails to
 # build its testmain). govulncheck is already on PATH, so the build cache
 # is no longer needed: empty it and recreate the dir 1777 so the scan
 # starts from a clean, writable cache.
 && go clean -cache \
 && install -d -m 1777 /opt/go/cache

USER runner
