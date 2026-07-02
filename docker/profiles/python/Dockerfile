# Python profile. Extends the scrutineer runner with a pinned CPython and
# uv so scans of pip/Poetry/Pipenv/PDM/uv projects can install their
# dependency set and reproduce findings in-place. There is no global pip;
# the interpreter is externally managed and uv handles installs (uv pip,
# uv venv, uv sync).
#
# CPython is installed by uv from a sha-verified standalone build at an
# explicit pinned version, so the interpreter is current and identical
# regardless of what the base image's distro packages (the runner has
# drifted between Debian releases, shipping 3.11 on bookworm and 3.13 on
# trixie -- pinning here keeps the scan interpreter stable across that).
#
# uv itself is a pinned, sha256-verified release tarball, fetched the same
# way the runner installs claude rather than from a moving installer.
#
# At runtime the worker builds this on demand (see internal/worker/profile.go:
# EnsureImage), tagging the result scrutineer-profile-python:<dockerfile-sha>
# and passing the configured runner image via --build-arg RUNNER_IMAGE.
#
# To build it manually the way the project does, from the repo root:
#
#   # 1. Build the base runner image locally (Debian/glibc, ships brief etc.):
#   docker build -t scrutineer-runner:local -f docker/runner/Dockerfile.runner .
#
#   # 2. Build this Python profile on top of that local runner:
#   docker build -t scrutineer-profile-python \
#       -f docker/profiles/python/Dockerfile \
#       --build-arg RUNNER_IMAGE=scrutineer-runner:local \
#       docker/profiles/python
#
#   # 3. Smoke-test it:
#   docker run --rm --entrypoint sh scrutineer-profile-python \
#       -c 'python --version && uv --version && uv pip --version'

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest

FROM ${RUNNER_IMAGE}

# Explicit pinned versions. uv resolves PYTHON_VERSION to a sha-verified
# python-build-standalone release; bump either and the content-addressed
# image tag invalidates the cache.
ARG UV_VERSION=0.11.21
ARG UV_SHA256_X64=8c88519b0ef0af9801fcdee419bbb12116bd9e6b18e162ae093c932d8b264050
ARG UV_SHA256_ARM64=88e800834007cc5efd4675f166eb2a51e7e3ad19876d85fa8805a6fb5c922397
ARG PYTHON_VERSION=3.13.14

USER root

# uv-managed CPython lives here; the install below symlinks its python /
# python3 onto PATH so reproducers and venvs use the pinned interpreter by
# default. UV_TOOL_BIN_DIR puts any `uv tool install` shims on PATH too.
ENV UV_PYTHON_INSTALL_DIR=/opt/uv/python \
    UV_TOOL_BIN_DIR=/usr/local/bin

# build-essential plus the headers C-extension wheels most commonly link
# against (ffi, openssl, zlib). The standalone CPython brings its own
# Python headers; these cover the third-party libs wheels build against.
# Toolchain stays in the final image because the in-place reproduce step
# compiles wheels.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libffi-dev \
        libssl-dev \
        zlib1g-dev \
 && rm -rf /var/lib/apt/lists/* \
 && case "$(dpkg --print-architecture)" in \
        amd64) arch=x86_64;  sha="${UV_SHA256_X64}" ;; \
        arm64) arch=aarch64; sha="${UV_SHA256_ARM64}" ;; \
        *) echo "unsupported architecture: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/uv.tar.gz \
        "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-${arch}-unknown-linux-gnu.tar.gz" \
 && echo "${sha}  /tmp/uv.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/uv.tar.gz -C /tmp \
 && install -m 0755 "/tmp/uv-${arch}-unknown-linux-gnu/uv" /usr/local/bin/uv \
 && install -m 0755 "/tmp/uv-${arch}-unknown-linux-gnu/uvx" /usr/local/bin/uvx \
 && rm -rf /tmp/uv.tar.gz "/tmp/uv-${arch}-unknown-linux-gnu" \
 && uv python install "${PYTHON_VERSION}" \
 && ln -sf "$(uv python find "${PYTHON_VERSION}")" /usr/local/bin/python3 \
 && ln -sf /usr/local/bin/python3 /usr/local/bin/python \
 && python --version \
 && python3 --version \
 && uv --version

# The pinned interpreter and its install dir must stay readable when the
# container runs as the host's uid (docker --user $(id -u):$(id -g))
# rather than the image user. uv writes its own caches under HOME at scan
# time, so only read/execute access is needed here.
RUN chmod -R a+rX /opt/uv

USER runner
