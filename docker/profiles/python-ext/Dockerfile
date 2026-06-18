# Python-extension profile.
#
# Ships CPython built from source with --with-pydebug + ASan + UBSan, for
# scanning Python packages that include compiled C/C++ extension modules.
# C extensions installed against this interpreter (CFLAGS/LDFLAGS wire the
# sanitizers in) are instrumented, so a reproducer that drives the
# extension surfaces memory-safety and UB bugs the static scan can only
# guess at. This mirrors the php-ext profile.
#
# Auto-selected for repos whose setup.py declares a C Extension (see
# internal/worker/profile.go); also selectable by name via
# ?profile=python-ext. The
# debug+sanitizer interpreter is much slower than the plain python
# profile, so it is scoped to repos that actually ship native code.
#
# At runtime the worker builds this on demand (see internal/worker/profile.go:
# EnsureImage), tagging the result scrutineer-profile-python-ext:<dockerfile-sha>
# and passing the configured runner image via --build-arg RUNNER_IMAGE. The
# build installs its toolchain with apt, so RUNNER_IMAGE must resolve to the
# Debian runner built from ./Dockerfile.runner.
#
# To build it manually the way the project does, from the repo root:
#
#   # 1. Build the base runner image locally (Debian/glibc, ships brief etc.):
#   docker build -t scrutineer-runner:local -f Dockerfile.runner .
#
#   # 2. Build this Python-extension profile on top of that local runner
#   #    (compiles CPython from source with ASan/UBSan; takes several minutes):
#   docker build -t scrutineer-profile-python-ext \
#       -f docker/profiles/python-ext/Dockerfile \
#       --build-arg RUNNER_IMAGE=scrutineer-runner:local \
#       docker/profiles/python-ext
#
#   # 3. Smoke-test it (debug build, sanitizers wired in):
#   docker run --rm --entrypoint sh scrutineer-profile-python-ext \
#       -c 'python --version && python -c "import sys; print(sys._is_gil_enabled if hasattr(sys,\"_is_gil_enabled\") else 0)"'

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest
ARG PYTHON_GIT_URL=https://github.com/python/cpython.git
ARG PYTHON_GIT_REF=v3.13.14

FROM ${RUNNER_IMAGE}
ARG PYTHON_GIT_URL
ARG PYTHON_GIT_REF

USER root

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/usr/local/python-asan/bin:$PATH \
    PYTHONMALLOC=malloc \
    ASAN_OPTIONS="symbolize=1:detect_leaks=0:allocator_may_return_null=1:halt_on_error=0:print_summary=1" \
    UBSAN_OPTIONS="print_stacktrace=1:print_summary=1"

# gcc (build-essential) builds CPython: clang now defaults to
# -Werror=implicit-function-declaration, which breaks several of
# configure's feature probes (getaddrinfo among them). gdb for triage,
# plus the headers the stdlib and most C extensions link against (ssl,
# ffi, zlib, bz2, lzma, readline, sqlite, ncurses, gdbm, uuid).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gdb \
        git ca-certificates \
        pkg-config \
        libssl-dev libffi-dev zlib1g-dev \
        libbz2-dev liblzma-dev libreadline-dev \
        libsqlite3-dev libncurses-dev libgdbm-dev uuid-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git clone --depth 1 --branch "${PYTHON_GIT_REF}" "${PYTHON_GIT_URL}" cpython
WORKDIR /opt/cpython
# ac_cv_buggy_getaddrinfo=no: under ASan, configure's getaddrinfo runtime
# probe can still misfire; this is the documented override for
# sanitizer/cross builds.
RUN ac_cv_buggy_getaddrinfo=no ./configure \
        --prefix=/usr/local/python-asan \
        --with-pydebug \
        --with-address-sanitizer \
        --with-undefined-behavior-sanitizer \
        --without-pymalloc \
 && make -j"$(nproc)" \
 && make install \
 && ln -s /usr/local/python-asan/bin/python3 /usr/local/bin/python \
 && ln -s /usr/local/python-asan/bin/python3 /usr/local/bin/python3

# Extensions built by pip against this interpreter must carry the same
# sanitizers, built with the same compiler (gcc) so they share CPython's
# gcc ASan runtime -- a clang-built .so dlopened into gcc-asan CPython
# aborts with a runtime mismatch. -fno-sanitize-recover makes UB in an
# extension abort rather than silently continue. Matches the php-ext
# approach.
ENV CFLAGS="-fsanitize=address -fsanitize=undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g -O1" \
    CXXFLAGS="-fsanitize=address -fsanitize=undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g -O1" \
    LDFLAGS="-fsanitize=address -fsanitize=undefined"

# ASan/UBSan-built interpreter; the install dir must stay writable for the
# host uid the scan runs as so pip can build extensions in place. Container
# is ephemeral and --rm'd after the scan, so the blast radius is zero.
RUN chmod -R a+rwX /usr/local/python-asan \
 && python --version 2>&1 | grep -q "3.13" \
 && python -c "import _testcapi; print('debug build ok')" \
 && python -X dev -c "print('asan python runs')"

USER runner
