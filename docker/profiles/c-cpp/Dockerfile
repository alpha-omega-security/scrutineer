# C/C++ profile. Extends the scrutineer runner with a C and C++ build and
# analysis toolchain so scans of native projects can build, run, and
# reproduce findings -- with AddressSanitizer/UndefinedBehaviorSanitizer,
# valgrind, and gdb on hand to turn memory-safety bugs into evidence.
#
# Unlike the language profiles there is no single package manager to detect
# (brief reports none for C/C++), so this profile is selected by build-file
# marker (CMakeLists.txt, Makefile, configure.ac, meson.build) or by name
# via ?profile=c-cpp. It serves both C and C++; the toolchains overlap
# almost entirely, so one image covers both.
#
# The toolchain is installed from Debian's apt (unpinned, like the php
# profile's apt packages): these are compilers and analysers, and tracking
# the distro's current build keeps the profile building as the base moves
# forward.
#
# At runtime the worker builds this on demand (see internal/worker/profile.go:
# EnsureImage), tagging the result scrutineer-profile-c-cpp:<dockerfile-sha>
# and passing the configured runner image via --build-arg RUNNER_IMAGE.
#
# To build it manually the way the project does, from the repo root:
#
#   # 1. Build the base runner image locally (Debian/glibc, ships brief etc.):
#   docker build -t scrutineer-runner:local -f Dockerfile.runner .
#
#   # 2. Build this C/C++ profile on top of that local runner:
#   docker build -t scrutineer-profile-c-cpp \
#       -f docker/profiles/c-cpp/Dockerfile \
#       --build-arg RUNNER_IMAGE=scrutineer-runner:local \
#       docker/profiles/c-cpp
#
#   # 3. Smoke-test it:
#   docker run --rm --entrypoint sh scrutineer-profile-c-cpp \
#       -c 'gcc --version && clang --version && cmake --version && valgrind --version'

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest

FROM ${RUNNER_IMAGE}

USER root

# Sanitizer run-time defaults, so a reproducer built with -fsanitize=...
# produces clean, useful output rather than aborting on benign noise.
# Mirrors the php-ext profile.
ENV ASAN_OPTIONS="symbolize=1:detect_leaks=0:allocator_may_return_null=1:halt_on_error=0:print_summary=1" \
    UBSAN_OPTIONS="print_stacktrace=1:print_summary=1"

# gcc/g++ and clang (clang adds -fsanitize=fuzzer, =memory, =thread that gcc
# lacks); cmake/ninja/make/autotools for whatever build system the project
# uses; gdb + valgrind to investigate crashes and leaks; clang-tidy and
# cppcheck for static analysis. llvm supplies llvm-symbolizer for readable
# sanitizer traces.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential g++ \
        clang lld llvm clang-tidy \
        cmake ninja-build make \
        autoconf automake libtool pkg-config m4 \
        gdb valgrind \
        cppcheck \
 # clang ships its sanitizer runtimes (libclang_rt.asan/ubsan/...) in a
 # separate, version-suffixed package; without it `clang -fsanitize=...`
 # fails to link. Derive the major version with `clang -dumpversion` (a
 # stable, machine-readable single value, vs parsing --version prose) so
 # this keeps working as the base distro moves clang forward.
 && clangver="$(clang -dumpversion | cut -d. -f1)" \
 && test -n "$clangver" \
 && apt-get install -y --no-install-recommends "libclang-rt-${clangver}-dev" \
 && rm -rf /var/lib/apt/lists/* \
 && gcc --version \
 && g++ --version \
 && clang --version \
 && cmake --version \
 && gdb --version \
 && valgrind --version \
 && cppcheck --version \
 && printf 'int main(){return 0;}\n' > /tmp/t.c \
 && clang -fsanitize=address,undefined /tmp/t.c -o /tmp/t && /tmp/t \
 && gcc -fsanitize=address,undefined /tmp/t.c -o /tmp/tg && /tmp/tg \
 && rm -f /tmp/t.c /tmp/t /tmp/tg

USER runner
