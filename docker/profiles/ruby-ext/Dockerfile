# Ruby native-extension profile.
#
# Ships Ruby built from source with ASan + UBSan, for scanning gems that
# include a compiled native extension (C/C++, or Rust via rb-sys/Cargo).
# Extensions the sanitized interpreter compiles (via mkmf/extconf, rake
# compile, or gem install) inherit the sanitizer flags through rbconfig and
# the exported CFLAGS/LDFLAGS, so a reproducer that drives the extension from
# Ruby surfaces the memory-safety and UB bugs the static read can only guess
# at. This mirrors php-ext / python-ext.
#
# It is a deliberate SUPERSET of the `ruby` profile, not a C-only profile: a
# native gem is mostly Ruby wrapping a small native core, so this image also
# ships a stock interpreter and the full Ruby toolchain, and its PROFILE.md
# keeps the whole Ruby-level audit (incl. metaprogramming) and adds the native
# playbook. Routing a gem here therefore never loses Ruby coverage — see the
# ruby-ext registry comment in internal/worker/profile.go.
#
# Auto-selected for repos that declare a native extension (gemspec
# spec.extensions, ext/<name>/extconf.rb, or ext/<name>/Cargo.toml — see
# internal/worker/profile.go); also selectable by name via ?profile=ruby-ext.
#
# Built on demand by the worker (EnsureImage), tagged
# scrutineer-profile-ruby-ext:<dockerfile-sha>, RUNNER_IMAGE wired via
# --build-arg. The toolchain installs with apt, so RUNNER_IMAGE must resolve
# to the Debian runner built from ./Dockerfile.runner.
#
# To build it manually the way the project does, from the repo root:
#
#   # 1. Build the base runner image locally (Debian/glibc, ships brief etc.):
#   docker build -t scrutineer-runner:local -f Dockerfile.runner .
#
#   # 2. Build this Ruby-extension profile on top of that local runner
#   #    (compiles Ruby from source with ASan/UBSan; takes several minutes):
#   docker build -t scrutineer-profile-ruby-ext \
#       -f docker/profiles/ruby-ext/Dockerfile \
#       --build-arg RUNNER_IMAGE=scrutineer-runner:local \
#       docker/profiles/ruby-ext
#
#   # 3. Smoke-test it (the default `ruby` is the sanitized build):
#   docker run --rm --entrypoint sh scrutineer-profile-ruby-ext \
#       -c 'ruby -v && ruby -e "p RbConfig::CONFIG[\"CFLAGS\"]"'

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest
ARG RUBY_GIT_URL=https://github.com/ruby/ruby.git
# Pin to the same release the `ruby` profile builds (RUBY_VERSION=3.4.9), so
# the language-level audit behaves identically across the two profiles. Ruby
# release tags use underscores (v3_4_9). Bump in lockstep with the ruby
# profile; the content-addressed image tag invalidates the cache on any edit.
ARG RUBY_GIT_REF=v3_4_9
# Second ASan interpreter, Ruby 4.0. 4.0.x tags use dots (v4.0.6); 3.4.x use underscores (v3_4_9).
ARG RUBY_GIT_REF_40=v4.0.6
# ruby-build (kept on PATH) lets a scan install a project-pinned STOCK Ruby for
# a Ruby-level reproducer when the gem targets a version other than 3.4. Same
# pin as the ruby / ruby-rails profiles.
ARG RUBY_BUILD_REF=v20260520

# Brakeman, the Rails-specific SAST, so ruby-ext is a superset of ruby-rails
# too: a Rails app that also ships a native extension matches ruby-ext first
# (it precedes ruby-rails in detection) and must still get Rails SAST. Pure
# Ruby; pin like the rest of the tooling. Kept in lockstep with the ruby-rails
# profile -- TestBrakemanVersionParity guards the two pins against drift.
ARG BRAKEMAN_VERSION=6.2.1

# Rust toolchain pins, kept in lockstep with docker/profiles/rust so rb-sys
# gems build the same way here. Nightly + rust-src is what -Zsanitizer /
# -Zbuild-std need to instrument the Rust side of the Ruby<->Rust boundary.
ARG RUSTUP_VERSION=1.29.0
ARG RUST_STABLE_VERSION=1.96
ARG RUST_NIGHTLY_VERSION=nightly-2026-06-24

FROM ${RUNNER_IMAGE}
ARG RUBY_GIT_URL
ARG RUBY_GIT_REF
ARG RUBY_GIT_REF_40
ARG RUBY_BUILD_REF
ARG BRAKEMAN_VERSION
ARG RUSTUP_VERSION
ARG RUST_STABLE_VERSION
ARG RUST_NIGHTLY_VERSION

USER root

# The sanitized interpreter is the default `ruby` (fail toward instrumentation:
# a plain `bundle install && rake compile` is instrumented without the agent
# opting in). The stock apt ruby stays at /usr/bin/ruby for fast Ruby-level
# reading and as the valgrind target (ASan and valgrind cannot be combined).
# GEM_HOME mirrors the ruby profile: gems install into the writable, exec-capable
# /work mount, not the root-owned image gem dir or the noexec /tmp fallback.
#
# ASAN_OPTIONS/UBSAN_OPTIONS here are the BUILD-SAFE variant. The from-source
# interpreter build below runs an ASan/UBSan-instrumented miniruby for codegen,
# and that interpreter — deliberately compiled WITHOUT -fno-sanitize-recover —
# trips benign UB and leaks freely during those short-lived runs. detect_leaks=0
# and halt_on_error=0 keep that benign, so `make` doesn't abort. The heavier
# scan-time options (abort_on_error, RUBY_FREE_AT_EXIT) are set LAST, after the
# build, so they scope to the gem scan — mirroring how the extension CFLAGS
# further down are set after the interpreter build.
ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/usr/local/ruby-asan/bin:/work/.gem/bin:/opt/ruby-build/bin:/usr/local/cargo/bin:$PATH \
    GEM_HOME=/work/.gem \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    RUST_NIGHTLY_VERSION=${RUST_NIGHTLY_VERSION} \
    ASAN_OPTIONS="detect_leaks=0:detect_stack_use_after_return=0" \
    UBSAN_OPTIONS="halt_on_error=0"

# Build toolchain + the headers Ruby links against (openssl, yaml/psych, zlib,
# ffi, gmp, readline, ncurses, gdbm). gdb/strace/valgrind for triage. The apt
# `ruby` is the BASERUBY both from-source builds pin (--with-baseruby) and the
# stock interpreter for fast reads / valgrind; ruby-dev lets it build a gem
# in-place for a valgrind run. wget fetches rustup-init.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf bison patch git pkg-config wget ca-certificates \
        gdb strace valgrind \
        ruby ruby-dev \
        libssl-dev libyaml-dev zlib1g-dev libffi-dev libgmp-dev \
        libreadline-dev libncurses-dev libgdbm-dev \
 && rm -rf /var/lib/apt/lists/*

# ruby-build (on PATH) installs a project-pinned STOCK Ruby at scan time for a
# Ruby-level reproducer when the gem targets a version the ASan interpreters
# (3.4 and 4.0) do not cover. The build deps above are kept so ruby-build can
# compile.
RUN git clone --depth 1 --branch "${RUBY_BUILD_REF}" \
        https://github.com/rbenv/ruby-build.git /opt/ruby-build \
 && rm -rf /opt/ruby-build/.git \
 && /opt/ruby-build/bin/ruby-build --version

# Both sanitized interpreters come from this one script; it is inlined so the Dockerfile-hashed image
# tag (profile.go imageTag) covers it. The kept trees /opt/ruby-src* are the C-API reference for triage.
COPY <<'SH' /usr/local/bin/build-asan-ruby
#!/bin/sh
# Build one ASan+UBSan Ruby (<git-ref> <install-prefix> <kept-src-dir>) and make its mkmf
# extension builds instrumented. Shared by both interpreters so the sanitizer flags cannot drift.
#  - cppflags sanitizers reach the interpreter AND, via rbconfig CPPFLAGS, every mkmf extension build.
#  - -fno-sanitize=alignment: the interpreter's unaligned packed-struct access is benign; re-enabled for extensions below.
#  - no -fno-sanitize-recover: the interpreter must survive its own UB or `make` (runs miniruby) aborts; set for extensions below.
#  - optflags=-O1 -g: readable ASan traces without the -O0 slowdown.
#  - --with-baseruby=/usr/bin/ruby: codegen on the apt Ruby, not the ASan 3.4 that PATH finds after the first build.
#  - GC vs ASan fake stack (issue-ruby-profiles.md #1): if fiber-heavy code crashes inside the GC, add --with-coroutine=copy.
set -eux

ref="$1"
prefix="$2"
src="$3"

git clone --depth 1 --branch "$ref" "$RUBY_GIT_URL" "$src"
cd "$src"
./autogen.sh
./configure \
    --prefix="$prefix" \
    --with-baseruby=/usr/bin/ruby \
    --disable-install-doc \
    cppflags="-fsanitize=address -fsanitize=undefined -fno-sanitize=alignment -fno-omit-frame-pointer -DRUBY_DEBUG=1" \
    optflags="-O1 -g" \
    debugflags="-g3" \
    LDFLAGS="-fsanitize=address -fsanitize=undefined"
# configure quietly downgrades a too-old baseruby to HAVE_BASERUBY=no and lets `make` fail later; stop here instead.
grep -q '^HAVE_BASERUBY = yes' Makefile || { echo "ruby-ext: /usr/bin/ruby is below $ref's BASERUBY minimum"; exit 1; }
make -j"$(nproc)"
make install
"$prefix/bin/ruby" -v

# Rewrite the RECORDED cppflags in this interpreter's rbconfig so extension
# compiles get the alignment check back ON and -fno-sanitize-recover=undefined
# (UB aborts = evidence). The interpreter binary is already built and stays
# quiet. Aborts loudly if the entry shape ever changes.
"$prefix/bin/ruby" -rrbconfig -e 'path=$LOADED_FEATURES.grep(/rbconfig\.rb$/).first; cfg=File.read(path); cfg.sub!(/^(\s*CONFIG\["cppflags"\] = ".*)"\s*$/){ $1.gsub(" -fno-sanitize=alignment","") + " -fno-sanitize-recover=undefined\"" } or abort("ruby-ext: cppflags entry not found in #{path}"); File.write(path, cfg)'
"$prefix/bin/ruby" -e 'f=RbConfig::CONFIG["CPPFLAGS"]; abort("ruby-ext: alignment still off for extensions: #{f}") if f.include?("-fno-sanitize=alignment"); abort("ruby-ext: -fno-sanitize-recover missing for extensions: #{f}") unless f.include?("-fno-sanitize-recover=undefined"); STDERR.puts "ruby-ext: extension CPPFLAGS =>#{f}"'

# Prove the rewrite reaches a real mkmf extension compile: build a throwaway
# extension and grep the ACTUAL compiler line. If the cppflags->CPPFLAGS chain
# ever fails to reach mkmf, the image build fails here instead of silently
# shipping uninstrumented extensions.
d="$(mktemp -d)"
mkdir -p "$d/probe"
cd "$d/probe"
printf 'require "mkmf"\ncreate_makefile("probe")\n' > extconf.rb
printf 'void Init_probe(void){}\n' > probe.c
"$prefix/bin/ruby" extconf.rb
make V=1 > compile.log 2>&1 || { cat compile.log; exit 1; }
grep -Eq -- '-fno-sanitize-recover=undefined' compile.log \
    || { echo "ruby-ext: extension compile is missing -fno-sanitize-recover=undefined"; cat compile.log; exit 1; }
if grep -Eq -- '-fno-sanitize=alignment' compile.log; then
    echo "ruby-ext: extension compile still carries -fno-sanitize=alignment (must be re-enabled for extensions)"
    cat compile.log
    exit 1
fi
cd /
rm -rf "$d"
SH
RUN chmod +x /usr/local/bin/build-asan-ruby \
 && build-asan-ruby "${RUBY_GIT_REF}"    /usr/local/ruby-asan    /opt/ruby-src
RUN build-asan-ruby "${RUBY_GIT_REF_40}" /usr/local/ruby-asan-40 /opt/ruby-src-40

# Per-interpreter shims (ruby-shims): GEM_HOME pinned, its bin first on PATH, tools resolved from the prefix or
# that GEM_HOME, so a session on one interpreter never loads another's gems. Select one by prepending its shims dir.
COPY <<'SHIMS' /usr/local/bin/ruby-shims
#!/bin/sh
# ruby-shims <asan|plain> <prefix> <gem-home> [shims-dir]: write <shims-dir>/{ruby,gem,bundle,bundler,rake}
# (default <prefix>/shims); `plain` also unsets the session's sanitizer CFLAGS/CXXFLAGS/LDFLAGS.
set -eu
case $# in 3|4) ;; *) echo "usage: ruby-shims <asan|plain> <prefix> <gem-home> [shims-dir]" >&2; exit 2 ;; esac
mode=$1 prefix=$2 gemhome=$3 shims=${4:-$2/shims}
case $mode in
    asan)  clear= ;;
    plain) clear='unset CFLAGS CXXFLAGS LDFLAGS' ;;
    *)     echo "ruby-shims: mode must be asan or plain" >&2; exit 2 ;;
esac
mkdir -p "$shims"
for t in ruby gem bundle bundler rake; do
    cat > "$shims/$t" <<SHIM
#!/bin/sh
$clear
export GEM_HOME=$gemhome
export PATH=$shims:$prefix/bin:$gemhome/bin:\$PATH
for x in $prefix/bin/$t $gemhome/bin/$t; do [ -x "\$x" ] && exec "\$x" "\$@"; done
echo "ruby-shims: $t is not installed for $prefix; gem install it through $shims/gem" >&2; exit 127
SHIM
    chmod +x "$shims/$t"
done
SHIMS
RUN chmod +x /usr/local/bin/ruby-shims \
 && ruby-shims asan  /usr/local/ruby-asan-40 /work/.gem-40 \
 && ruby-shims plain /usr /work/.gem-stock /usr/local/ruby-stock/shims \
 && ln -s /usr/local/ruby-asan-40/shims/ruby /usr/local/bin/ruby4

# Rust for rb-sys / Cargo-native gems. Minimal stable (default) + the pinned
# nightly with rust-src so the Rust side of the boundary can be rebuilt with
# -Zsanitizer=address -Zbuild-std to match the ASan interpreter. Miri is NOT
# shipped here (it cannot cross the FFI boundary that is the whole point of a
# native extension); use the dedicated `rust` profile for isolated unsafe-Rust
# Miri runs. amd64/arm64 only — the realistic runtime arches; extend the case
# from docker/profiles/rust/Dockerfile if you need more.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        'amd64') rustArch='x86_64-unknown-linux-gnu'; rustupSha256='4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10';; \
        'arm64') rustArch='aarch64-unknown-linux-gnu'; rustupSha256='9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792';; \
        *) echo >&2 "unsupported architecture for rust: $arch"; exit 1;; \
    esac; \
    url="https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${rustArch}/rustup-init"; \
    wget --progress=dot:giga --timeout=30 --tries=4 "$url"; \
    echo "${rustupSha256} *rustup-init" | sha256sum -c -; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --profile minimal --default-toolchain ${RUST_STABLE_VERSION} --default-host ${rustArch}; \
    rm rustup-init; \
    /usr/local/cargo/bin/rustup toolchain install ${RUST_NIGHTLY_VERSION} --component rust-src; \
    chmod -R a+w "$RUSTUP_HOME" "$CARGO_HOME"; \
    /usr/local/cargo/bin/rustc --version

# Brakeman (pure-Ruby Rails SAST) so ruby-ext is a superset of ruby-rails too:
# a Rails app that also ships a native extension matches ruby-ext first and must
# still get Rails SAST (see the ruby-ext registry comment in
# internal/worker/profile.go). Install with the STOCK apt ruby into its default
# system gem dir (always on that ruby's Gem.path), with the wrapper forced onto
# /usr/local/bin (on PATH): Brakeman then runs under the stock, not the ASan,
# interpreter. GEM_HOME points at the ephemeral /work mount, so drop it for this
# layer -- otherwise Brakeman would land in /work, which the scan's mount hides.
RUN env -u GEM_HOME /usr/bin/gem install --no-document -n /usr/local/bin \
        brakeman -v "${BRAKEMAN_VERSION}" \
 && brakeman --version

# Conservative-GC valgrind suppressions (memcheck on the STOCK ruby, never the
# ASan one). A starting set — extend it as real runs surface GC false positives.
COPY ruby.supp /usr/local/share/ruby-ext/ruby.supp

# Sanitizer flags for build systems that DO read the environment — chiefly the
# cc-rs crate that rb-sys / Cargo-native gems use to compile their C/C++ shim.
# NOTE: these do NOT reach Ruby's own mkmf extension builds — mkmf hard-assigns
# CFLAGS in its generated Makefile, so `make` ignores the environment; mkmf gets
# its sanitizer + -fno-sanitize-recover flags from the rbconfig patch above.
# -fno-sanitize-recover=undefined makes UB abort (the abort is the evidence).
ENV CFLAGS="-fsanitize=address -fsanitize=undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g -O1" \
    CXXFLAGS="-fsanitize=address -fsanitize=undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g -O1" \
    LDFLAGS="-fsanitize=address -fsanitize=undefined"

# The install dir and Rust caches must stay writable for the non-root host uid
# the scan runs as, so mkmf/cargo can build extensions in place. The container
# is ephemeral and --rm'd after the scan, so the blast radius is zero.
RUN chmod -R a+rwX /usr/local/ruby-asan /usr/local/ruby-asan-40 "$RUSTUP_HOME" "$CARGO_HOME" \
 && ruby -v 2>&1 | grep -q "ruby 3.4" \
 && ruby4 -v 2>&1 | grep -q "ruby 4.0" \
 && test "$(/usr/local/ruby-asan-40/shims/gem env gemdir)" = /work/.gem-40 \
 && /usr/local/ruby-asan-40/shims/bundle --version \
 && /usr/local/ruby-asan-40/shims/rake --version \
 && test "$(/usr/local/ruby-stock/shims/gem env gemdir)" = /work/.gem-stock \
 && /usr/local/ruby-stock/shims/ruby -v \
 && ldd /usr/local/ruby-asan/bin/ruby | grep -q libasan \
 && ldd /usr/local/ruby-asan-40/bin/ruby | grep -q libasan \
 && /usr/bin/ruby -v && valgrind --version && cargo --version

# Runtime (gem-scan) sanitizer options — set LAST, after every build and verify
# step above. abort_on_error and RUBY_FREE_AT_EXIT are fatal/heavy scan-time
# signals that MUST NOT be live during the build (the build-safe ENV near the
# top omits them): the instrumented miniruby leaks and tears down on every
# short-lived codegen run, so having them here during `make` aborted healthy
# runs and produced the original exit-2. They belong to the scan, not the build.
#
# halt_on_error stays 0 while abort_on_error=1: a gem's extension is compiled
# with -fno-sanitize-recover=undefined (via the patched rbconfig above), so its
# UB takes the compiled-in abort handler and, with abort_on_error=1, exits with
# SIGABRT — the same crash signature as an ASan finding. The interpreter, built
# WITHOUT -fno-sanitize-recover, uses the recoverable handler: with
# halt_on_error=0 it prints-and-continues and never reaches abort, so its benign
# UB can't kill the scan. (halt_on_error=1 would abort the scan on the
# interpreter's own benign UB — the opposite of what we want.)
ENV RUBY_FREE_AT_EXIT=1 \
    ASAN_OPTIONS="detect_leaks=0:detect_stack_use_after_return=0:abort_on_error=1:symbolize=1:print_summary=1" \
    UBSAN_OPTIONS="print_stacktrace=1:print_summary=1:halt_on_error=0:abort_on_error=1"

USER runner
