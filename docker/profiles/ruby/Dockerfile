# Ruby profile. Extends the scrutineer runner with a modern Ruby
# interpreter and Bundler so scans of Bundler/RubyGems projects can audit
# or reproduce in-place.
#
# The runner's Debian release (trixie-slim, inherited via FROM) only
# supplies the build toolchain here -- Ruby itself is compiled from source
# by ruby-build at an explicit pinned version, so the interpreter is
# current regardless of what the distro packages.
#
# Built on-demand by the worker; the image tag is content-addressed on
# this Dockerfile's sha so an edit invalidates the cache automatically.
#
#   docker build --build-arg RUNNER_IMAGE=<digest-pinned-runner> \
#     -t scrutineer-profile-ruby:<sha> docker/profiles/ruby

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest
FROM ${RUNNER_IMAGE}

# Explicit, verifiable Ruby version (vs. the fragile distro apt epoch
# string). Bump to pull a newer interpreter; the content-addressed image
# tag invalidates the cache on any edit to this file.
ARG RUBY_VERSION=3.4.9
# ruby-build ref supplies the build recipe for RUBY_VERSION. Pinned to a
# release tag (not master) so the build is reproducible and not exposed to
# a moving branch -- mirrors the rest of the image's pinned tooling. When
# bumping RUBY_VERSION, advance this to a release tag that ships that
# version's definition under share/ruby-build/.
ARG RUBY_BUILD_REF=v20260520

USER root
# ruby-build compiles CRuby from source, so it needs the C toolchain plus
# the headers Ruby links against (openssl, yaml/psych, zlib, readline,
# ffi/fiddle, gmp, ncurses, gdbm). Bundler ships with Ruby since 2.6, so
# installing the interpreter yields `ruby`, `gem`, and `bundle`. The
# toolchain is also what Bundler needs to build native gem extensions when
# a scan reproduces a Gemfile in-place, so it is kept in the final image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        autoconf \
        patch \
        git \
        libssl-dev \
        libyaml-dev \
        zlib1g-dev \
        libreadline-dev \
        libffi-dev \
        libgmp-dev \
        libncurses-dev \
        libgdbm-dev \
 && git clone --depth 1 --branch "${RUBY_BUILD_REF}" \
        https://github.com/rbenv/ruby-build.git /opt/ruby-build \
 && /opt/ruby-build/bin/ruby-build "${RUBY_VERSION}" /usr/local \
 && rm -rf /opt/ruby-build/.git /var/lib/apt/lists/* \
 && ruby --version \
 && bundle --version \
 && /opt/ruby-build/bin/ruby-build --version

# Gems install into the writable, exec-capable workspace mount rather than the
# image's root-owned gem dir (unwritable to the non-root --user runtime) or the
# HOME=/tmp fallback (a noexec, 256 MB tmpfs where native gem .so files can't be
# loaded). /work is host-owned via --userns=keep-id under rootless podman,
# survives hardened mode's --read-only rootfs, and /work/.gem sits outside /src
# so installed gems stay out of the scanned tree.
#
# ruby-build is kept at /opt/ruby-build (on PATH) so a scan can install a
# project-pinned Ruby (a Gemfile `ruby "x.y.z"` directive, a .ruby-version, or
# a gemspec required_ruby_version) when the image's 3.4 does not satisfy it --
# otherwise Bundler refuses to install and the scan would silently lose its
# runtime. The build toolchain above stays in the image for the same reason.
ENV GEM_HOME=/work/.gem \
    PATH=/work/.gem/bin:/opt/ruby-build/bin:$PATH

USER runner
