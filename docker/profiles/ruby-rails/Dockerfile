# Ruby on Rails profile.
#
# The `ruby` profile image + Brakeman, the Rails-specific SAST. Built FROM the
# `ruby` profile (not the runner) so the interpreter is literally the same build
# -- no second from-source CRuby compile, and no RUBY_VERSION / ruby-build pin to
# keep in lockstep. Brakeman adds the Rails-shaped vulnerability classes (SQLi,
# XSS, mass-assignment, unsafe deserialization, command injection, SSRF, open
# redirect, CSRF gaps) that the generic semgrep pass does not match.
#
# Auto-selected for repos with a config/application.rb that names
# Rails::Application (the canonical Rails boot file -- see
# internal/worker/profile.go); also selectable via ?profile=ruby-rails.
#
# Built on demand by the worker (EnsureImage): it builds the `ruby` profile
# first and passes its content-addressed tag as BASE_IMAGE, then tags this image
# scrutineer-profile-ruby-rails:<sha>. To build it manually, build the ruby
# profile first and pass it as BASE_IMAGE:
#
#   docker build -t scrutineer-profile-ruby \
#       --build-arg RUNNER_IMAGE=scrutineer-runner:local docker/profiles/ruby
#   docker build -t scrutineer-profile-ruby-rails \
#       -f docker/profiles/ruby-rails/Dockerfile \
#       --build-arg BASE_IMAGE=scrutineer-profile-ruby \
#       docker/profiles/ruby-rails

ARG BASE_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest
FROM ${BASE_IMAGE}

# Brakeman is pure Ruby; pin it like the rest of the image's tooling. Bump as
# new releases land. Kept in lockstep with docker/profiles/ruby-ext (which also
# ships Brakeman); TestBrakemanVersionParity guards the two pins against drift.
ARG BRAKEMAN_VERSION=6.2.1

USER root
# Install Brakeman into the base ruby's default system gem dir (always on
# Gem.path), so the /usr/local/bin/brakeman wrapper resolves at scan time even
# though GEM_HOME points project gems at the ephemeral /work/.gem mount. GEM_HOME
# is inherited from the ruby base, so drop it for the install -- otherwise
# Brakeman would land in /work, which the scan's bind-mount then hides.
# --no-document keeps the image lean. The interpreter, Bundler, build toolchain
# and ruby-build all come from the base image; GEM_HOME/PATH are inherited too.
RUN env -u GEM_HOME gem install --no-document brakeman -v "${BRAKEMAN_VERSION}" \
 && brakeman --version

USER runner
