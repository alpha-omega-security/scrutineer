# BEAM profile. Extends the scrutineer runner with Erlang/OTP, Elixir,
# rebar3, and Hex so scans of Mix (Elixir) or rebar3 (Erlang) projects can
# fetch dependencies, compile, test, and reproduce findings in-place.
#
# Erlang/OTP is compiled from source by kerl at an explicit pinned version,
# so the runtime is current and identical regardless of what the base
# image's distro packages (and so it does not drift with the runner's
# Debian release). Elixir is a precompiled release archive verified by
# sha256; it is BEAM bytecode, so the same archive runs on any arch as
# long as the OTP major matches (27 here). kerl and rebar3 are pinned and
# checksummed too.
#
# At runtime the worker builds this on demand (see internal/worker/profile.go:
# EnsureImage), tagging the result scrutineer-profile-beam:<dockerfile-sha>
# and passing the configured runner image via --build-arg RUNNER_IMAGE. The
# OTP source build takes several minutes.
#
# To build it manually the way the project does, from the repo root:
#
#   # 1. Build the base runner image locally (Debian/glibc, ships brief etc.):
#   docker build -t scrutineer-runner:local -f Dockerfile.runner .
#
#   # 2. Build this BEAM profile on top of that local runner
#   #    (compiles Erlang/OTP from source; takes several minutes):
#   docker build -t scrutineer-profile-beam \
#       -f docker/profiles/beam/Dockerfile \
#       --build-arg RUNNER_IMAGE=scrutineer-runner:local \
#       docker/profiles/beam
#
#   # 3. Smoke-test it:
#   docker run --rm --entrypoint sh scrutineer-profile-beam \
#       -c 'erl -version && elixir --version && rebar3 version'

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest

FROM ${RUNNER_IMAGE}

# Explicit pinned versions. Bump a version and its checksum together; the
# content-addressed image tag invalidates the cache. Elixir's OTP_MAJOR
# must match the OTP version's major (elixir-otp-<major>.zip).
ARG OTP_VERSION=27.3.4.13
ARG KERL_VERSION=4.4.0
ARG KERL_SHA256=1479f5db324ca17f6a1d950a1bb84109b09578de61b94dc6a2f821a96d88f64a
ARG ELIXIR_VERSION=1.20.1
ARG ELIXIR_OTP_MAJOR=27
ARG ELIXIR_SHA256=4b7ddfde964149ab0057fab1ba22c58c69afbff5c52d7894154d38c58b515024
ARG REBAR3_VERSION=3.27.0
ARG REBAR3_SHA256=af85aab41f9fd74bdd6341ebdf6fe9c88077aab9f8eac82371583fa02f2b0bdf

USER root

# Hex's package cache and Mix archives live under /opt (a real image dir)
# rather than $HOME=/tmp, which the worker mounts noexec and caps at 256m.
# BEAM runs bytecode through the VM (a native binary under /opt/otp), so the
# noexec mount does not block compiling or running; only the small 256m cap
# and the per-uid write paths matter, which the /opt redirect handles.
ENV PATH=/opt/otp/bin:/opt/elixir/bin:$PATH \
    MIX_HOME=/opt/mix \
    HEX_HOME=/opt/hex

# Build toolchain for the OTP source build (autoconf/m4, ncurses for the
# shell, openssl for the crypto/ssl apts Hex needs) plus unzip for the
# Elixir archive. Kept lean: the GUI apps (wx, observer, debugger) and
# Java interface are configured out below, so their dev libs aren't needed.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential autoconf m4 \
        libncurses-dev libssl-dev \
        unzip \
 && rm -rf /var/lib/apt/lists/* \
 # kerl: pinned single script that builds OTP from source.
 && curl -fsSL -o /usr/local/bin/kerl \
        "https://raw.githubusercontent.com/kerl/kerl/${KERL_VERSION}/kerl" \
 && echo "${KERL_SHA256}  /usr/local/bin/kerl" | sha256sum -c - \
 && chmod +x /usr/local/bin/kerl \
 # Build and install Erlang/OTP, skipping the GUI/Java components to keep
 # the build fast and the image lean. KERL_BASE_DIR is set explicitly (kerl
 # otherwise defaults it to $HOME/.kerl) so the build artifacts land in a
 # known path that is deleted afterwards, instead of depending on $HOME
 # being set during the image build.
 && export KERL_BASE_DIR=/var/tmp/kerl \
 && KERL_CONFIGURE_OPTIONS="--without-wx --without-javac --without-debugger --without-observer --without-et --without-megaco --without-jinterface" \
        kerl build "${OTP_VERSION}" "${OTP_VERSION}" \
 && kerl install "${OTP_VERSION}" /opt/otp \
 && rm -rf /var/tmp/kerl \
 # Elixir precompiled release (BEAM bytecode, arch-independent).
 && curl -fsSL -o /tmp/elixir.zip \
        "https://github.com/elixir-lang/elixir/releases/download/v${ELIXIR_VERSION}/elixir-otp-${ELIXIR_OTP_MAJOR}.zip" \
 && echo "${ELIXIR_SHA256}  /tmp/elixir.zip" | sha256sum -c - \
 && unzip -q /tmp/elixir.zip -d /opt/elixir \
 && rm /tmp/elixir.zip \
 # rebar3 self-contained escript.
 && curl -fsSL -o /usr/local/bin/rebar3 \
        "https://github.com/erlang/rebar3/releases/download/${REBAR3_VERSION}/rebar3" \
 && echo "${REBAR3_SHA256}  /usr/local/bin/rebar3" | sha256sum -c - \
 && chmod +x /usr/local/bin/rebar3 \
 # Install Hex and the Mix rebar shim into MIX_HOME so `mix deps.get`
 # works offline-ish at scan time; HEX_HOME is the writable package cache.
 && install -d -m 1777 /opt/hex \
 && install -d -m 0755 /opt/mix \
 && mix local.hex --force \
 && mix local.rebar --force \
 && chmod -R a+rX /opt/mix \
 && erl -noshell -eval 'io:format("OTP ~s~n", [erlang:system_info(otp_release)]), halt().' \
 && elixir --version \
 && rebar3 version

# The runner image has no UTF-8 locale, so the BEAM defaults to latin1
# filename encoding and Elixir warns it "may malfunction". +fnu tells the
# VM to treat filenames as UTF-8, which is what Elixir expects. (Placed
# after the build so editing it does not rebuild the OTP-from-source layer
# in local caches.)
ENV ELIXIR_ERL_OPTIONS="+fnu"

USER runner
