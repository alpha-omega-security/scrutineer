# .NET profile. Extends the scrutineer runner with a pinned .NET SDK so
# scans of NuGet/.NET projects can restore dependencies, build, test, and
# reproduce findings in-place.
#
# The SDK is an official, sha512-verified release tarball (the hash
# Microsoft publishes in releases.json), fetched the same way the runner
# installs claude -- not from a moving apt feed. Bump DOTNET_VERSION and
# both checksums together; the content-addressed image tag invalidates the
# cache on any edit to this file.
#
# At runtime the worker builds this on demand (see internal/worker/profile.go:
# EnsureImage), tagging the result scrutineer-profile-dotnet:<dockerfile-sha>
# and passing the configured runner image via --build-arg RUNNER_IMAGE.
#
# To build it manually the way the project does, from the repo root:
#
#   # 1. Build the base runner image locally (Debian/glibc, ships brief etc.):
#   docker build -t scrutineer-runner:local -f Dockerfile.runner .
#
#   # 2. Build this .NET profile on top of that local runner:
#   docker build -t scrutineer-profile-dotnet \
#       -f docker/profiles/dotnet/Dockerfile \
#       --build-arg RUNNER_IMAGE=scrutineer-runner:local \
#       docker/profiles/dotnet
#
#   # 3. Smoke-test it:
#   docker run --rm --entrypoint sh scrutineer-profile-dotnet \
#       -c 'dotnet --version && dotnet --list-sdks'

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest

FROM ${RUNNER_IMAGE}

# .NET 10 LTS. Both arches are listed because the worker may build this on
# an amd64 or arm64 host.
ARG DOTNET_VERSION=10.0.301
ARG DOTNET_SHA512_X64=cfbeec3a3a1d3ad3e168e37a77c4cc26c23125acd84a86d014047da3ecffce4c368a9acac4d7c950a047fa3d98989ce8aea69f8e5842cb6d330e8911e1c335a7
ARG DOTNET_SHA512_ARM64=4ee438b363cb8468930d50b6bdc738a375e2f33b25bfd0c8dcb55853dda7f0fb187693e0f49dfc31556e68320b961a50dcf3b74c1f25abe3a5bd916db607db99

USER root

# Caches live under /opt (a real image dir) rather than $HOME=/tmp, which
# the worker mounts noexec and caps at 256m -- too small for a restored
# package set. Telemetry and the first-run banner are off so they don't
# write to $HOME or muddy scan logs. Dirs are made 1777 below so the host
# uid the scan runs as can write; the container is --rm'd after.
ENV DOTNET_ROOT=/usr/share/dotnet \
    PATH=/usr/share/dotnet:$PATH \
    DOTNET_CLI_HOME=/opt/dotnet-home \
    NUGET_PACKAGES=/opt/nuget \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1

# .NET's runtime depends on ICU (globalization), OpenSSL, zlib, libstdc++,
# and the kerberos lib. libicu-dev carries a stable package name across
# Debian releases and pulls in whichever libicuNN the distro ships, so the
# profile keeps building as the runner base moves between releases.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libicu-dev \
        libssl3 \
        zlib1g \
        libstdc++6 \
        libgcc-s1 \
        libgssapi-krb5-2 \
 && rm -rf /var/lib/apt/lists/* \
 && case "$(dpkg --print-architecture)" in \
        amd64) arch=x64;   sha="${DOTNET_SHA512_X64}" ;; \
        arm64) arch=arm64; sha="${DOTNET_SHA512_ARM64}" ;; \
        *) echo "unsupported architecture: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/dotnet.tar.gz \
        "https://builds.dotnet.microsoft.com/dotnet/Sdk/${DOTNET_VERSION}/dotnet-sdk-${DOTNET_VERSION}-linux-${arch}.tar.gz" \
 && echo "${sha}  /tmp/dotnet.tar.gz" | sha512sum -c - \
 && mkdir -p /usr/share/dotnet \
 && tar -xzf /tmp/dotnet.tar.gz -C /usr/share/dotnet \
 && rm /tmp/dotnet.tar.gz \
 && ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet \
 && install -d -m 1777 /opt/dotnet-home /opt/nuget \
 && dotnet --version \
 && dotnet --list-sdks

USER runner
