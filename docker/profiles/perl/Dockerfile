# Perl profile. Extends the scrutineer runner with a full Perl
# interpreter, cpanm, and a C toolchain so scans of CPAN distributions
# can install their dependency set, run the test suite, and build
# reproducers that `use` the project's modules.
#
# The base runner already has perl-base (debian's stripped interpreter
# that dpkg depends on) but no cpan client, no `prove`, and only a thin
# slice of the core library. This installs the full `perl` package from
# Debian -- the distro version tracks upstream closely enough for
# auditing and there is no perl-build/plenv equivalent worth pinning, so
# the version floats with the runner's debian release rather than being
# compiled here.
#
# Built on-demand by the worker; the image tag is content-addressed on
# this Dockerfile's sha so an edit invalidates the cache automatically.
#
#   docker build --build-arg RUNNER_IMAGE=<digest-pinned-runner> \
#     -t scrutineer-profile-perl:<sha> docker/profiles/perl

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest
FROM ${RUNNER_IMAGE}

USER root
# `perl` pulls in the full standard library plus prove/perldoc;
# `cpanminus` is the de-facto installer; `libmodule-build-perl` covers
# Build.PL dists. The C toolchain plus libperl-dev and the common -dev
# headers let XS modules compile when cpanm builds them from source --
# XS is common enough on CPAN that a separate -ext profile (cf. python)
# isn't worth the split.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        perl \
        cpanminus \
        libmodule-build-perl \
        liblocal-lib-perl \
        build-essential \
        libperl-dev \
        libssl-dev \
        zlib1g-dev \
        libexpat1-dev \
 && rm -rf /var/lib/apt/lists/* \
 && perl -v \
 && cpanm --version \
 && prove --version

# Modules install into the writable, exec-capable workspace mount via
# local::lib rather than the image's root-owned vendor dirs (unwritable to
# the non-root --user runtime) or HOME=/tmp (a noexec, 256 MB tmpfs where
# XS .so files can't be loaded). /work is host-owned via --userns=keep-id
# under rootless podman, survives hardened mode's --read-only rootfs, and
# /work/perl5 sits outside /src so installed modules stay out of the
# scanned tree. PERL_CPANM_HOME keeps cpanm's build/work dir on the same
# mount.
ENV PERL_LOCAL_LIB_ROOT=/work/perl5 \
    PERL_MB_OPT="--install_base /work/perl5" \
    PERL_MM_OPT="INSTALL_BASE=/work/perl5" \
    PERL5LIB=/work/perl5/lib/perl5 \
    PERL_CPANM_HOME=/work/.cpanm \
    PATH=/work/perl5/bin:$PATH

USER runner
