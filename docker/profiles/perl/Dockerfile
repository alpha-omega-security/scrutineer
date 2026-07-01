# Perl profile. Extends the scrutineer runner with a full Perl
# interpreter, cpanm-bootstrapped cpm, and a C toolchain so scans of
# CPAN distributions can install dependencies, run the test suite, and
# build reproducers that `use` the project's modules.
#
# The base runner already has perl-base (debian's stripped interpreter
# that dpkg depends on) but no CPAN client, no `prove`, and only a thin
# slice of the core library. This installs the full `perl` package from
# Debian -- the distro version tracks upstream closely enough for
# auditing and there is no perl-build/plenv equivalent worth pinning, so
# the version floats with the runner's Debian release rather than being
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

ENV DEBIAN_FRONTEND=noninteractive

# `perl` pulls in the full standard library plus prove/perldoc.
# cpanminus is only the bootstrap path for cpm; scans should use cpm
# itself as the actively-maintained installer. The C toolchain plus a
# broad set of headers keeps common XS modules on system libs instead of
# falling back to Alien::* downloads from non-allowlisted hosts.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        perl \
        cpanminus \
        libmodule-build-perl \
        liblocal-lib-perl \
        build-essential \
        pkg-config \
        libperl-dev \
        libssl-dev \
        zlib1g-dev \
        libexpat1-dev \
        libxml2-dev \
        libxslt1-dev \
        libsqlite3-dev \
        default-libmysqlclient-dev \
        libpq-dev \
        libgmp-dev \
        libbz2-dev \
        liblzma-dev \
        libzstd-dev \
        libffi-dev \
        libpcre2-dev \
        libdb-dev \
 && cpanm --mirror https://cpan.metacpan.org --mirror-only --notest App::cpm \
 && rm -rf /var/lib/apt/lists/* \
 && perl -v \
 && cpm --version \
 && prove --version

# Modules install into the writable, exec-capable workspace mount via
# local::lib rather than the image's root-owned vendor dirs (unwritable to
# the non-root --user runtime) or HOME=/tmp (a noexec, 256 MB tmpfs where
# XS .so files can't be loaded). cpm's build dir must also live on /work,
# but it has no env var for that, so the profile guide always passes
# `--home /work/.perl-cpm` explicitly.
ENV PERL_LOCAL_LIB_ROOT=/work/perl5 \
    PERL_MB_OPT="--install_base /work/perl5" \
    PERL_MM_OPT="INSTALL_BASE=/work/perl5" \
    PERL5LIB=/work/perl5/lib/perl5 \
    PATH=/work/perl5/bin:$PATH \
    PERL_MM_USE_DEFAULT=1 \
    NONINTERACTIVE_TESTING=1 \
    AUTOMATED_TESTING=1

USER runner
