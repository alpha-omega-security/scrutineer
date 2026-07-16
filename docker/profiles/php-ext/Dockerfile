# PHP-extension profile.
#
# Ships PHP, built from source with --enable-debug + ASan + UBSan.
#
# At runtime the worker builds this on demand (see internal/worker/profile.go:
# EnsureImage), tagging the result scrutineer-profile-php-ext:<dockerfile-sha>
# and passing the configured runner image via --build-arg RUNNER_IMAGE. The
# build installs its toolchain with apt, so RUNNER_IMAGE must resolve to the
# Debian runner built from ./Dockerfile.runner, not the legacy Alpine image.
#
# To build it manually the way the project does, from the repo root:
#
#   # 1. Build the base runner image locally (Debian/glibc, ships brief etc.):
#   docker build -t scrutineer-runner:local -f Dockerfile.runner .
#
#   # 2. Build this PHP-extension profile on top of that local runner
#   #    (compiles PHP from source with ASan/UBSan; takes several minutes):
#   docker build -t scrutineer-profile-php-ext \
#       -f docker/profiles/php-ext/Dockerfile \
#       --build-arg RUNNER_IMAGE=scrutineer-runner:local \
#       docker/profiles/php-ext
#
#   # 3. Smoke-test it (debug build, sanitizers wired in):
#   docker run --rm --entrypoint sh scrutineer-profile-php-ext \
#       -c 'php -v && composer --version'

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest
ARG PHP_GIT_URL=https://github.com/php/php-src.git
ARG PHP_GIT_REF=php-8.5.6

FROM composer:2.10.2 AS composer

FROM ${RUNNER_IMAGE}
ARG PHP_GIT_URL
ARG PHP_GIT_REF

USER root

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/usr/local/php/bin:/usr/local/php/sbin:$PATH \
    COMPOSER_ALLOW_SUPERUSER=1 \
    USE_ZEND_ALLOC=0 \
    ASAN_OPTIONS="symbolize=1:strict_string_checks=1:detect_stack_use_after_return=1:detect_leaks=0:print_summary=1" \
    UBSAN_OPTIONS="print_stacktrace=1:print_summary=1"

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf bison re2c pkg-config make \
        clang lld llvm \
        gdb strace \
        unzip \
        libxml2-dev libssl-dev libonig-dev libsqlite3-dev zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git clone --depth 1 --branch "${PHP_GIT_REF}" "${PHP_GIT_URL}" php-src
WORKDIR /opt/php-src
RUN ./buildconf --force \
 && ./configure \
        --prefix=/usr/local/php \
        --with-config-file-path=/usr/local/php/etc \
        --with-config-file-scan-dir=/usr/local/php/etc/conf.d \
        --enable-debug \
        --enable-address-sanitizer \
        --enable-undefined-sanitizer \
        --enable-cli \
        --enable-mbstring \
        --enable-pcntl \
        --with-openssl \
        --with-zlib \
 && make -j"$(nproc)" \
 && make install \
 && mkdir -p /usr/local/php/etc/conf.d \
 && cp php.ini-development /usr/local/php/etc/php.ini

COPY <<'INI' /usr/local/php/etc/conf.d/99-scrutineer.ini
zend.assertions=1
phar.readonly=0
memory_limit=-1
date.timezone=UTC
INI

ENV CFLAGS="-fsanitize=address -DZEND_TRACK_ARENA_ALLOC -fsanitize=undefined -fno-sanitize-recover=undefined -fno-sanitize=object-size -fno-omit-frame-pointer -g -O1" \
    CXXFLAGS="-fsanitize=address -DZEND_TRACK_ARENA_ALLOC -fsanitize=undefined -fno-sanitize-recover=undefined -fno-sanitize=object-size -fno-omit-frame-pointer -g -O1" \
    LDFLAGS="-fsanitize=address -fsanitize=undefined"

COPY --from=composer /usr/bin/composer /usr/local/bin/composer

RUN php -v 2>&1 | grep -qE "DEBUG\)" && \
    php-config --configure-options | grep -q "address-sanitizer" && \
    php-config --configure-options | grep -q "undefined-sanitizer" && \
    composer --version && gdb --version

USER runner
