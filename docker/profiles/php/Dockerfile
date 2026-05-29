# PHP profile.

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest

FROM composer:2.9.8 AS composer

FROM ${RUNNER_IMAGE}

ARG PHP_VERSION=8.4.21-3+0~20260514.49+debian12~1.gbp45ccaf
# php8.4-redis is the only PECL pkg whose sury build differs across arches.
ARG TARGETARCH

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
        gnupg lsb-release \
 && install -d -m 0755 /etc/apt/keyrings \
 && curl -fsSL https://packages.sury.org/php/apt.gpg \
        -o /etc/apt/keyrings/sury-php.gpg \
 && chmod go+r /etc/apt/keyrings/sury-php.gpg \
 && echo "deb [signed-by=/etc/apt/keyrings/sury-php.gpg] https://packages.sury.org/php/ $(lsb_release -sc) main" \
        > /etc/apt/sources.list.d/sury-php.list \
 && apt-get update \
 && case "${TARGETARCH}" in \
      amd64) PHP_REDIS=6.3.0-2+0~20251204.66+debian12~1.gbpd148c3 ;; \
      arm64) PHP_REDIS=6.3.0-1+0~20251120.64+debian12~1.gbpd464c1 ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && apt-get install -y --no-install-recommends \
        php8.4-cli=${PHP_VERSION} \
        php8.4-common=${PHP_VERSION} \
        php8.4-dev=${PHP_VERSION} \
        php8.4-bcmath=${PHP_VERSION} \
        php8.4-bz2=${PHP_VERSION} \
        php8.4-curl=${PHP_VERSION} \
        php8.4-dba=${PHP_VERSION} \
        php8.4-gd=${PHP_VERSION} \
        php8.4-gmp=${PHP_VERSION} \
        php8.4-intl=${PHP_VERSION} \
        php8.4-ldap=${PHP_VERSION} \
        php8.4-mbstring=${PHP_VERSION} \
        php8.4-mysql=${PHP_VERSION} \
        php8.4-opcache=${PHP_VERSION} \
        php8.4-pgsql=${PHP_VERSION} \
        php8.4-snmp=${PHP_VERSION} \
        php8.4-soap=${PHP_VERSION} \
        php8.4-sqlite3=${PHP_VERSION} \
        php8.4-tidy=${PHP_VERSION} \
        php8.4-xml=${PHP_VERSION} \
        php8.4-xsl=${PHP_VERSION} \
        php8.4-zip=${PHP_VERSION} \
        php8.4-amqp=2.1.2-7+0~20260519.35+debian12~1.gbpff72ce \
        php8.4-apcu=5.1.28-1+0~20260518.58+debian12~1.gbp5969fc \
        php8.4-grpc=1.80.0-1+0~20260331.43+debian12~1.gbpa12d0b \
        php8.4-igbinary=3.2.16-6+0~20260330.57+debian12~1.gbp1eff65 \
        php8.4-imagick=3.8.1-1+0~20251220.54+debian12~1.gbpde1d95 \
        php8.4-imap=3:1.0.3-2+0~20251203.6+debian12~1.gbp0bf79d \
        php8.4-memcached=3.4.0-1+0~20260331.75+debian12~1.gbp3fb0c0 \
        php8.4-mongodb=2.1.4-4+0~20251203.65+debian12~1.gbp6dbd50 \
        php8.4-msgpack=1:3.0.0-2+0~20251124.50+debian12~1.gbp330ae0 \
        php8.4-protobuf=4.33.2-1+0~20251220.29+debian12~1.gbp93d410 \
        php8.4-rdkafka=6.0.5-2+0~20251124.9+debian12~1.gbpdc15a9 \
        php8.4-redis=${PHP_REDIS} \
        php8.4-yaml=2.3.0-2+0~20251124.42+debian12~1.gbp29d390 \
        build-essential autoconf libtool pkg-config re2c \
 && rm -rf /var/lib/apt/lists/*

COPY --from=composer /usr/bin/composer /usr/local/bin/composer

ARG PIE_VERSION=1.4.5
ARG PIE_SHA256=6cdc03b8861b290d4e2a61147082a9f21dac5af572c66f0d121f266361499662
RUN install -d /usr/local/lib/pie && \
    curl -fsSL -o /usr/local/lib/pie/pie.phar \
        "https://github.com/php/pie/releases/download/${PIE_VERSION}/pie.phar" && \
    echo "${PIE_SHA256}  /usr/local/lib/pie/pie.phar" | sha256sum -c - && \
    chmod +x /usr/local/lib/pie/pie.phar

# pie unpacks tarballs under $HOME/.pie and runs configure/make there. The
# worker sets HOME=/tmp, but /tmp is mounted noexec so unpacked shell helpers
# (shtool, libtool) won't execute. Wrapper redirects HOME to a real
# (exec-capable) image dir; 1777 so any host uid can write.
RUN install -d -m 1777 /opt/pie-home
COPY <<'WRAP' /usr/local/bin/pie
#!/bin/sh
exec env HOME=/opt/pie-home /usr/local/lib/pie/pie.phar "$@"
WRAP
RUN chmod +x /usr/local/bin/pie

# memory_limit: Avoid OOMs from default limits
# date.timezone: otherwise every CLI run prints an implicit-tz warning that leaks into findings.
# phar.readonly: lets a PoC build a hostile phar to confirm a deserialization sink, not just read one.
COPY <<'INI' /etc/php/8.4/cli/conf.d/99-scrutineer.ini
zend.assertions=0
phar.readonly=0
memory_limit=-1
date.timezone=UTC
INI

# pie writes the built .so into the extension dir and an enable-ini into conf.d.
# The runtime user is the host's uid (docker --user $(id -u):$(id -g)), not the
# image's runner, so make both paths writable by any uid. Container is ephemeral
# and --rm'd after the scan, so the blast radius of a malicious write is zero.
RUN chmod 1777 /usr/lib/php/20240924 /etc/php/8.4/cli/conf.d

RUN php -v && composer --version && pie --version

USER runner
