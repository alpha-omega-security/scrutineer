# PHP profile.

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest

FROM composer:2.9.8 AS composer

FROM ${RUNNER_IMAGE}

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
 && apt-get install -y --no-install-recommends \
        php8.4-cli php8.4-common php8.4-dev \
        php8.4-amqp php8.4-apcu php8.4-bcmath php8.4-bz2 php8.4-curl \
        php8.4-dba php8.4-gd php8.4-gmp php8.4-grpc php8.4-igbinary \
        php8.4-imagick php8.4-imap php8.4-intl php8.4-ldap \
        php8.4-mbstring php8.4-memcached php8.4-mongodb php8.4-msgpack \
        php8.4-mysql php8.4-opcache php8.4-pgsql php8.4-protobuf \
        php8.4-rdkafka php8.4-redis php8.4-snmp php8.4-soap \
        php8.4-sqlite3 php8.4-tidy php8.4-xml php8.4-xsl \
        php8.4-yaml php8.4-zip \
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
