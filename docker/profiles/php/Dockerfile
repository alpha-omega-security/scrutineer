# PHP profile. Extends the scrutineer runner with a PHP interpreter so
# scans of Composer projects can audit or reproduce in-place.
#
# Built on demand by the worker; the image tag is content-addressed on
# this Dockerfile's sha so an edit invalidates the cache automatically.
#
#   docker build --build-arg RUNNER_IMAGE=<digest-pinned-runner> \
#     -t scrutineer-profile-php:<sha> docker/profiles/php

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest
FROM ${RUNNER_IMAGE}

USER root
RUN apk add --no-cache \
        php84=8.4.21-r0 \
        php84-phar=8.4.21-r0 \
        php84-openssl=8.4.21-r0 \
        php84-mbstring=8.4.21-r0 \
        php84-tokenizer=8.4.21-r0 \
        php84-curl=8.4.21-r0 \
        php84-dom=8.4.21-r0 \
        php84-simplexml=8.4.21-r0 \
        php84-xml=8.4.21-r0 \
        php84-xmlwriter=8.4.21-r0 \
        php84-fileinfo=8.4.21-r0 \
        php84-iconv=8.4.21-r0 \
    && ln -sf /usr/bin/php84 /usr/local/bin/php

USER runner
