# docker pull ghcr.io/alpha-omega-security/scrutineer-runner:latest && \
# docker build -t scrutineer-profile-rust:latest docker/profiles/rust

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest

FROM ${RUNNER_IMAGE}

ARG RUSTUP_VERSION=1.29.0
ARG RUST_STABLE_VERSION=1.96
ARG RUST_NIGHTLY_VERSION=nightly-2026-06-24

USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        ca-certificates \
        autoconf \
        automake \
        libssl-dev \
        libssh-dev \
        git \
        wget \
 && rm -rf /var/lib/apt/lists/*

# Add rust to the container. MIRI_SYSROOT is pinned so the sysroot built
# below as root is the one the runner user finds at scan time (the worker
# runs with HOME=/tmp, which is noexec, so the default ~/.cache/miri
# location would force a rebuild that then fails to execute).
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    MIRI_SYSROOT=/usr/local/miri-sysroot \
    PATH=/usr/local/cargo/bin:$PATH \
    RUSTUP_VERSION=${RUSTUP_VERSION} \
    RUST_STABLE_VERSION=${RUST_STABLE_VERSION} \
    RUST_NIGHTLY_VERSION=${RUST_NIGHTLY_VERSION}

# Install rust
RUN set -eux; \
    \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        'amd64') \
            rustArch='x86_64-unknown-linux-gnu'; \
            rustupSha256='4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10'; \
            ;; \
        'armhf') \
            rustArch='armv7-unknown-linux-gnueabihf'; \
            rustupSha256='124e02253af9128f9e27ea1ac929cbb73cf44cf35469d0f594a1b62f7b71fea1'; \
            ;; \
        'arm64') \
            rustArch='aarch64-unknown-linux-gnu'; \
            rustupSha256='9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792'; \
            ;; \
        'i386') \
            rustArch='i686-unknown-linux-gnu'; \
            rustupSha256='5140e82096f96d1d8077f00eb312648e0e5106d101c9918d086f72cbc69bb3a1'; \
            ;; \
        'ppc64el') \
            rustArch='powerpc64le-unknown-linux-gnu'; \
            rustupSha256='4bfff85bd3967d988e14567aa9cc6ab0ea386f0ffeff0f9f14d23f0103bf1f97'; \
            ;; \
        's390x') \
            rustArch='s390x-unknown-linux-gnu'; \
            rustupSha256='66c2c132428b6b77803facb02cbdf33b89d20c00bd20da142be8cb651f2e7cd8'; \
            ;; \
        *) \
            echo >&2 "unsupported architecture: $arch"; \
            exit 1; \
            ;; \
    esac; \
    \
    url="https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${rustArch}/rustup-init"; \
    wget --progress=dot:giga "$url"; \
    echo "${rustupSha256} *rustup-init" | sha256sum -c -; \
    \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --profile minimal --default-toolchain ${RUST_STABLE_VERSION} --default-host ${rustArch}; \
    rm rustup-init; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
    \
    rustup --version; \
    cargo --version; \
    rustc --version;

# Install the pinned nightly with rust-src (for -Zbuild-std / sanitizers)
# and miri, then run miri's one-time sysroot build so scans don't pay it.
# The bare `nightly` channel is deliberately not installed; select this
# toolchain with `+${RUST_NIGHTLY_VERSION}` (exported via ENV above).
RUN rustup toolchain install ${RUST_NIGHTLY_VERSION} \
        --component rust-src \
        --component miri \
 && cargo +${RUST_NIGHTLY_VERSION} miri setup \
 && chmod -R a+w $RUSTUP_HOME $CARGO_HOME $MIRI_SYSROOT

USER runner
