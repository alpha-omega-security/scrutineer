# docker pull ghcr.io/alpha-omega-security/scrutineer-runner:latest && \
# docker build -t scrutineer-profile-rust:latest docker/profiles/rust

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest
FROM ${RUNNER_IMAGE}

USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        autoconf \
        patch \
        git \
        libssl-dev \
        libyaml-dev \
        zlib1g-dev \
        libreadline-dev \
        libffi-dev \
        libgmp-dev \
        libncurses-dev \
        libgdbm-dev 

# Add rust to the container
USER runner

# Install rust
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
RUN echo 'source $HOME/.cargo/env' >> $HOME/.bashrc
# Install nightly
RUN . $HOME/.cargo/env && rustup toolchain install nightly && rustup default nightly
# Install tools and associated
RUN . $HOME/.cargo/env && \
       rustup component add miri

ENV RUSTFLAGS='-Zsanitizer=address'
ENV ASAN_OPTIONS=detect_leaks=0