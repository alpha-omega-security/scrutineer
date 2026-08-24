# OCaml profile: opam, a compiled 5.x switch, dune, and C headers for the
# common conf-* depexts. opam is the upstream static binary (trixie's 2.3.0
# predates CVE-2026-57825). Built on demand by the worker; compiling the
# switch takes several minutes.

ARG RUNNER_IMAGE=ghcr.io/alpha-omega-security/scrutineer-runner:latest
FROM ${RUNNER_IMAGE}

ARG OPAM_VERSION=2.5.2
ARG OPAM_SHA256_X86_64=edfca2630c373b44b7ee1c2f81cd8dcf67468d0db57d6c02158de553ac63dbd4
ARG OPAM_SHA256_ARM64=c4106ece84bcb60c68342573d2d6b4f0d6770ee088015c2216adc83d8854dcf9
ARG OCAML_VERSION=5.5.0

USER root

ENV DEBIAN_FRONTEND=noninteractive

# OPAMROOT under /opt because $HOME=/tmp is a noexec 256 MB tmpfs at scan time.
ENV OPAMROOT=/opt/opam \
    OPAMYES=1 \
    OPAMCONFIRMLEVEL=unsafe-yes \
    OPAMROOTISOK=1 \
    OPAMSWITCH=default \
    OPAMERRLOGLEN=0 \
    PATH=/opt/opam/default/bin:$PATH \
    CAML_LD_LIBRARY_PATH=/opt/opam/default/lib/stublibs:/opt/opam/default/lib/ocaml/stublibs:/opt/opam/default/lib/ocaml \
    OCAML_TOPLEVEL_PATH=/opt/opam/default/lib/toplevel

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        m4 \
        rsync \
        unzip \
        libgmp-dev \
        libssl-dev \
        zlib1g-dev \
        libzstd-dev \
        libsqlite3-dev \
        libpcre2-dev \
        libev-dev \
        libffi-dev \
 && rm -rf /var/lib/apt/lists/* \
 && case "$(dpkg --print-architecture)" in \
        amd64) opam_arch=x86_64; opam_sha="${OPAM_SHA256_X86_64}" ;; \
        arm64) opam_arch=arm64;  opam_sha="${OPAM_SHA256_ARM64}" ;; \
        *) echo "unsupported architecture: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /usr/local/bin/opam \
        "https://github.com/ocaml/opam/releases/download/${OPAM_VERSION}/opam-${OPAM_VERSION}-${opam_arch}-linux" \
 && echo "${opam_sha}  /usr/local/bin/opam" | sha256sum -c - \
 && chmod +x /usr/local/bin/opam \
 # bwrap doesn't nest in a container. Default HTTP index: opam.ocaml.org
 # is on the egress allowlist and its repo file carries archive-mirrors,
 # so scan-time `opam update` and every archive fetch go through that one
 # host regardless of where a package's primary URL points.
 && opam init --disable-sandboxing --bare --no-setup \
 && opam switch create default "${OCAML_VERSION}" \
 && opam install dune ocamlfind ocaml-lsp-server odoc merlin \
 # a+rwX: the worker runs the container as the host uid (--user), not runner.
 && opam clean -acrs \
 && chmod -R a+rwX /opt/opam \
 && opam --version \
 && ocaml -version \
 && dune --version \
 && ocamlfind list >/dev/null

USER runner
