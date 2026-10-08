FROM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# COMMIT is the git SHA being built. .git is excluded from the build context
# (.dockerignore), so the Go VCS stamp is unavailable here; pass it explicitly
# with `docker build --build-arg COMMIT=$(git rev-parse HEAD)` to surface it on
# the settings page. Empty when not supplied.
ARG COMMIT=""
RUN CGO_ENABLED=0 go build -ldflags "-X main.commit=${COMMIT}" -o /scrutineer ./cmd/scrutineer

FROM node:26-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80 AS claude

RUN npm install -g @anthropic-ai/claude-code@2.1.287

FROM python:3.14-alpine@sha256:9e9fde4d32eedce0b661d9ab91e826b62dddf28e928c230ec55f1866cac66b01 AS python-tools

ARG SEMGREP_VERSION=1.178.0

ARG BANDIT_VERSION=1.9.4

RUN pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" "setuptools<81" "bandit==${BANDIT_VERSION}"

FROM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS go-tools
RUN apk add --no-cache git
ARG BETTERLEAKS_VERSION=v1.9.0
RUN GOBIN=/out CGO_ENABLED=0 go install -ldflags "-X=github.com/betterleaks/betterleaks/version.Version=${BETTERLEAKS_VERSION}" github.com/betterleaks/betterleaks@${BETTERLEAKS_VERSION}

RUN GOBIN=/out go install github.com/git-pkgs/git-pkgs@v0.20.0

RUN GOBIN=/out go install github.com/git-pkgs/brief/cmd/brief@v0.14.0

# vid links tree-sitter grammars (C), so unlike the main binary it needs
# cgo; build-base provides gcc and musl headers, matching the musl-based
# final image.
FROM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS vid-build
RUN apk add --no-cache build-base git
RUN GOBIN=/out CGO_ENABLED=1 go install github.com/andrew/VID/cmd/vid@v0.1.0

FROM rust:1.98-alpine@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f AS zizmor-build
RUN apk add --no-cache build-base linux-headers
RUN cargo install --locked --root /out zizmor@1.30.1

FROM python:3.15.0rc2-alpine@sha256:a73535961d3114b7b2e6948ef2dd8d295b885a76d3c23e87e688856713c1cbac
FROM python:3.14-alpine@sha256:9e9fde4d32eedce0b661d9ab91e826b62dddf28e928c230ec55f1866cac66b01
RUN apk add --no-cache git ca-certificates bash nodejs coreutils && \
    rm -f /usr/local/bin/pip* /usr/local/bin/idle* /usr/local/bin/pydoc*

# scrutineer binary
COPY --from=build /scrutineer /usr/local/bin/scrutineer

# claude cli
COPY --from=claude /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=claude /usr/local/bin/claude /usr/local/bin/claude

# semgrep and bandit (both installed into the python-tools stage above, so
# the shared site-packages copy covers their libraries)
COPY --from=python-tools /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages
COPY --from=python-tools /usr/local/bin/semgrep* /usr/local/bin/
COPY --from=python-tools /usr/local/bin/pysemgrep /usr/local/bin/
COPY --from=python-tools /usr/local/bin/bandit* /usr/local/bin/

# go tools
COPY --from=go-tools /out/* /usr/local/bin/

# zizmor
COPY --from=zizmor-build /out/bin/zizmor /usr/local/bin/zizmor

# vid
COPY --from=vid-build /out/vid /usr/local/bin/vid

# Non-root user (T1/T11: reduce blast radius)
RUN adduser -D -h /home/scrutineer scrutineer && \
    mkdir -p /data && chown scrutineer:scrutineer /data
USER scrutineer

EXPOSE 8080
ENTRYPOINT ["scrutineer"]
CMD ["-addr", "0.0.0.0:8080", "-data", "/data"]
