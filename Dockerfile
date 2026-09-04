FROM golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
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

FROM node:26-alpine@sha256:2d984a15c9b54fd0aeb608b8e0d0d83529eb34d2966db27a1fb4f1edc3d298a3 AS claude
RUN npm install -g @anthropic-ai/claude-code@2.1.259

FROM python:3.14-alpine@sha256:05b2b8b732ecd268fee8727a369f936f022d1321b59befd13c30ede22769dcdc AS python-tools
RUN pip install --no-cache-dir semgrep==1.167.0 "setuptools<81" bandit==1.9.4

FROM golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS go-tools
RUN apk add --no-cache git
RUN GOBIN=/out go install github.com/git-pkgs/git-pkgs@v0.19.0 && \
    GOBIN=/out go install github.com/git-pkgs/brief/cmd/brief@v0.12.0

# vid links tree-sitter grammars (C), so unlike the main binary it needs
# cgo; build-base provides gcc and musl headers, matching the musl-based
# final image.
FROM golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS vid-build
RUN apk add --no-cache build-base git
RUN GOBIN=/out CGO_ENABLED=1 go install github.com/andrew/VID/cmd/vid@v0.1.0

FROM rust:1.98-alpine@sha256:a10e64dd139b7387337c7fbe8aca31b959b57b2fd4c8ae20a02cf1d6ea424dce AS zizmor-build
RUN apk add --no-cache build-base linux-headers
RUN cargo install --locked --root /out zizmor@1.29.0

FROM python:3.15.0rc1-alpine@sha256:c31ce768b814aa1cd3e9247f5d06f4713cf8e4140b707a1bf31fa18411c7c219
FROM python:3.14-alpine@sha256:05b2b8b732ecd268fee8727a369f936f022d1321b59befd13c30ede22769dcdc
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
