FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
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

FROM node:26-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019 AS claude
RUN npm install -g @anthropic-ai/claude-code@2.1.237

FROM python:3.15.0rc1-alpine@sha256:c31ce768b814aa1cd3e9247f5d06f4713cf8e4140b707a1bf31fa18411c7c219 AS python-tools
RUN pip install --no-cache-dir semgrep==1.167.0 "setuptools<81"

FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS go-tools
RUN apk add --no-cache git
RUN GOBIN=/out go install github.com/git-pkgs/git-pkgs@v0.15.3 && \
    GOBIN=/out go install github.com/git-pkgs/brief/cmd/brief@v0.12.0

# vid links tree-sitter grammars (C), so unlike the main binary it needs
# cgo; build-base provides gcc and musl headers, matching the musl-based
# final image.
FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS vid-build
RUN apk add --no-cache build-base git
RUN GOBIN=/out CGO_ENABLED=1 go install github.com/andrew/VID/cmd/vid@v0.1.0

FROM rust:1.97-alpine@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900 AS zizmor-build
RUN apk add --no-cache build-base linux-headers
RUN cargo install --locked --root /out zizmor@1.29.0

FROM python:3.15.0rc1-alpine@sha256:c31ce768b814aa1cd3e9247f5d06f4713cf8e4140b707a1bf31fa18411c7c219
RUN apk add --no-cache git ca-certificates bash nodejs coreutils && \
    rm -f /usr/local/bin/pip* /usr/local/bin/idle* /usr/local/bin/pydoc*

# scrutineer binary
COPY --from=build /scrutineer /usr/local/bin/scrutineer

# claude cli
COPY --from=claude /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=claude /usr/local/bin/claude /usr/local/bin/claude

# semgrep
COPY --from=python-tools /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages
COPY --from=python-tools /usr/local/bin/semgrep* /usr/local/bin/
COPY --from=python-tools /usr/local/bin/pysemgrep /usr/local/bin/

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
