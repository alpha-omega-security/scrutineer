FROM golang:1.26.4-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS build
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

FROM node:26-alpine@sha256:144769ec3f32e8ee36b3cfde91e82bee25d9367b20f31a151f3f7eea3a2a8541 AS claude
RUN npm install -g @anthropic-ai/claude-code@2.1.160

FROM python:3.14.5-alpine@sha256:5a824eb82cc75361f98611f3cfc5091ea33f10a6ccea4d4ebdabbc523b9a1614 AS python-tools
RUN pip install --no-cache-dir semgrep==1.116.0 "setuptools<81"

FROM golang:1.26.4-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS go-tools
RUN apk add --no-cache git
RUN GOBIN=/out go install github.com/git-pkgs/git-pkgs@v0.15.3 && \
    GOBIN=/out go install github.com/git-pkgs/brief/cmd/brief@v0.6.0

FROM rust:1.96-alpine@sha256:66f48b19d6e88519e2e58bebe0d945779a6a4ca41c2db17db78c9569655b50ac AS zizmor-build
RUN apk add --no-cache build-base linux-headers
RUN cargo install --locked --root /out zizmor@1.24.1

FROM python:3.14.5-alpine@sha256:5a824eb82cc75361f98611f3cfc5091ea33f10a6ccea4d4ebdabbc523b9a1614
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

# Non-root user (T1/T11: reduce blast radius)
RUN adduser -D -h /home/scrutineer scrutineer && \
    mkdir -p /data && chown scrutineer:scrutineer /data
USER scrutineer

EXPOSE 8080
ENTRYPOINT ["scrutineer"]
CMD ["-addr", "0.0.0.0:8080", "-data", "/data"]
