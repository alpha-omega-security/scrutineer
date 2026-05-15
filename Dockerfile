FROM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /scrutineer ./cmd/scrutineer

FROM node:22-alpine@sha256:968df39aedcea65eeb078fb336ed7191baf48f972b4479711397108be0966920 AS claude
RUN npm install -g @anthropic-ai/claude-code@2.1.119

FROM python:3.13-alpine@sha256:420cd0bf0f3998275875e02ecd5808168cf0843cbb4d3c536432f729247b2acc AS python-tools
RUN pip install --no-cache-dir semgrep==1.116.0 "setuptools<81"

FROM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS go-tools
RUN apk add --no-cache git
RUN GOBIN=/out go install github.com/git-pkgs/git-pkgs@v0.15.3 && \
    GOBIN=/out go install github.com/git-pkgs/brief/cmd/brief@v0.6.0

FROM rust:1.88-alpine@sha256:9dfaae478ecd298b6b5a039e1f2cc4fc040fc818a2de9aa78fa714dea036574d AS zizmor-build
RUN apk add --no-cache build-base linux-headers
RUN cargo install --locked --root /out zizmor@1.24.1

FROM python:3.13-alpine@sha256:420cd0bf0f3998275875e02ecd5808168cf0843cbb4d3c536432f729247b2acc
RUN apk add --no-cache git ca-certificates bash nodejs coreutils && \
    rm -f /usr/local/bin/pip* /usr/local/bin/idle* /usr/local/bin/pydoc*

# scrutineer binary
COPY --from=build /scrutineer /usr/local/bin/scrutineer

# claude cli
COPY --from=claude /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=claude /usr/local/bin/claude /usr/local/bin/claude

# semgrep
COPY --from=python-tools /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
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
