FROM golang:1.26.2-alpine AS build
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /scrutineer ./cmd/scrutineer

FROM node:22-alpine AS claude
RUN npm install -g @anthropic-ai/claude-code@1.0.17

FROM python:3.13-alpine AS python-tools
RUN pip install --no-cache-dir semgrep==1.115.0

FROM alpine:3.21
RUN apk add --no-cache git ca-certificates python3 bash nodejs

# scrutineer binary
COPY --from=build /scrutineer /usr/local/bin/scrutineer

# claude cli
COPY --from=claude /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -sf /usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js /usr/local/bin/claude

# semgrep
COPY --from=python-tools /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=python-tools /usr/local/bin/semgrep* /usr/local/bin/

# go tools installed from source
COPY --from=build /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"
RUN GOBIN=/usr/local/bin go install github.com/git-pkgs/git-pkgs@v0.14.0 && \
    GOBIN=/usr/local/bin go install github.com/git-pkgs/brief@v0.10.0 && \
    rm -rf /root/go /usr/local/go

# zizmor
RUN apk add --no-cache --virtual .build-deps cargo && \
    cargo install zizmor@1.6.0 && \
    cp /root/.cargo/bin/zizmor /usr/local/bin/ && \
    rm -rf /root/.cargo && \
    apk del .build-deps

# Non-root user (T1/T11: reduce blast radius)
RUN adduser -D -h /home/scrutineer scrutineer && \
    mkdir -p /data && chown scrutineer:scrutineer /data
USER scrutineer

EXPOSE 8080
ENTRYPOINT ["scrutineer"]
CMD ["-addr", "0.0.0.0:8080", "-data", "/data"]
