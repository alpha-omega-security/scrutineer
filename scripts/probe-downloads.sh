#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo 'usage: probe-downloads.sh OUTPUT_DIR [ROUNDS: 1-5]' >&2
  exit 64
fi
rounds=${2:-3}
case "$rounds" in [1-5]) ;; *) echo 'rounds must be 1-5' >&2; exit 64 ;; esac
case "$(uname -m)" in
  x86_64) node_arch=x64 ;;
  aarch64|arm64) node_arch=arm64 ;;
  *) echo 'unsupported architecture' >&2; exit 64 ;;
esac

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
node_version=$(sed -n 's/^ARG NODE_VERSION=//p' "$root/docker/profiles/node/Dockerfile")
sqlite_version=$(awk '$1 == "github.com/glebarez/go-sqlite" {print $2}' "$root/go.mod")
sarif_version=$(awk '$1 == "github.com/git-pkgs/sarif" {print $2}' "$root/go.mod")
clone_version=$(awk '$1 == "github.com/git-pkgs/clone" {print $2}' "$root/go.mod")
test -n "$node_version" && test -n "$sqlite_version" && test -n "$sarif_version" && test -n "$clone_version"

mkdir -p "$1"
output=$(CDPATH='' cd -- "$1" && pwd)
scratch=$(mktemp -d)
trap 'chmod -R u+w "$scratch"; rm -rf "$scratch"' EXIT

{
  uname -a
  curl -q --version
  go version
  for key in HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy; do
    if [ -n "${!key:-}" ]; then printf '%s=set\n' "$key"; fi
  done
} > "$output/environment.txt"
printf 'sample\tstarted_utc\telapsed_seconds\texit_code\n' > "$output/results.tsv"
failures=0

record() {
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" | tee -a "$output/results.tsv"
  if [ "$4" -ne 0 ]; then failures=$((failures + 1)); fi
}

probe_curl() {
  local sample=$1 protocol=$2 url=$3 status=0 started before
  started=$(date -u +%FT%TZ)
  before=$SECONDS
  curl -q "$protocol" --fail --silent --show-error --location \
    --connect-timeout 10 --max-time 30 --retry 0 \
    --output /dev/null --dump-header "$output/$sample.headers" \
    --write-out '%{json}\n' "$url" \
    > "$output/$sample.json" 2> "$output/$sample.stderr" || status=$?
  record "$sample" "$started" "$((SECONDS - before))" "$status"
}

probe_go() {
  local sample=$1 http2=$2 status=0 started before
  started=$(date -u +%FT%TZ)
  before=$SECONDS
  # An empty module cache and no go.sum exercise checksum verification too.
  (
    cd "$scratch"
    timeout --signal=TERM --kill-after=5s 60s env \
      GOENV=off GOWORK=off GOTOOLCHAIN=local GOFLAGS= \
      GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
      GOPRIVATE= GONOPROXY= GONOSUMDB= \
      GOPATH="$scratch/$sample" GOMODCACHE="$scratch/$sample/pkg/mod" \
      GODEBUG="http2client=$http2,http2debug=1" \
      go mod download -x -json \
        "github.com/glebarez/go-sqlite@$sqlite_version" \
        "github.com/git-pkgs/sarif@$sarif_version" \
        "github.com/git-pkgs/clone@$clone_version"
  ) > "$output/$sample.json" 2> "$output/$sample.stderr" || status=$?
  record "$sample" "$started" "$((SECONDS - before))" "$status"
}

for ((round = 1; round <= rounds; round++)); do
  # Reverse each pair to reduce the effect of request order.
  protocols=(h2 h1)
  if [ "$((round % 2))" -eq 0 ]; then protocols=(h1 h2); fi
  for target in node module checksum go; do
    for protocol in "${protocols[@]}"; do
      sample="$round-$target-$protocol"
      curl_protocol=--http2-prior-knowledge
      http2=1
      if [ "$protocol" = h1 ]; then curl_protocol=--http1.1; http2=0; fi
      case "$target" in
        node) probe_curl "$sample" "$curl_protocol" "https://nodejs.org/dist/v$node_version/node-v$node_version-linux-$node_arch.tar.xz" ;;
        module) probe_curl "$sample" "$curl_protocol" "https://proxy.golang.org/github.com/glebarez/go-sqlite/@v/$sqlite_version.zip" ;;
        checksum) probe_curl "$sample" "$curl_protocol" 'https://sum.golang.org/tile/8/0/x151/359' ;;
        go) probe_go "$sample" "$http2" ;;
      esac
    done
  done
done

printf 'Failed samples: %s\n' "$failures"
test "$failures" -eq 0
