#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
mkdir "$test_dir/bin"
export PROBE_TEST_LOG="$test_dir/commands"

cat > "$test_dir/bin/curl" <<'SH'
#!/usr/bin/env bash
set -eu
if [ "$2" = --version ]; then echo 'curl fixture'; exit 0; fi
printf 'curl %s\n' "$*" >> "$PROBE_TEST_LOG"
printf '{"http_version":"2","response_code":200}\n'
if [ "${PROBE_TEST_CURL_FAILURE:-0}" = 1 ] && [[ "$*" == *--http2-prior-knowledge*proxy.golang.org* ]]; then
  echo 'HTTP/2 stream reset' >&2
  exit 92
fi
SH
cat > "$test_dir/bin/go" <<'SH'
#!/usr/bin/env bash
set -eu
if [ "$1" = version ]; then echo 'go fixture'; exit 0; fi
test "$GOENV" = off && test "$GOWORK" = off && test "$GOTOOLCHAIN" = local
test "$GOPROXY" = https://proxy.golang.org && test "$GOSUMDB" = sum.golang.org
test -z "$GOPRIVATE$GONOPROXY$GONOSUMDB$GOFLAGS"
test ! -e go.sum && test ! -e go.mod && test ! -e "$GOMODCACHE"
mkdir -p "$GOMODCACHE"
printf 'go %s %s %s\n' "$GODEBUG" "$GOMODCACHE" "$*" >> "$PROBE_TEST_LOG"
printf '{"Path":"fixture"}\n'
if [ "${PROBE_TEST_GO_FAILURE:-0}" = 1 ]; then echo 'download failed' >&2; exit 1; fi
SH
cat > "$test_dir/bin/timeout" <<'SH'
#!/usr/bin/env bash
set -eu
test "$1" = --signal=TERM && test "$2" = --kill-after=5s && test "$3" = 60s
if [ "${PROBE_TEST_TIMEOUT:-0}" = 1 ]; then exit 124; fi
shift 3
exec "$@"
SH
chmod +x "$test_dir/bin/"*
export PATH="$test_dir/bin:$PATH"

run_probe() {
  local name=$1 expected=$2 rounds=$3 status=0
  : > "$PROBE_TEST_LOG"
  bash "$root/scripts/probe-downloads.sh" "$test_dir/$name" "$rounds" > "$test_dir/$name.log" || status=$?
  if [ "$status" -ne "$expected" ]; then
    cat "$test_dir/$name.log" >&2
    echo "$name: exit $status, expected $expected" >&2
    exit 1
  fi
}

run_probe success 0 2
test "$(wc -l < "$test_dir/success/results.tsv" | tr -d ' ')" = 17
test "$(grep -c '^curl ' "$PROBE_TEST_LOG")" = 12
test "$(grep -c '^go ' "$PROBE_TEST_LOG")" = 4
test "$(grep -c -- '--max-time 30 --retry 0' "$PROBE_TEST_LOG")" = 12
test "$(grep -c 'http2client=0,http2debug=1' "$PROBE_TEST_LOG")" = 2
test "$(grep -c 'http2client=1,http2debug=1' "$PROBE_TEST_LOG")" = 2
test "$(sed -n '2p' "$test_dir/success/results.tsv" | cut -f1)" = 1-node-h2
test "$(sed -n '10p' "$test_dir/success/results.tsv" | cut -f1)" = 2-node-h1
test -s "$test_dir/success/1-node-h2.json"
test -s "$test_dir/success/2-go-h1.json"
test -s "$test_dir/success/environment.txt"
printf 'ok - paired protocols, bounded requests, separate Go caches and reversed order\n'

export PROBE_TEST_CURL_FAILURE=1
run_probe curl-failure 1 1
test "$(wc -l < "$test_dir/curl-failure/results.tsv" | tr -d ' ')" = 9
awk -F '\t' '$1 == "1-module-h2" && $4 == 92 {found=1} END {exit !found}' "$test_dir/curl-failure/results.tsv"
grep -q 'HTTP/2 stream reset' "$test_dir/curl-failure/1-module-h2.stderr"
unset PROBE_TEST_CURL_FAILURE
printf 'ok - curl failures retain evidence and do not stop later samples\n'

export PROBE_TEST_GO_FAILURE=1
run_probe go-failure 1 1
grep -q 'download failed' "$test_dir/go-failure/1-go-h1.stderr"
grep -q 'Failed samples: 2' "$test_dir/go-failure.log"
unset PROBE_TEST_GO_FAILURE
printf 'ok - Go failures retain evidence and complete both protocols\n'

export PROBE_TEST_TIMEOUT=1
run_probe timeout 1 1
test "$(awk -F '\t' '$4 == 124 {n++} END {print n}' "$test_dir/timeout/results.tsv")" = 2
unset PROBE_TEST_TIMEOUT
printf 'ok - Go timeouts are recorded\n'

for rounds in 0 6 invalid; do run_probe "invalid-$rounds" 64 "$rounds"; done
printf 'ok - invalid sample counts are rejected\n'
