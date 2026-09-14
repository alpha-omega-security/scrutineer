#!/bin/sh
set -eu

# The fixture verifies argument and environment preservation on every attempt.
if [ "${1:-}" = fixture ]; then
  shift
  [ "$#" -eq 2 ] && [ "$2" = 'argument with spaces' ] && [ "$GOBIN" = /out ] || exit 99
  count=$(cat "$TEST_DIR/count")
  count=$((count + 1))
  printf '%s\n' "$count" > "$TEST_DIR/count"
  [ "$count" -ge "$1" ] || exit 42
  exit 0
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEST_DIR=$(mktemp -d)
export TEST_DIR
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM
mkdir "$TEST_DIR/bin"
printf '#!/bin/sh\nprintf "%%s\\n" "$1" >> "$TEST_DIR/sleeps"\n' > "$TEST_DIR/bin/sleep"
chmod +x "$TEST_DIR/bin/sleep"
PATH="$TEST_DIR/bin:$PATH"
GOBIN=/out
export PATH GOBIN

check() {
  target=$1
  expected_status=$2
  expected_count=$3
  expected_sleeps=$4
  printf '0\n' > "$TEST_DIR/count"
  : > "$TEST_DIR/sleeps"
  status=0
  sh "$root/scripts/retry-build-command.sh" sh "$root/scripts/retry-build-command_test.sh" fixture "$target" 'argument with spaces' || status=$?
  [ "$status" -eq "$expected_status" ]
  [ "$(cat "$TEST_DIR/count")" -eq "$expected_count" ]
  [ "$(cat "$TEST_DIR/sleeps")" = "$expected_sleeps" ]
}

check 1 0 1 ''
check 2 0 2 5
check 3 0 3 '5
10'
check 4 42 3 '5
10'
status=0
sh "$root/scripts/retry-build-command.sh" || status=$?
[ "$status" -eq 64 ]
echo 'All build-command retry tests passed.'
