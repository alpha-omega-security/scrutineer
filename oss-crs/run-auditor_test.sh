#!/usr/bin/env bash

set -euo pipefail

tests=0

fail() {
  printf 'not ok %s - %s\n' "$tests" "$1" >&2
  exit 1
}

assert_eq() {
  local expected=$1
  local actual=$2
  local label=$3
  tests=$((tests + 1))
  if [ "$actual" != "$expected" ]; then
    printf 'expected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
    fail "$label"
  fi
  printf 'ok %s - %s\n' "$tests" "$label"
}

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
script=$root/oss-crs/run-auditor.sh
TEST_DIR=$(mktemp -d)
export TEST_DIR
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM

# The fake scrutineer records its argv and env, writes the outputs the real
# command would and exits with FAKE_STATUS.
cat > "$TEST_DIR/scrutineer" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$TEST_DIR/scrutineer.argv"
printf 'base=%s\nkey=%s\noauth=%s\nhaiku=%s\n' "${ANTHROPIC_BASE_URL:-}" "${ANTHROPIC_API_KEY:-}" "${CLAUDE_CODE_OAUTH_TOKEN:-}" "${ANTHROPIC_DEFAULT_HAIKU_MODEL:-}" > "$TEST_DIR/scrutineer.env"
while [ "$#" -gt 0 ]; do
  [ "$1" = -out ] && out=$2
  shift
done
if [ -n "${FAKE_WAIT_TERM:-}" ]; then
  trap 'mkdir -p "$out/scrutineer-audit"; exit 3' TERM
  : > "$FAKE_WAIT_TERM"
  while :; do sleep 0.1; done
fi
mkdir -p "$out/scrutineer-audit"
echo 'scrutineer ran'
if [ "${FAKE_CANDIDATE:-}" = yes ]; then
  mkdir -p "$out/bug-candidates"
  echo '{}' > "$out/bug-candidates/scrutineer.sarif"
fi
exit "${FAKE_STATUS:-0}"
FAKE
# Like the real command, register-log-dir refuses an existing path and turns
# it into a symlink under OSS_CRS_LOG_DIR.
cat > "$TEST_DIR/libCRS" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$TEST_DIR/libcrs.calls"
if [ "$1" = register-log-dir ]; then
  [ ! -e "$2" ] || exit 1
  mkdir -p "$OSS_CRS_LOG_DIR/$(basename "$2")"
  ln -s "$OSS_CRS_LOG_DIR/$(basename "$2")" "$2"
fi
FAKE
chmod +x "$TEST_DIR/scrutineer" "$TEST_DIR/libCRS"

mkdir "$TEST_DIR/source"
printf 'secret-key\n' > "$TEST_DIR/key"

run() {
  : > "$TEST_DIR/libcrs.calls"
  rm -f "$TEST_DIR/scrutineer.argv" "$TEST_DIR/scrutineer.env"
  status=0
  SCRUTINEER="$TEST_DIR/scrutineer" LIBCRS="$TEST_DIR/libCRS" \
    SCRUTINEER_AUDIT_WORK="$TEST_DIR/work" "$@" bash "$script" > /dev/null 2>&1 || status=$?
}

run env -u OSS_CRS_TARGET_SOURCE
if [ "$status" -eq 0 ]; then
  fail 'missing source: expected a non-zero exit'
fi
assert_eq absent "$([ -e "$TEST_DIR/scrutineer.argv" ] && echo present || echo absent)" 'missing source: scrutineer not called'

run env OSS_CRS_TARGET_SOURCE="$TEST_DIR/source" \
  OSS_CRS_LLM_API_URL=http://litellm.oss-crs:4000 OSS_CRS_LLM_API_KEY_FILE="$TEST_DIR/key" \
  SCRUTINEER_MODEL=claude-test SCRUTINEER_AUDIT_TIMEOUT=30m SCRUTINEER_CONCURRENCY=2
assert_eq 0 "$status" 'llm routing: exit status'
argv=$(tr '\n' ' ' < "$TEST_DIR/scrutineer.argv")
assert_eq 'audit -no-container -source '"$TEST_DIR"'/source -out '"$TEST_DIR"'/work/out -data '"$TEST_DIR"'/work/data -trusted-model-host litellm.oss-crs -model claude-test -audit-timeout 30m -concurrency 2 ' "$argv" 'llm routing: scrutineer arguments'
assert_eq $'base=http://litellm.oss-crs:4000\nkey=secret-key\noauth=\nhaiku=claude-test' "$(cat "$TEST_DIR/scrutineer.env")" 'llm routing: environment'

# An OAuth token sends Claude straight to Anthropic, so the LiteLLM URL and
# key the framework still provides are left unused.
run env OSS_CRS_TARGET_SOURCE="$TEST_DIR/source" \
  OSS_CRS_LLM_API_URL=http://litellm.oss-crs:4000 OSS_CRS_LLM_API_KEY_FILE="$TEST_DIR/key" \
  CLAUDE_CODE_OAUTH_TOKEN=oauth-token SCRUTINEER_MODEL=claude-test
assert_eq 0 "$status" 'oauth: exit status'
argv=$(tr '\n' ' ' < "$TEST_DIR/scrutineer.argv")
assert_eq 'audit -no-container -source '"$TEST_DIR"'/source -out '"$TEST_DIR"'/work/out -data '"$TEST_DIR"'/work/data -model claude-test ' "$argv" 'oauth: scrutineer arguments'
assert_eq $'base=\nkey=\noauth=oauth-token\nhaiku=claude-test' "$(cat "$TEST_DIR/scrutineer.env")" 'oauth: environment'

run env OSS_CRS_TARGET_SOURCE="$TEST_DIR/source" FAKE_STATUS=0 FAKE_CANDIDATE=yes
assert_eq 0 "$status" 'complete: exit status'
assert_eq "submit bug-candidate $TEST_DIR/work/out/bug-candidates/scrutineer.sarif"$'\n'"submit report $TEST_DIR/work/out/scrutineer-audit" "$(cat "$TEST_DIR/libcrs.calls")" 'complete: submits candidates then report'

run env OSS_CRS_TARGET_SOURCE="$TEST_DIR/source" FAKE_STATUS=3
assert_eq 0 "$status" 'incomplete: exit status'
assert_eq "submit report $TEST_DIR/work/out/scrutineer-audit" "$(cat "$TEST_DIR/libcrs.calls")" 'incomplete: submits only the report'

run env OSS_CRS_TARGET_SOURCE="$TEST_DIR/source" FAKE_STATUS=1
assert_eq 1 "$status" 'failure: exit status'
assert_eq '' "$(cat "$TEST_DIR/libcrs.calls")" 'failure: submits nothing'

# A root start without the audit user refuses to run the audit as root. The
# fake id reports uid 0 and knows no other user.
mkdir -p "$TEST_DIR/rootbin"
cat > "$TEST_DIR/rootbin/id" <<'FAKE'
#!/usr/bin/env bash
[ "${1:-}" = -u ] && { echo 0; exit 0; }
exit 1
FAKE
chmod +x "$TEST_DIR/rootbin/id"
run env PATH="$TEST_DIR/rootbin:$PATH" OSS_CRS_TARGET_SOURCE="$TEST_DIR/source" SCRUTINEER_AUDIT_USER=nobody-here
assert_eq 2 "$status" 'root without audit user: exit status'
assert_eq absent "$([ -e "$TEST_DIR/scrutineer.argv" ] && echo present || echo absent)" 'root without audit user: scrutineer not called'
assert_eq '' "$(cat "$TEST_DIR/libcrs.calls")" 'root without audit user: submits nothing'

for attempt in first second; do
  run env OSS_CRS_TARGET_SOURCE="$TEST_DIR/source" OSS_CRS_LOG_DIR="$TEST_DIR/crs-logs"
  assert_eq 0 "$status" "log dir ($attempt run): exit status"
  assert_eq 'scrutineer ran' "$(cat "$TEST_DIR/crs-logs/logs/scrutineer.log")" "log dir ($attempt run): log persisted"
done

# A TERM to the entrypoint reaches scrutineer, whose partial outputs are still
# submitted. The entrypoint then exits 0 like any other submitted audit.
: > "$TEST_DIR/libcrs.calls"
rm -f "$TEST_DIR/waiting"
status=0
OSS_CRS_TARGET_SOURCE="$TEST_DIR/source" FAKE_WAIT_TERM="$TEST_DIR/waiting" \
  SCRUTINEER="$TEST_DIR/scrutineer" LIBCRS="$TEST_DIR/libCRS" \
  SCRUTINEER_AUDIT_WORK="$TEST_DIR/work" bash "$script" > /dev/null 2>&1 &
entry=$!
for _ in $(seq 100); do
  [ -e "$TEST_DIR/waiting" ] && break
  sleep 0.1
done
kill -TERM "$entry"
wait "$entry" || status=$?
assert_eq 0 "$status" 'term: exit status'
assert_eq "submit report $TEST_DIR/work/out/scrutineer-audit" "$(cat "$TEST_DIR/libcrs.calls")" 'term: submits the partial report'

printf '1..%s\n' "$tests"
