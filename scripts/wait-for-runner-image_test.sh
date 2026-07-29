#!/usr/bin/env bash

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
resolver="$root/scripts/wait-for-runner-image.sh"
tests=0
repository=alpha-omega-security/scrutineer
commit_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
digest="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/wait-for-runner-image-test.XXXXXX")
stub_bin="$test_root/bin"
mkdir -p "$stub_bin"
trap 'rm -rf "$test_root"' EXIT

fail() {
  printf 'not ok %s - %s\n' "$tests" "$1" >&2
  exit 1
}

pass() {
  tests=$((tests + 1))
  printf 'ok %s - %s\n' "$tests" "$1"
}

assert_eq() {
  expected=$1
  actual=$2
  label=$3
  if [ "$actual" != "$expected" ]; then
    printf 'expected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
    fail "$label"
  fi
  pass "$label"
}

assert_contains() {
  value=$1
  expected=$2
  label=$3
  case "$value" in
    *"$expected"*) pass "$label" ;;
    *)
      printf 'expected substring:\n%s\nactual:\n%s\n' "$expected" "$value" >&2
      fail "$label"
      ;;
  esac
}

assert_command_calls() {
  expected=$1
  command_name=$2
  label=$3
  file="$case_dir/${command_name}-count"
  if [ -f "$file" ]; then
    actual=$(cat "$file")
  else
    actual=0
  fi
  assert_eq "$expected" "$actual" "$label"
}

assert_file_lines() {
  expected=$1
  file=$2
  label=$3
  if [ -f "$file" ]; then
    actual=$(wc -l < "$file" | tr -d '[:space:]')
  else
    actual=0
  fi
  assert_eq "$expected" "$actual" "$label"
}

cat > "$stub_bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state=${RUNNER_IMAGE_TEST_STATE:?}
count_file="$state/docker-count"
count=0
[ ! -f "$count_file" ] || count=$(cat "$count_file")
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
printf '%s\n' "$*" >> "$state/docker-args"
response=$(sed -n "${count}p" "$state/docker-responses")
if [ -z "$response" ] && [ -s "$state/docker-responses" ]; then
  response=$(tail -n 1 "$state/docker-responses")
fi
case "$response" in
  missing)
    printf 'manifest unknown\n' >&2
    exit 1
    ;;
  missing:*)
    printf '%s\n' "${response#missing:}" >&2
    exit 1
    ;;
  malformed)
    printf '{}\n'
    ;;
  digest:*)
    printf '{"digest":"%s"}\n' "${response#digest:}"
    ;;
  *)
    printf 'unexpected docker response: %s\n' "$response" >&2
    exit 2
    ;;
esac
EOF

cat > "$stub_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state=${RUNNER_IMAGE_TEST_STATE:?}
count_file="$state/gh-count"
count=0
[ ! -f "$count_file" ] || count=$(cat "$count_file")
count=$((count + 1))
printf '%s\n' "$count" > "$count_file"
printf '%s\n' "$*" >> "$state/gh-args"
response=$(sed -n "${count}p" "$state/gh-responses")
if [ -z "$response" ] && [ -s "$state/gh-responses" ]; then
  response=$(tail -n 1 "$state/gh-responses")
fi
if [ "$response" = error ]; then
  printf 'simulated GitHub API failure\n' >&2
  exit 1
fi
jq_filter=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --jq)
      jq_filter=$2
      shift 2
      ;;
    *) shift ;;
  esac
done
[ -n "$jq_filter" ] || {
  printf 'missing --jq filter\n' >&2
  exit 2
}
printf '%s\n' "$response" | jq -r "$jq_filter"
EOF

cat > "$stub_bin/sleep" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state=${RUNNER_IMAGE_TEST_STATE:?}
printf '%s\n' "$1" >> "$state/sleep-args"
EOF

chmod +x "$stub_bin/docker" "$stub_bin/gh" "$stub_bin/sleep"

case_number=0
start_case() {
  case_number=$((case_number + 1))
  case_dir="$test_root/case-$case_number"
  mkdir -p "$case_dir"
  : > "$case_dir/docker-responses"
  printf '{"workflow_runs":[]}\n' > "$case_dir/gh-responses"
}

run_case() {
  wait_seconds=$1
  poll_seconds=$2
  if output=$(PATH="$stub_bin:$PATH" \
    RUNNER_IMAGE_TEST_STATE="$case_dir" \
    "$resolver" "$repository" "$commit_sha" \
    "$wait_seconds" "$poll_seconds" 2>"$case_dir/stderr"); then
    status=0
  else
    status=$?
  fi
  error=$(cat "$case_dir/stderr")
}

start_case
printf 'digest:%s\n' "$digest" > "$case_dir/docker-responses"
run_case 2 1
assert_eq 0 "$status" 'existing image succeeds'
assert_eq "ghcr.io/${repository}-runner@${digest}" "$output" \
  'existing image returns immutable reference'
assert_command_calls 1 gh \
  'existing image confirms no retained active workflow'

start_case
printf 'digest:%s\n' "$digest" > "$case_dir/docker-responses"
printf '%s\n' \
  '{"workflow_runs":[{"id":100,"status":"completed","conclusion":"failure","html_url":"https://github.example/runs/100","created_at":"2026-07-28T17:00:00Z"},{"id":101,"status":"in_progress","conclusion":null,"html_url":"https://github.example/runs/101","created_at":"2026-07-28T18:00:00Z"}]}' \
  '{"workflow_runs":[{"id":100,"status":"completed","conclusion":"failure","html_url":"https://github.example/runs/100","created_at":"2026-07-28T17:00:00Z"},{"id":101,"status":"completed","conclusion":"success","html_url":"https://github.example/runs/101","created_at":"2026-07-28T18:00:00Z"}]}' \
  > "$case_dir/gh-responses"
run_case 2 1
assert_eq 0 "$status" 'active runner workflow is awaited'
assert_eq "ghcr.io/${repository}-runner@${digest}" "$output" \
  'successful runner workflow resolves immutable reference'
assert_command_calls 2 gh \
  'active runner workflow is queried until success'
assert_file_lines 1 "$case_dir/sleep-args" \
  'active runner workflow waits between queries'
assert_command_calls 1 docker \
  'manifest is not accepted before runner workflow success'
assert_contains "$error" 'https://github.example/runs/101' \
  'newest exact-SHA workflow run is selected'
gh_args=$(cat "$case_dir/gh-args")
assert_contains "$gh_args" \
  'repos/alpha-omega-security/scrutineer/actions/workflows/runner-image.yml/runs' \
  'query selects the runner image workflow'
assert_contains "$gh_args" 'event=push' 'query selects push runs'
assert_contains "$gh_args" 'branch=main' 'query selects the main branch'
assert_contains "$gh_args" "head_sha=${commit_sha}" \
  'query selects the exact release commit'

start_case
printf 'digest:%s\n' "$digest" > "$case_dir/docker-responses"
printf '%s\n' \
  '{"workflow_runs":[{"id":102,"status":"completed","conclusion":"failure","html_url":"https://github.example/runs/102","created_at":"2026-07-28T18:00:00Z"}]}' \
  > "$case_dir/gh-responses"
run_case 2 1
assert_eq 1 "$status" 'failed runner workflow blocks release'
assert_contains "$error" 'completed with conclusion failure' \
  'failed runner workflow reports its conclusion'
assert_contains "$error" 'https://github.example/runs/102' \
  'failed runner workflow reports its URL'
assert_file_lines 0 "$case_dir/sleep-args" \
  'failed runner workflow does not wait until timeout'
assert_command_calls 0 docker \
  'failed runner workflow is not bypassed by a readable manifest'

start_case
printf '%s\n' missing > "$case_dir/docker-responses"
printf '%s\n' \
  '{"workflow_runs":[{"id":103,"status":"completed","conclusion":"cancelled","html_url":"https://github.example/runs/103","created_at":"2026-07-28T18:00:00Z"}]}' \
  > "$case_dir/gh-responses"
run_case 2 1
assert_eq 1 "$status" 'cancelled runner workflow blocks release'
assert_contains "$error" 'completed with conclusion cancelled' \
  'cancelled runner workflow reports its conclusion'

start_case
printf '%s\n' missing > "$case_dir/docker-responses"
run_case 2 1
assert_eq 1 "$status" 'missing runner workflow times out'
assert_contains "$error" \
  "No Runner Image push run appeared for ${commit_sha} within 2 seconds" \
  'missing runner workflow reports the exact commit and timeout'
assert_command_calls 3 gh \
  'missing runner workflow is queried through the deadline'
assert_file_lines 2 "$case_dir/sleep-args" \
  'missing runner workflow stops sleeping at the deadline'

start_case
printf '%s\n' 'missing:denied: simulated registry failure' > "$case_dir/docker-responses"
printf '%s\n' \
  '{"workflow_runs":[{"id":104,"status":"completed","conclusion":"success","html_url":"https://github.example/runs/104","created_at":"2026-07-28T18:00:00Z"}]}' \
  > "$case_dir/gh-responses"
run_case 2 1
assert_eq 1 "$status" 'missing manifest after runner success times out'
assert_contains "$error" \
  "succeeded, but ghcr.io/${repository}-runner:sha-${commit_sha} was unavailable after 2 seconds" \
  'missing manifest reports successful runner and registry timeout'
assert_contains "$error" 'denied: simulated registry failure' \
  'registry timeout reports the last inspection error'

start_case
printf '%s\n' malformed > "$case_dir/docker-responses"
run_case 2 1
assert_eq 1 "$status" 'malformed manifest blocks release'
assert_contains "$error" 'Could not resolve a manifest digest' \
  'malformed manifest reports digest failure'
assert_command_calls 1 gh \
  'malformed readable manifest checks retained workflow state'

start_case
printf 'digest:%s\n' "$digest" > "$case_dir/docker-responses"
printf '%s\n' \
  '{"workflow_runs":[{"id":105,"status":"completed","conclusion":null,"html_url":"https://github.example/runs/105","created_at":"2026-07-28T18:00:00Z"}]}' \
  '{"workflow_runs":[{"id":105,"status":"completed","conclusion":"success","html_url":"https://github.example/runs/105","created_at":"2026-07-28T18:00:00Z"}]}' \
  > "$case_dir/gh-responses"
run_case 2 1
assert_eq 0 "$status" 'completed run without conclusion is retried'
assert_file_lines 1 "$case_dir/sleep-args" \
  'completed run without conclusion waits for a stable result'
assert_command_calls 1 docker \
  'completed run without conclusion cannot resolve the manifest early'

start_case
printf 'digest:%s\n' "$digest" > "$case_dir/docker-responses"
printf '%s\n' \
  error \
  '{"workflow_runs":[{"id":106,"status":"in_progress","conclusion":null,"html_url":"https://github.example/runs/106","created_at":"2026-07-28T18:00:00Z"}]}' \
  '{"workflow_runs":[{"id":106,"status":"completed","conclusion":"success","html_url":"https://github.example/runs/106","created_at":"2026-07-28T18:00:00Z"}]}' \
  > "$case_dir/gh-responses"
run_case 3 1
assert_eq 0 "$status" 'transient GitHub API failure is retried'
assert_command_calls 3 gh \
  'GitHub API is queried again after a transient failure'
assert_file_lines 2 "$case_dir/sleep-args" \
  'transient GitHub API failure consumes bounded wait intervals'
assert_contains "$error" 'simulated GitHub API failure' \
  'transient GitHub API failure remains visible in diagnostics'

start_case
printf '%s\n' missing > "$case_dir/docker-responses"
printf '%s\n' error > "$case_dir/gh-responses"
run_case 2 1
assert_eq 1 "$status" 'persistent GitHub API failure blocks release'
assert_contains "$error" \
  "Unable to inspect the Runner Image workflow for ${commit_sha} within 2 seconds" \
  'persistent GitHub API failure reports exact workflow lookup and timeout'
assert_contains "$error" 'simulated GitHub API failure' \
  'persistent GitHub API failure reports the last API error'
assert_command_calls 3 gh \
  'persistent GitHub API failure is retried through the deadline'
assert_command_calls 0 docker \
  'GitHub API failure cannot use the missing-run manifest fallback'

printf '1..%s\n' "$tests"
