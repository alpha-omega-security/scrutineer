#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: wait-for-runner-image.sh REPOSITORY COMMIT_SHA WAIT_SECONDS POLL_SECONDS

Wait for the successful Runner Image push workflow for COMMIT_SHA, then print
the immutable GHCR image reference for that commit.
EOF
  exit 2
}

fail() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}

is_nonnegative_integer() {
  [[ "$1" =~ ^(0|[1-9][0-9]*)$ ]]
}

[ "$#" -eq 4 ] || usage

repository=$1
commit_sha=$2
wait_seconds=$3
poll_seconds=$4

[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || \
  fail "Invalid GitHub repository: ${repository}"
[[ "$commit_sha" =~ ^[0-9a-f]{40}$ ]] || \
  fail "Invalid commit SHA: ${commit_sha}"
is_nonnegative_integer "$wait_seconds" || \
  fail "WAIT_SECONDS must be a non-negative integer, got ${wait_seconds}"
is_nonnegative_integer "$poll_seconds" || \
  fail "POLL_SECONDS must be a positive integer, got ${poll_seconds}"
[ "$poll_seconds" -gt 0 ] || \
  fail "POLL_SECONDS must be greater than zero"

runner_tag="ghcr.io/${repository}-runner:sha-${commit_sha}"
workflow_path="runner-image.yml"
branch="main"
error_file=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/wait-for-runner-image.XXXXXX") || \
  fail "Could not create a temporary error file"
trap 'rm -f "$error_file"' EXIT
elapsed=0
last_state=""
run_id=""
run_status=""
run_conclusion=""
run_url=""

print_last_error() {
  if [ -s "$error_file" ]; then
    printf 'Last command error:\n' >&2
    cat "$error_file" >&2
  fi
}

resolve_image() {
  local manifest digest

  : > "$error_file"
  if ! manifest=$(docker buildx imagetools inspect \
    "$runner_tag" --format '{{json .Manifest}}' 2>"$error_file"); then
    return 1
  fi

  : > "$error_file"
  if ! digest=$(jq -r '.digest // empty' <<< "$manifest" 2>"$error_file"); then
    print_last_error
    fail "Could not parse the manifest for ${runner_tag}"
  fi
  if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    fail "Could not resolve a manifest digest for ${runner_tag}"
  fi

  printf 'ghcr.io/%s-runner@%s\n' "$repository" "$digest"
  exit 0
}

while :; do
  api_failed=false
  : > "$error_file"
  if ! run_info=$(gh api -X GET \
    "repos/${repository}/actions/workflows/${workflow_path}/runs" \
    -f event=push \
    -f branch="$branch" \
    -f head_sha="$commit_sha" \
    -F per_page=10 \
    --jq '.workflow_runs
      | sort_by(.created_at)
      | reverse
      | .[0]
      | if . == null then ""
        else [(.id | tostring), .status, (.conclusion // ""), .html_url]
          | join("|")
        end' 2>"$error_file"); then
    api_failed=true
    run_info=""
  fi

  if [ "$api_failed" = true ]; then
    state="api-error"
  else
    run_id=""
    run_status=""
    run_conclusion=""
    run_url=""
    if [ -n "$run_info" ]; then
      IFS='|' read -r run_id run_status run_conclusion run_url <<< "$run_info"
    fi

    if [ "$run_status" = "completed" ] \
      && [ -n "$run_conclusion" ] \
      && [ "$run_conclusion" != "success" ]; then
      fail "Runner Image run ${run_url:-${run_id}} completed with conclusion ${run_conclusion}; refusing to release ${commit_sha}"
    fi

    # A run that still has work left must finish successfully even if its merge
    # step has already made the manifest briefly visible. If Actions no longer
    # retains a run for an older commit, the immutable image remains sufficient.
    if [ -z "$run_id" ] \
      || { [ "$run_status" = "completed" ] && [ "$run_conclusion" = "success" ]; }; then
      resolve_image || true
    fi

    state="${run_id}|${run_status}|${run_conclusion}"
  fi

  if [ "$state" != "$last_state" ]; then
    if [ "$api_failed" = true ]; then
      printf 'Unable to inspect the Runner Image workflow; retrying\n' >&2
      print_last_error
    elif [ -z "$run_id" ]; then
      printf 'Waiting for the Runner Image push run for %s to appear\n' \
        "$commit_sha" >&2
    elif [ "$run_status" = "completed" ] && [ "$run_conclusion" = "success" ]; then
      printf 'Runner Image run %s succeeded; waiting for %s to become readable\n' \
        "$run_url" "$runner_tag" >&2
    elif [ "$run_status" = "completed" ]; then
      printf 'Runner Image run %s completed without a conclusion; waiting for a stable result\n' \
        "$run_url" >&2
    else
      printf 'Waiting for Runner Image run %s (status: %s)\n' \
        "$run_url" "${run_status:-unknown}" >&2
    fi
    last_state=$state
  fi

  if [ "$elapsed" -ge "$wait_seconds" ]; then
    if [ "$api_failed" = true ]; then
      print_last_error
      fail "Unable to inspect the Runner Image workflow for ${commit_sha} within ${wait_seconds} seconds"
    elif [ -z "$run_id" ]; then
      print_last_error
      fail "No Runner Image push run appeared for ${commit_sha} within ${wait_seconds} seconds"
    elif [ "$run_status" = "completed" ] && [ "$run_conclusion" = "success" ]; then
      print_last_error
      fail "Runner Image run ${run_url} succeeded, but ${runner_tag} was unavailable after ${wait_seconds} seconds"
    elif [ "$run_status" = "completed" ]; then
      fail "Timed out after ${wait_seconds} seconds waiting for Runner Image run ${run_url} to report a conclusion"
    else
      fail "Timed out after ${wait_seconds} seconds waiting for Runner Image run ${run_url} (status: ${run_status:-unknown})"
    fi
  fi

  delay=$poll_seconds
  if [ $((elapsed + delay)) -gt "$wait_seconds" ]; then
    delay=$((wait_seconds - elapsed))
  fi
  sleep "$delay"
  elapsed=$((elapsed + delay))
done
