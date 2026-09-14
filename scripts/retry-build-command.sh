#!/bin/sh
# Retry idempotent build commands without changing their verification settings.
set -eu

if [ "$#" -eq 0 ]; then
  echo "usage: retry-build-command.sh command [args...]" >&2
  exit 64
fi

attempt=1
while :; do
  if "$@"; then
    exit 0
  else
    status=$?
  fi
  if [ "$attempt" -ge 3 ]; then
    echo "build command failed after $attempt attempts (exit $status)" >&2
    exit "$status"
  fi
  delay=$((attempt * 5))
  echo "build command failed (exit $status); retrying in ${delay}s" >&2
  sleep "$delay"
  attempt=$((attempt + 1))
done
