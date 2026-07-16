#!/usr/bin/env bash
# Ensures Renovate or a manual edit cannot leave the runner, main image, and
# threat-model documentation on different Claude Code releases. Keep this
# compatible with macOS bash 3.2 and BSD userland so it also runs locally.

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)

runner_amd64=$(sed -E -n \
  's/^ARG CLAUDE_AMD64_LOCK=v([0-9]+\.[0-9]+\.[0-9]+)@sha256:[0-9a-f]{64}$/\1/p' \
  "$root/Dockerfile.runner")
runner_arm64=$(sed -E -n \
  's/^ARG CLAUDE_ARM64_LOCK=v([0-9]+\.[0-9]+\.[0-9]+)@sha256:[0-9a-f]{64}$/\1/p' \
  "$root/Dockerfile.runner")
main_image=$(sed -E -n \
  's|^RUN npm install -g @anthropic-ai/claude-code@([0-9]+\.[0-9]+\.[0-9]+)$|\1|p' \
  "$root/Dockerfile")
# Backticks in this pattern are literal Markdown delimiters, not shell syntax.
# shellcheck disable=SC2016
documented=$(sed -E -n \
  's/.*`claude-code@([0-9]+\.[0-9]+\.[0-9]+)`.*/\1/p' \
  "$root/threatmodel.md")

require_single() {
  local label=$1
  local value=$2
  local count
  count=$(printf '%s\n' "$value" | awk 'NF { count++ } END { print count + 0 }')
  if [ "$count" -ne 1 ]; then
    printf 'expected exactly one Claude Code version in %s, found %s\n' "$label" "$count" >&2
    return 1
  fi
}

require_single 'Dockerfile.runner amd64 lock' "$runner_amd64"
require_single 'Dockerfile.runner arm64 lock' "$runner_arm64"
require_single 'Dockerfile npm install' "$main_image"
require_single 'threatmodel.md tool list' "$documented"

if [ "$runner_amd64" != "$runner_arm64" ] || \
   [ "$runner_amd64" != "$main_image" ] || \
   [ "$runner_amd64" != "$documented" ]; then
  printf '%s\n' \
    'Claude Code version pins disagree:' \
    "  Dockerfile.runner amd64: $runner_amd64" \
    "  Dockerfile.runner arm64: $runner_arm64" \
    "  Dockerfile npm install:  $main_image" \
    "  threatmodel.md:          $documented" >&2
  exit 1
fi

printf 'Claude Code version pins agree: %s\n' "$runner_amd64"
