#!/usr/bin/env bash
# Produce a CycloneDX SBOM for the clone using git-pkgs. Output is JSON on
# stdout so the skill can redirect it straight to report.json.
set -euo pipefail

if ! command -v git-pkgs >/dev/null 2>&1; then
  echo "git-pkgs not found on PATH" >&2
  exit 127
fi

cd ./src
git fetch --unshallow --quiet >/dev/null 2>&1 || true
git-pkgs init --no-hooks >/dev/null

# stdout is pure JSON; stderr carries progress and warnings (consumers
# should ignore stderr).
git-pkgs sbom --format json
