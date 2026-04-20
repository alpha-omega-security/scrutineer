#!/usr/bin/env bash
# Index every dependency manifest in the clone and wrap git-pkgs's array
# output in the `{"dependencies": [...]}` envelope the scrutineer parser
# expects. Exits non-zero with an informative message if git-pkgs is missing.
set -euo pipefail

if ! command -v git-pkgs >/dev/null 2>&1; then
  echo "git-pkgs not found on PATH" >&2
  exit 127
fi

cd ./src

# git-pkgs walks history; the clone may be shallow. Unshallow is a no-op
# if the clone is already full.
git fetch --unshallow --quiet >/dev/null 2>&1 || true

git-pkgs init --no-hooks >/dev/null

# Wrap the array in a top-level object so the output matches schema.json.
printf '{"dependencies": '
git-pkgs list --format json
printf '}\n'
