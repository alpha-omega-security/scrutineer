#!/usr/bin/env bash
# Index every dependency manifest in the clone and wrap git-pkgs's output in
# the `{"dependencies": [...]}` envelope the scrutineer parser expects. Exits
# non-zero with an informative message if git-pkgs is missing or emits a
# non-array JSON value other than null.
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
# Older git-pkgs builds can emit null or nothing when they find no manifests;
# both mean "no dependencies" here, not permission to infer rows by hand.
git-pkgs list --format json | python3 -c 'import json, sys
raw = sys.stdin.read().strip()
if raw == "" or raw == "null":
    deps = []
else:
    deps = json.loads(raw)
if deps is None:
    deps = []
if not isinstance(deps, list):
    raise SystemExit(f"git-pkgs list returned {type(deps).__name__}, want array")
json.dump({"dependencies": deps}, sys.stdout, separators=(",", ":"))
sys.stdout.write("\n")
'
