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
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
git-pkgs list --format json > "$tmp"
python3 - "$tmp" <<'PY'
import json
import sys

raw = open(sys.argv[1], encoding="utf-8").read().strip()
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
PY
