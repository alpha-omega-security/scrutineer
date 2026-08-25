#!/usr/bin/env bash
set -euo pipefail

src="${1:-./src}"
report="${2:-./report.json}"

if ! command -v brief >/dev/null 2>&1; then
  echo "brief not found on PATH" >&2
  exit 127
fi

src="$(cd "$src" && pwd -P)"
report_dir="$(cd "$(dirname "$report")" && pwd -P)"
report="$report_dir/$(basename "$report")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

brief --json "$src" > "$work/root.json"

# Brief 0.12.0 can omit native files in submodules, including submodules under
# ignored directories such as vendor. Remove this loop when
# https://github.com/git-pkgs/brief/issues/158 adds an include-submodules scan.
submodule_reports=()
if git -C "$src" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  while IFS= read -r -d '' submodule; do
    submodule_report="$work/submodule-${#submodule_reports[@]}.json"
    brief --json "$submodule" > "$submodule_report"
    submodule_reports+=("$submodule_report")
  done < <(git -C "$src" submodule foreach --quiet --recursive 'printf "%s\0" "$PWD"')
fi

# The envelope keeps each Brief report intact. Once Brief can include submodules
# in the root report, replace it with that single report and update the schema.
{
  printf '{"schema_version":1,"root":'
  cat "$work/root.json"
  printf ',"submodules":['
  separator=""
  for submodule_report in "${submodule_reports[@]}"; do
    printf '%s' "$separator"
    cat "$submodule_report"
    separator=","
  done
  printf ']}\n'
} > "$work/report.json"

mv "$work/report.json" "$report"
