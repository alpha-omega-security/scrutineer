#!/usr/bin/env bash
set -euo pipefail

cd ./src

if [[ ! -f go.mod ]]; then
  printf '%s\n' '{"capabilities":{},"error":"no repository-root go.mod"}'
  exit 0
fi

report=$(mktemp ./capslock.XXXXXX)
trap 'rm -f "$report"' EXIT

# -force_local_module prevents Capslock's fallback mode from creating a
# temporary module and downloading packages not declared by this repository.
if ! capslock -force_local_module -output package -packages ./... >"$report"; then
  printf '%s\n' '{"capabilities":{},"error":"capslock analysis failed; inspect scan log"}'
  exit 0
fi

printf '%s' '{"capabilities":'
cat "$report"
printf '%s\n' '}'
