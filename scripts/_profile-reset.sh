#!/usr/bin/env bash
# Shared implementation for scripts/ruby-image-reset.sh and scripts/all-images-reset.sh.
# NOT run directly — each wrapper sets `glob` and `desc`, then sources this file.
#
# Removes locally-built profile images matching $glob (forcing a rebuild on the
# next scan) and pulls the latest upstream runner image they build FROM. Uses
# docker if present, otherwise podman. Profile images are tagged by content
# hash (not :latest), so they are matched by repository glob. Pass -f/--force
# to a wrapper to skip the confirmation prompt.
#
# macOS bash compatibility — this must stay runnable under bash 3.2 (the
# /bin/bash Apple ships) and BSD userland. Do NOT "modernise" it:
#   * No arrays / mapfile: an empty "${arr[@]}" is an "unbound variable" error
#     under `set -u` on bash < 4.4 (incl. macOS 3.2). Image ids are held in a
#     newline string and intentionally word-split into rmi.
#   * No `xargs -r`: -r is a GNU extension that BSD/macOS xargs rejects; the
#     `[ -n "$ids" ]` guard is the portable equivalent.
#   * `pipefail` (bash 3.0+) and `read -rp` (bash 3.2+) are safe.

set -euo pipefail
glob="${glob:?internal error: sourcing wrapper must set glob}"
desc="${desc:?internal error: sourcing wrapper must set desc}"

force=0
for a in "$@"; do
  case "$a" in
    -f|--force) force=1 ;;
    *)
      printf 'unknown argument: %s\nusage: %s [-f|--force]\n' "$a" "$(basename "$0")" >&2
      exit 2
      ;;
  esac
done

rt=podman
command -v docker >/dev/null && rt=docker

if [ "$force" -ne 1 ]; then
  read -rp "Remove $desc images via $rt and pull the latest runner? [y/N] " ans || true
  case "${ans:-}" in
    [yY] | [yY][eE][sS]) ;;
    *) echo "aborted."; exit 0 ;;
  esac
fi

ids=$("$rt" images -qf reference="$glob")
# shellcheck disable=SC2086 # intentional word-split: rmi takes each image id as a separate arg
[ -n "$ids" ] && "$rt" rmi -f $ids
"$rt" pull ghcr.io/alpha-omega-security/scrutineer-runner:latest
