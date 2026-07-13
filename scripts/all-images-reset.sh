#!/usr/bin/env bash
# Removes ALL profile images (every ecosystem: ruby, python, node, go, java,
# php, rust, ...) so the next scan rebuilds them, then pulls the latest upstream
# runner. Pass --force to skip the confirmation. Implementation +
# macOS/bash-3.2 notes: scripts/_profile-reset.sh
#
# glob/desc are consumed by the sourced helper (invisible to shellcheck without
# -x), and the source path is dynamic (SC1091). Suppress both file-wide.
# shellcheck disable=SC2034,SC1091
glob='scrutineer-profile-*'
desc='ALL profile'
. "$(dirname "$0")/_profile-reset.sh"
