#!/usr/bin/env bash
#
# Re-scan monorepo sub-packages on a schedule via scrutineer's local API.
#
# Works for any ecosystem the subprojects skill detects (go module, npm package,
# python package, rust crate, ruby gem, ...). Scrutineer has no per-sub-package
# scheduler -- its recurring schedule is repo-root only -- but re-submitting
# `owner/repo#sub/dir` re-runs the full pipeline for that sub-package (triage
# skips whatever is already current at HEAD), so a cron job or systemd timer
# covers the gap.
#
# The enqueue endpoint is localhost-only and rejects cross-site *browser* POSTs,
# but a header-less client like curl is allowed, so no token is needed.
#
# Usage:   scripts/rescan-subprojects.sh LIST_FILE [BASE_URL]
# Example: scripts/rescan-subprojects.sh subprojects.txt http://127.0.0.1:8080
#
# LIST_FILE holds one `repo#sub/dir` URL per line, any forge or ecosystem; blank
# lines and lines starting with '#' are ignored:
#   https://github.com/rails/rails#activesupport                      (ruby gem)
#   https://github.com/vercel/next.js#packages/next                   (npm)
#   https://github.com/kubernetes/kubernetes#staging/src/k8s.io/api   (go module)
#
# systemd timer (daily):
#   # /etc/systemd/system/scrutineer-rescan.service
#   [Service]
#   Type=oneshot
#   ExecStart=/opt/scrutineer/scripts/rescan-subprojects.sh /opt/scrutineer/subprojects.txt
#
#   # /etc/systemd/system/scrutineer-rescan.timer
#   [Timer]
#   OnCalendar=daily
#   Persistent=true
#   [Install]
#   WantedBy=timers.target
#
set -euo pipefail

list_file=${1:?usage: rescan-subprojects.sh LIST_FILE [BASE_URL]}
base_url=${2:-http://127.0.0.1:8080}

# Drop comments and blank lines; the bulk endpoint would reject a '#'-comment as
# an invalid URL. --data-urlencode keeps the '#sub/dir' fragment intact (it
# would otherwise be stripped as a URL fragment).
urls=$(grep -vE '^[[:space:]]*(#|$)' "$list_file" || true)
if [ -z "$urls" ]; then
	echo "no URLs in $list_file" >&2
	exit 1
fi

count=$(printf '%s\n' "$urls" | grep -c .)
echo "enqueueing $count sub-package scan(s) at $base_url"
curl -fsS -X POST "$base_url/repositories/bulk" \
	--data-urlencode "urls=$urls" >/dev/null
echo "done; watch progress in the UI or the Scans tab"
