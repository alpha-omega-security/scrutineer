#!/usr/bin/env bash
# OSS-CRS auditor entrypoint: runs `scrutineer audit` against the read-only
# target source then submits the results through libCRS.
set -euo pipefail

LIBCRS=${LIBCRS:-libCRS}
SCRUTINEER=${SCRUTINEER:-scrutineer}

if [ -z "${OSS_CRS_TARGET_SOURCE:-}" ] || [ ! -d "$OSS_CRS_TARGET_SOURCE" ]; then
  echo "run-auditor: OSS_CRS_TARGET_SOURCE must name an existing directory" >&2
  exit 2
fi

work=${SCRUTINEER_AUDIT_WORK:-/tmp/scrutineer-audit}
out=$work/out
data=$work/data
logs=$work/logs
# data starts empty: scrutineer audit refuses one that holds a database.
# register-log-dir refuses an existing path because it creates logs as a
# symlink into OSS_CRS_LOG_DIR.
rm -rf "$out" "$data" "$logs"
mkdir -p "$out" "$data"
if [ -n "${OSS_CRS_LOG_DIR:-}" ] && command -v "$LIBCRS" > /dev/null 2>&1; then
  "$LIBCRS" register-log-dir "$logs"
else
  mkdir -p "$logs"
fi

args=()
if [ -n "${OSS_CRS_LLM_API_URL:-}" ]; then
  export ANTHROPIC_BASE_URL=$OSS_CRS_LLM_API_URL
  host=${OSS_CRS_LLM_API_URL#*://}
  host=${host%%/*}
  host=${host##*@}
  host=${host%%:*}
  args+=(-trusted-model-host "$host")
fi
if [ -n "${OSS_CRS_LLM_API_KEY_FILE:-}" ]; then
  ANTHROPIC_API_KEY=$(cat "$OSS_CRS_LLM_API_KEY_FILE")
  export ANTHROPIC_API_KEY
fi
if [ -n "${SCRUTINEER_MODEL:-}" ]; then
  args+=(-model "$SCRUTINEER_MODEL")
  # Claude Code's background model must also exist in the LiteLLM config.
  export ANTHROPIC_DEFAULT_HAIKU_MODEL=${ANTHROPIC_DEFAULT_HAIKU_MODEL:-$SCRUTINEER_MODEL}
fi
if [ -n "${SCRUTINEER_AUDIT_TIMEOUT:-}" ]; then
  args+=(-audit-timeout "$SCRUTINEER_AUDIT_TIMEOUT")
fi
if [ -n "${SCRUTINEER_CONCURRENCY:-}" ]; then
  args+=(-concurrency "$SCRUTINEER_CONCURRENCY")
fi

# claude refuses bypassPermissions as root and the agent should not hold root
# inside the CRS container, so the audit runs as the runner user.
runas=()
if [ "$(id -u)" = 0 ]; then
  user=${SCRUTINEER_AUDIT_USER:-runner}
  if id "$user" > /dev/null 2>&1; then
    chown -R "$user" "$out" "$data"
    home=$(getent passwd "$user" | cut -d: -f6)
    runas=(setpriv "--reuid=$user" "--regid=$user" --init-groups env "HOME=${home:-/home/$user}")
  fi
fi

# Background plus wait so a TERM from the framework reaches scrutineer, which
# then writes partial outputs that are still submitted below.
exec 3> >(tee "$logs/scrutineer.log")
tee_pid=$!
${runas[@]+"${runas[@]}"} "$SCRUTINEER" audit -no-container \
  -source "$OSS_CRS_TARGET_SOURCE" -out "$out" -data "$data" ${args[@]+"${args[@]}"} \
  >&3 2>&1 &
pid=$!
trap 'kill -TERM "$pid" 2> /dev/null || true' TERM INT
# A trapped signal interrupts wait before scrutineer exits, so wait again
# until the child is reaped and status holds its real exit code.
while :; do
  status=0
  wait "$pid" || status=$?
  kill -0 "$pid" 2> /dev/null || break
done
trap - TERM INT
# Close the log pipe and let tee flush before the log dir is read.
exec 3>&-
wait "$tee_pid" 2> /dev/null || true

case $status in
  0 | 3) ;;
  *) exit "$status" ;;
esac
if [ -f "$out/bug-candidates/scrutineer.sarif" ]; then
  "$LIBCRS" submit bug-candidate "$out/bug-candidates/scrutineer.sarif"
fi
"$LIBCRS" submit report "$out/scrutineer-audit"
# OSS-CRS aborts the campaign as failed on a non-zero module exit, so an
# incomplete or interrupted audit whose results were submitted exits 0. Its
# status is in audit.json.
if [ "$status" = 3 ]; then
  echo "run-auditor: audit did not complete; see audit.json in the submitted report" >&2
fi
exit 0
