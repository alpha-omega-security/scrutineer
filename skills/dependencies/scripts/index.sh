#!/usr/bin/env bash
# Run the git-pkgs dependency analyses against the clone and emit a single
# versioned envelope on stdout. Each analysis has its own status so a
# registry timeout in one does not discard a valid inventory from another.
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

commit="$(git rev-parse HEAD 2>/dev/null || true)"
gp_version="$(git-pkgs --version 2>/dev/null || true)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# One line per section: <name> <command> [args...]. Each command's stdout,
# stderr, and exit code are captured independently so the assembler can
# report partial failure.
sections=(
  "inventory       list       --format json"
  "sbom            sbom       --format json"
  "licenses        licenses   --format json"
  "vulnerabilities vulns      --format json"
  "outdated        outdated   --format json"
  "deprecated      deprecated --format json"
)

for spec in "${sections[@]}"; do
  read -r name cmd rest <<<"$spec"
  # shellcheck disable=SC2086
  if git-pkgs "$cmd" $rest >"$work/$name.json" 2>"$work/$name.err"; then
    echo 0 >"$work/$name.exit"
  else
    echo $? >"$work/$name.exit"
  fi
done

WORK="$work" COMMIT="$commit" GP_VERSION="$gp_version" python3 - <<'PY'
import json, os, sys, datetime

work = os.environ["WORK"]
sections = ["inventory", "sbom", "licenses", "vulnerabilities", "outdated", "deprecated"]
# licenses/vulns/outdated/deprecated currently emit a bare array; once
# git-pkgs/git-pkgs#306 lands they emit {"results": [...], "sources": [...]}.
# Normalise both so this script keeps working across the transition.
shimmed = {"licenses", "vulnerabilities", "outdated", "deprecated"}

def load(name):
    with open(os.path.join(work, name + ".exit")) as f:
        code = int(f.read().strip() or "1")
    with open(os.path.join(work, name + ".err"), errors="replace") as f:
        err = f.read().strip()
    raw = open(os.path.join(work, name + ".json"), errors="replace").read().strip()
    if code != 0:
        return {"status": "error", "error": err or f"git-pkgs exited {code}"}
    if raw in ("", "null"):
        result = [] if name != "sbom" else {}
    else:
        try:
            result = json.loads(raw)
        except ValueError as e:
            return {"status": "error", "error": f"parse output: {e}"}
    section = {"status": "ok"}
    if name in shimmed:
        if isinstance(result, dict) and "results" in result:
            section["result"] = result.get("results") or []
            section["sources"] = result.get("sources") or []
        elif isinstance(result, list):
            section["result"] = result
            section["sources"] = []
        else:
            return {"status": "error", "error": f"unexpected {type(result).__name__} output"}
    else:
        section["result"] = result
    if err:
        section["warnings"] = [err]
    return section

envelope = {
    "schema_version": 1,
    "commit": os.environ.get("COMMIT", ""),
    "generated_at": datetime.datetime.now(datetime.timezone.utc)
        .isoformat().replace("+00:00", "Z"),
    "git_pkgs_version": os.environ.get("GP_VERSION", ""),
    "analyses": {name: load(name) for name in sections},
}
json.dump(envelope, sys.stdout, separators=(",", ":"))
sys.stdout.write("\n")
PY
