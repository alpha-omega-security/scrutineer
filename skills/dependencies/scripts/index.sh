#!/usr/bin/env bash
# Run the two per-repository git-pkgs analyses against the clone and emit a
# versioned envelope on stdout. Each analysis has its own status so a failure
# in one does not discard a valid result from the other. Per-package registry
# lookups (licences, vulnerabilities, latest-version, deprecation) are not run
# here; scrutineer performs those once per package outside the scan.
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
# report partial failure. sbom runs with --skip-enrichment so no registry is
# contacted from inside the scan; scrutineer fills licence data per package.
sections=(
  "inventory list --format json"
  "sbom      sbom --format json --skip-enrichment"
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
sections = ["inventory", "sbom"]

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
    section = {"status": "ok", "result": result}
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
