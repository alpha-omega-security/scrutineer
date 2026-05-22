#!/usr/bin/env python3
"""Run semgrep against ./src and emit the findings in scrutineer's shape.

Requires semgrep on PATH. Writes structured JSON to stdout. Stderr carries
progress and errors.

semgrep is invoked with cwd=./src so paths in results are repo-relative
(e.g. `lib/foo.py:42`) rather than carrying a `src/` prefix.

Results are grouped by (check_id, message): the rule's message template
interpolates whatever metavars the rule author considered significant, so
identical messages are the rule author's signal that the matches are
equivalent. Each group becomes one finding with the full set of file:line
positions in `locations` (#191).
"""
import json
import shutil
import subprocess
import sys
from collections import defaultdict

SEVERITY_MAP = {
    "ERROR": "High",
    "WARNING": "Medium",
    "INFO": "Low",
    "INVENTORY": "Low",
    "EXPERIMENT": "Low",
}


def main():
    if shutil.which("semgrep") is None:
        print(json.dumps({"findings": [], "error": "semgrep not on PATH"}))
        sys.exit(0)

    proc = subprocess.run(
        [
            "semgrep",
            "--config",
            "p/security-audit",
            "--config",
            "p/secrets",
            "--json",
            "--quiet",
            ".",
        ],
        cwd="./src",
        capture_output=True,
        text=True,
    )
    # exit code 1 means findings; 0 means clean; anything else is failure.
    if proc.returncode not in (0, 1):
        print(json.dumps({"findings": [], "error": proc.stderr.strip()[:2000]}))
        sys.exit(0)

    try:
        data = json.loads(proc.stdout) if proc.stdout else {"results": []}
    except json.JSONDecodeError as exc:
        print(json.dumps({"findings": [], "error": f"semgrep json: {exc}"}))
        sys.exit(0)

    groups = defaultdict(list)
    for r in data.get("results", []):
        extra = r.get("extra") or {}
        key = (r.get("check_id", "semgrep match"), extra.get("message", "").strip())
        groups[key].append(r)

    findings = []
    for i, ((check_id, message), results) in enumerate(groups.items(), start=1):
        first = results[0]
        extra = first.get("extra") or {}
        meta = extra.get("metadata") or {}
        cwe = ""
        raw_cwe = meta.get("cwe") or meta.get("cwe_id")
        if isinstance(raw_cwe, list) and raw_cwe:
            raw_cwe = raw_cwe[0]
        if isinstance(raw_cwe, str) and raw_cwe.startswith("CWE-"):
            cwe = raw_cwe.split()[0]
        severity = SEVERITY_MAP.get(str(extra.get("severity", "")).upper(), "Medium")

        locations = sorted({result_location(r) for r in results})
        n = len(locations)
        suffix = f" ({n} locations)" if n > 1 else ""
        findings.append({
            "id": f"F{i}",
            "title": check_id,
            "severity": severity,
            "cwe": cwe,
            "location": locations[0],
            "locations": locations,
            "trace": message,
            "rating": f"{severity} from semgrep rule {check_id}{suffix}",
        })

    print(json.dumps({"findings": findings}))


def result_location(r):
    path = r.get("path", "")
    start = r.get("start") or {}
    return f"{path}:{start.get('line', 0)}" if path else "unknown"


if __name__ == "__main__":
    main()
