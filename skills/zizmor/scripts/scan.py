#!/usr/bin/env python3
"""Run zizmor against ./src/.github/workflows and emit findings in
scrutineer's shape. Requires zizmor on PATH. Writes JSON to stdout.

Results are grouped by (ident, desc) so the same audit firing on every
job in a workflow becomes one finding with the full set of file:line
positions in `locations` (#191).
"""
import json
import os
import shutil
import subprocess
import sys
from collections import defaultdict

SEVERITY_MAP = {
    "unknown": "Low",
    "informational": "Low",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}


def main():
    workflows = os.path.join("./src", ".github", "workflows")
    if not os.path.isdir(workflows):
        print(json.dumps({"findings": [], "error": "no .github/workflows dir"}))
        return

    if shutil.which("zizmor") is None:
        print(json.dumps({"findings": [], "error": "zizmor not on PATH"}))
        return

    proc = subprocess.run(
        ["zizmor", "--no-exit-codes", "--format", "json", ".github/workflows"],
        cwd="./src",
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(json.dumps({"findings": [], "error": proc.stderr.strip()[:2000]}))
        return

    try:
        data = json.loads(proc.stdout) if proc.stdout else []
    except json.JSONDecodeError as exc:
        print(json.dumps({"findings": [], "error": f"zizmor json: {exc}"}))
        return

    if isinstance(data, dict):
        data = data.get("findings", [])

    groups = defaultdict(list)
    for r in data:
        key = (r.get("ident") or "zizmor finding", (r.get("desc") or "").strip())
        groups[key].append(r)

    findings = []
    for i, ((ident, desc), results) in enumerate(groups.items(), start=1):
        first = results[0]
        severity = SEVERITY_MAP.get(
            str(first.get("determinations", {}).get("severity", "")).lower(), "Medium"
        )
        locations = sorted({result_location(r) for r in results})
        n = len(locations)
        suffix = f" ({n} locations)" if n > 1 else ""
        findings.append({
            "id": f"F{i}",
            "title": ident,
            "severity": severity,
            "location": locations[0],
            "locations": locations,
            "trace": desc,
            "rating": f"{severity} from zizmor rule {ident}{suffix}",
            "references": [{
                "url": f"https://docs.zizmor.sh/audits/#{ident}",
                "summary": f"zizmor docs: {ident}",
                "tags": "docs",
            }],
        })

    print(json.dumps({"findings": findings}))


def result_location(r):
    locations = r.get("locations") or []
    if not locations:
        return "unknown"
    sym = locations[0].get("symbolic") or {}
    key = sym.get("key") or {}
    path = key.get("local", {}).get("given_path") or key.get("Local", {}).get("given_path") or "workflow"
    row = locations[0].get("concrete", {}).get("location", {}).get("start_point", {}).get("row")
    return f"{path}:{row + 1}" if row is not None else path


if __name__ == "__main__":
    main()
