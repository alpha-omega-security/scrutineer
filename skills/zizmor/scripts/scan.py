#!/usr/bin/env python3
"""Run zizmor against ./src/.github/workflows and emit findings in
scrutineer's shape. Requires zizmor on PATH. Writes JSON to stdout.
"""
import json
import os
import shutil
import subprocess
import sys

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
        ["zizmor", "--format", "json", ".github/workflows"],
        cwd="./src",
        capture_output=True,
        text=True,
    )
    # zizmor exits non-zero when it has findings; that's not a failure.
    if proc.returncode not in (0, 14):
        print(json.dumps({"findings": [], "error": proc.stderr.strip()[:2000]}))
        return

    try:
        data = json.loads(proc.stdout) if proc.stdout else []
    except json.JSONDecodeError as exc:
        print(json.dumps({"findings": [], "error": f"zizmor json: {exc}"}))
        return

    if isinstance(data, dict):
        data = data.get("findings", [])

    findings = []
    for i, r in enumerate(data, start=1):
        severity = SEVERITY_MAP.get(str(r.get("determinations", {}).get("severity", "")).lower(), "Medium")
        locations = r.get("locations") or []
        loc = "unknown"
        if locations:
            sym = locations[0].get("symbolic") or {}
            key = sym.get("key") or {}
            path = key.get("local", {}).get("given_path") or key.get("Local", {}).get("given_path") or "workflow"
            line = locations[0].get("concrete", {}).get("location", {}).get("start_point", {}).get("row")
            loc = f"{path}:{line}" if line else path
        findings.append({
            "id": f"F{i}",
            "title": r.get("ident") or r.get("desc") or "zizmor finding",
            "severity": severity,
            "location": loc,
            "trace": r.get("desc", "").strip(),
            "rating": f"{severity} from zizmor rule {r.get('ident', '')}",
        })

    print(json.dumps({"findings": findings}))


if __name__ == "__main__":
    main()
