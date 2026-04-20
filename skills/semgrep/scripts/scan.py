#!/usr/bin/env python3
"""Run semgrep against ./src and emit the findings in scrutineer's shape.

Requires semgrep on PATH. Writes structured JSON to stdout. Stderr carries
progress and errors.
"""
import json
import shutil
import subprocess
import sys

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
            "./src",
        ],
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

    findings = []
    for i, r in enumerate(data.get("results", []), start=1):
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        cwe = ""
        raw_cwe = meta.get("cwe") or meta.get("cwe_id")
        if isinstance(raw_cwe, list) and raw_cwe:
            raw_cwe = raw_cwe[0]
        if isinstance(raw_cwe, str) and raw_cwe.startswith("CWE-"):
            cwe = raw_cwe.split()[0]
        severity = SEVERITY_MAP.get(str(extra.get("severity", "")).upper(), "Medium")
        start = r.get("start") or {}
        path = r.get("path", "")
        location = f"{path}:{start.get('line', 0)}" if path else "unknown"
        findings.append({
            "id": f"F{i}",
            "title": r.get("check_id", "semgrep match"),
            "severity": severity,
            "cwe": cwe,
            "location": location,
            "trace": extra.get("message", "").strip(),
            "rating": f"{severity} from semgrep rule {r.get('check_id', '')}",
        })

    print(json.dumps({"findings": findings}))


if __name__ == "__main__":
    main()
