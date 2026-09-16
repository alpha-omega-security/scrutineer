#!/usr/bin/env python3
"""Run Betterleaks against ./src and emit Scrutineer findings.

Betterleaks' raw JSON contains matched credentials and related context. This
adapter only reads fields needed to identify and locate a detection. It never
copies raw matches, secrets, capture groups, or repository metadata.
"""
import json
import os
import shutil
import subprocess


def main():
    if not os.path.isdir("./src"):
        print(json.dumps({"findings": [], "error": "no ./src directory"}))
        return

    if shutil.which("betterleaks") is None:
        print(json.dumps({"findings": [], "error": "betterleaks not on PATH"}))
        return

    proc = subprocess.run(
        [
            "betterleaks",
            "git",
            ".",
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--redact=100",
            "--exit-code",
            "0",
            "--no-banner",
        ],
        cwd="./src",
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        error = proc.stderr.strip() or f"betterleaks exited {proc.returncode}"
        print(json.dumps({"findings": [], "error": error[:2000]}))
        return

    try:
        data = json.loads(proc.stdout) if proc.stdout else []
    except json.JSONDecodeError as exc:
        print(json.dumps({"findings": [], "error": f"betterleaks json: {exc}"}))
        return

    if data is None:
        results = []
    elif isinstance(data, dict):
        results = data.get("findings") or []
    elif isinstance(data, list):
        results = data
    else:
        print(json.dumps({"findings": [], "error": "betterleaks json: expected a list"}))
        return

    findings = []
    for i, result in enumerate(results, start=1):
        if not isinstance(result, dict):
            continue
        rule_id = str(result.get("RuleID") or "betterleaks finding")
        location = result_location(result)
        finding = {
            "id": f"F{i}",
            "title": rule_id,
            "severity": "High",
            "cwe": "",
            "location": location,
            "locations": [location],
            "trace": str(result.get("Description") or "Secret detected by Betterleaks."),
            "rating": f"High from Betterleaks rule {rule_id}",
        }
        confidence = result_confidence(result)
        if confidence:
            finding["confidence"] = confidence
        findings.append(finding)

    print(json.dumps({"findings": findings}))


def result_location(result):
    path = str(result.get("File") or "").removeprefix("./")
    if not path:
        return "unknown"
    line = result.get("StartLine")
    return f"{path}:{line}" if isinstance(line, int) and line > 0 else path


def result_confidence(result):
    attributes = result.get("Attributes")
    if not isinstance(attributes, dict):
        return ""
    confidence = str(attributes.get("confidence") or "").lower()
    return confidence if confidence in {"low", "medium", "high"} else ""


if __name__ == "__main__":
    main()
