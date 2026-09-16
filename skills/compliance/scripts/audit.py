#!/usr/bin/env python3
"""Run darnit's OpenSSF Baseline audit against ./src and emit the compliance
report shape.

Requires darnit on PATH. Writes structured JSON to stdout; darnit's untouched
output goes to ./darnit.json. Stderr carries progress and errors.

darnit's CLI runs with stop_on_llm, so a control whose builtin checks are
inconclusive comes back as PENDING_LLM with a consultation request instead
of a verdict; that request is carried through as `consultation` so the agent
can answer it. darnit's summary block is dropped: it omits ERROR and
PENDING_LLM and counts `na` on "NA" while an excluded control reports "N/A",
so scrutineer recounts from the controls themselves.

darnit merges ./src/.baseline.toml into the framework, which lets the audited
repository drop a control from the results or replace its checks with its
own, so the audit runs with that file set aside.
"""
import json
import os
import shutil
import subprocess
import sys

FRAMEWORK = "openssf-baseline"


def report(controls, error=None):
    out = {"schema_version": 1, "framework": FRAMEWORK, "total": len(controls), "controls": controls}
    if error:
        out["error"] = error
    return out


def fail(message):
    print(message, file=sys.stderr)
    json.dump(report([], message), sys.stdout, indent=2)
    print()
    return 0


def main():
    if not shutil.which("darnit"):
        return fail("darnit not found on PATH")
    user_config = "./src/.baseline.toml"
    aside = os.path.lexists(user_config)
    if aside:
        os.rename(user_config, user_config + ".scrutineer-aside")
    try:
        proc = subprocess.run(
            ["darnit", "audit", "./src", "--framework", FRAMEWORK, "--output", "json", "--no-fail"],
            capture_output=True,
            text=True,
        )
    finally:
        if aside:
            os.rename(user_config + ".scrutineer-aside", user_config)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr, end="")
    if proc.returncode != 0:
        return fail(f"darnit exited {proc.returncode}: {proc.stderr.strip()[-2000:]}")
    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return fail(f"darnit output is not JSON: {exc}")
    with open("./darnit.json", "w") as fh:
        fh.write(proc.stdout)

    controls = []
    for r in raw.get("results", []):
        status = r.get("status", "ERROR")
        if status == "N/A":
            status = "NA"
        entry = {
            "id": r.get("id", ""),
            "level": r.get("level", 1),
            "status": status,
            "details": r.get("details", ""),
            "source": "darnit",
        }
        consultation = (r.get("evidence") or {}).get("llm_consultation")
        if status == "PENDING_LLM" and consultation:
            entry["consultation"] = {
                "prompt": consultation.get("prompt", ""),
                "analysis_hints": consultation.get("analysis_hints", []),
                "gathered_evidence": consultation.get("gathered_evidence") or {},
            }
        controls.append(entry)
    json.dump(report(controls), sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
