#!/usr/bin/env python3
"""Run poutine against ./src and emit findings in scrutineer's shape.
Requires poutine on PATH. Writes JSON to stdout.

Results are grouped by rule so the same rule firing on every job in a
pipeline becomes one finding with the full set of file:line positions in
`locations`, matching the zizmor adapter's behaviour (#191).

poutine reports the rule metadata once, in a top-level `rules` map keyed by
rule id, and each finding carries only `rule_id` plus its own location. The
title, severity and references therefore come from that map rather than from
the finding, and a finding naming a rule the map does not describe still
yields a finding — a location we drop is a vulnerability we did not report.
"""
import json
import os
import shutil
import subprocess
import sys
from collections import defaultdict

# poutine levels are SARIF's (`error`/`warning`/`note`); scrutineer's scale has
# a fourth step above them. Nothing in poutine emits `critical`, so nothing maps
# to `Critical` — inventing that step here would let a rule the tool calls an
# error outrank one another scanner genuinely rated critical.
SEVERITY_MAP = {
    "error": "High",
    "warning": "Medium",
    "note": "Low",
}

# poutine reads GitHub Actions, GitLab CI, Azure Pipelines and Tekton. Skipping
# the run when a repo has none of them keeps the scan cheap on the many repos
# that ship no pipeline at all, the way the zizmor adapter skips a repo with no
# workflows directory.
PIPELINE_PATHS = [
    (".github", "workflows"),
    (".gitlab-ci.yml",),
    (".gitlab", "ci"),
    ("azure-pipelines.yml",),
    (".tekton",),
]


def has_pipelines(src):
    return any(os.path.exists(os.path.join(src, *parts)) for parts in PIPELINE_PATHS)


def main():
    src = "./src"
    if not os.path.isdir(src):
        print(json.dumps({"findings": [], "error": "no ./src dir"}))
        return

    if not has_pipelines(src):
        print(json.dumps({"findings": [], "error": "no CI pipeline definitions"}))
        return

    if shutil.which("poutine") is None:
        print(json.dumps({"findings": [], "error": "poutine not on PATH"}))
        return

    # --quiet drops the progress bar from stdout and --disable-version-check
    # stops the once-a-day release check, which would otherwise reach the
    # network from inside the sandbox and stall behind the egress proxy.
    proc = subprocess.run(
        ["poutine", "analyze_local", ".", "--format", "json",
         "--quiet", "--disable-version-check"],
        cwd=src,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(json.dumps({"findings": [], "error": proc.stderr.strip()[:2000]}))
        return

    try:
        data = json.loads(proc.stdout) if proc.stdout else {}
    except json.JSONDecodeError as exc:
        print(json.dumps({"findings": [], "error": f"poutine json: {exc}"}))
        return

    rules = data.get("rules") or {}
    groups = defaultdict(list)
    for f in data.get("findings") or []:
        groups[f.get("rule_id") or "poutine finding"].append(f)

    findings = []
    for i, (rule_id, hits) in enumerate(sorted(groups.items()), start=1):
        rule = rules.get(rule_id) or {}
        severity = SEVERITY_MAP.get(str(rule.get("level", "")).lower(), "Medium")
        locations = sorted({finding_location(h) for h in hits})
        n = len(locations)
        suffix = f" ({n} locations)" if n > 1 else ""
        findings.append({
            "id": f"F{i}",
            "title": rule.get("title") or rule_id,
            "severity": severity,
            "location": locations[0],
            "locations": locations,
            "trace": (rule.get("description") or "").strip() or rule_id,
            "rating": f"{severity} from poutine rule {rule_id}{suffix}",
            "references": references(rule_id, rule),
        })

    print(json.dumps({"findings": findings}))


def references(rule_id, rule):
    """The rule's own doc page, then whatever references the rule carries."""
    refs = [{
        "url": f"https://boostsecurityio.github.io/poutine/rules/{rule_id}/",
        "summary": f"poutine docs: {rule_id}",
        "tags": "docs",
    }]
    for r in rule.get("refs") or []:
        url = (r.get("ref") or "").strip()
        if url:
            refs.append({"url": url, "summary": (r.get("description") or "").strip()})
    return refs


def finding_location(f):
    meta = f.get("meta") or {}
    path = meta.get("path") or "pipeline"
    line = meta.get("line")
    # poutine omits `line` rather than sending 0 when a finding is about the
    # file as a whole, so a bare path is a real answer and not a missing one.
    return f"{path}:{line}" if line else path


if __name__ == "__main__":
    main()
