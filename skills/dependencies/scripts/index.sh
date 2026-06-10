#!/usr/bin/env bash
# Index every dependency manifest in the clone and wrap git-pkgs's output in
# the `{"dependencies": [...]}` envelope the scrutineer parser expects. Exits
# non-zero with an informative message if git-pkgs is missing or emits a
# non-array JSON value other than null.
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

# Wrap the array in a top-level object so the output matches schema.json, and
# resolve Maven property placeholders while the POM files are still available.
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
git-pkgs list --format json > "$tmp"
python3 - "$tmp" <<'PY'
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

raw = open(sys.argv[1], encoding="utf-8").read().strip()
if raw == "" or raw == "null":
    deps = []
else:
    deps = json.loads(raw)
if deps is None:
    deps = []
if not isinstance(deps, list):
    raise SystemExit(f"git-pkgs list returned {type(deps).__name__}, want array")

expr_re = re.compile(r"\$\{([^}]+)\}")
pom_cache = {}
src_root = os.path.realpath(os.getcwd())

def lname(tag):
    return tag.rsplit("}", 1)[-1]

def child(el, name):
    if el is None:
        return None
    for c in list(el):
        if lname(c.tag) == name:
            return c
    return None

def text(el, name):
    c = child(el, name)
    if c is None or c.text is None:
        return ""
    return c.text.strip()

def replace_props(value, props):
    if not value:
        return value
    def repl(match):
        key = match.group(1)
        return props.get(key, match.group(0))
    return expr_re.sub(repl, value)

def resolve_value(value, props):
    prev = value
    for _ in range(20):
        cur = replace_props(prev, props)
        if cur == prev:
            return cur
        prev = cur
    return prev

def under_src(path):
    try:
        return os.path.commonpath([src_root, path]) == src_root
    except ValueError:
        return False

def normalize_pom_path(path):
    if not path:
        return ""
    path = os.path.realpath(path)
    if not under_src(path):
        return ""
    return path

def parent_pom_path(path, rel):
    parent_path = os.path.realpath(os.path.join(os.path.dirname(path), rel))
    if os.path.isdir(parent_path):
        parent_path = os.path.realpath(os.path.join(parent_path, "pom.xml"))
    if not under_src(parent_path):
        return ""
    return parent_path

def parse_pom(path, stack=()):
    path = normalize_pom_path(path)
    if not path:
        return {}
    if path in pom_cache:
        return dict(pom_cache[path])
    if path in stack or not os.path.exists(path):
        pom_cache[path] = {}
        return {}

    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        pom_cache[path] = {}
        return {}

    props = {}
    parent = child(root, "parent")
    parent_group = parent_artifact = parent_version = ""
    if parent is not None:
        parent_group = text(parent, "groupId")
        parent_artifact = text(parent, "artifactId")
        parent_version = text(parent, "version")
        rel_el = child(parent, "relativePath")
        rel = "../pom.xml" if rel_el is None else (rel_el.text or "").strip()
        if rel:
            props.update(parse_pom(parent_pom_path(path, rel), stack + (path,)))
            parent_version = resolve_value(parent_version, props)

    group_id = text(root, "groupId") or parent_group
    artifact_id = text(root, "artifactId") or parent_artifact
    version = text(root, "version") or parent_version

    properties = child(root, "properties")
    if properties is not None:
        for p in list(properties):
            if p.text is not None:
                props[lname(p.tag)] = p.text.strip()

    builtins = {
        "groupId": group_id,
        "artifactId": artifact_id,
        "version": version,
        "project.groupId": group_id,
        "project.artifactId": artifact_id,
        "project.version": version,
        "pom.groupId": group_id,
        "pom.artifactId": artifact_id,
        "pom.version": version,
        "parent.groupId": parent_group,
        "parent.artifactId": parent_artifact,
        "parent.version": parent_version,
        "project.parent.groupId": parent_group,
        "project.parent.artifactId": parent_artifact,
        "project.parent.version": parent_version,
    }
    props.update({k: v for k, v in builtins.items() if v})

    for _ in range(20):
        changed = False
        for k, v in list(props.items()):
            resolved = replace_props(v, props)
            if resolved != v:
                props[k] = resolved
                changed = True
        if not changed:
            break

    pom_cache[path] = dict(props)
    return dict(props)

for dep in deps:
    if not isinstance(dep, dict):
        continue
    req = dep.get("requirement")
    manifest = dep.get("manifest_path") or ""
    if not isinstance(req, str) or "${" not in req or not manifest.endswith("pom.xml"):
        continue
    resolved = resolve_value(req, parse_pom(manifest))
    dep["requirement"] = resolved
    dep["requirement_unresolved"] = bool(expr_re.search(resolved))

json.dump({"dependencies": deps}, sys.stdout, separators=(",", ":"))
sys.stdout.write("\n")
PY
