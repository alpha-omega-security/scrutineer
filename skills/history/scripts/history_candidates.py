#!/usr/bin/env python3
"""Select security-shaped commits and render bounded diff batches."""

import argparse
import json
import os
import re
import subprocess
import sys


COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
BASE_PATTERNS = (
    ("advisory-id", re.compile(r"\b(?:CVE-\d{4}-\d+|GHSA-[0-9a-z-]+)\b", re.I)),
    ("security", re.compile(r"\b(?:security|vulnerabilit(?:y|ies)|exploit(?:able|ation)?|attack)\b", re.I)),
    ("hardening", re.compile(r"\b(?:harden(?:ing|ed)?|unsafe|trust boundary|privilege escalation)\b", re.I)),
    (
        "security-shaped-fix",
        re.compile(
            r"\bfix(?:es|ed|ing)?\b.{0,64}\b(?:auth|bound|overflow|underflow|injection|traversal|escape|saniti[sz]|validat|permission|privilege|secret|token|leak|race|crash|panic|denial)\w*",
            re.I | re.S,
        ),
    ),
)

ECOSYSTEMS = {
    "c-cpp": {
        "paths": re.compile(r"\.(?:c|h|cc|cpp|cxx|hpp|hxx)$", re.I),
        "patterns": (
            ("memory-bounds", re.compile(r"\b(?:out[- ]of[- ]bounds|bounds check|buffer overflow|integer overflow|use[- ]after[- ]free|double free|null dereference|memory corruption)\b", re.I)),
        ),
    },
    "rust": {
        "paths": re.compile(r"(?:^|/)(?:Cargo\.toml|.*\.rs)$", re.I),
        "patterns": (("rust-safety", re.compile(r"\b(?:soundness|unsafe block|undefined behavio(?:u)?r|panic safety)\b", re.I)),),
    },
    "go": {
        "paths": re.compile(r"(?:^|/)(?:go\.mod|.*\.go)$", re.I),
        "patterns": (("go-security", re.compile(r"\b(?:path traversal|request smuggling|data race|certificate verification|zip slip)\b", re.I)),),
    },
    "python": {
        "paths": re.compile(r"(?:^|/)(?:pyproject\.toml|setup\.py|requirements[^/]*\.txt|.*\.py)$", re.I),
        "patterns": (("python-security", re.compile(r"\b(?:pickle|yaml load|template injection|path traversal|zip slip|command injection)\b", re.I)),),
    },
    "javascript-typescript": {
        "paths": re.compile(r"(?:^|/)(?:package\.json|.*\.(?:js|jsx|mjs|cjs|ts|tsx))$", re.I),
        "patterns": (("web-security", re.compile(r"\b(?:xss|csrf|ssrf|prototype pollution|open redirect|jwt|cookie|session fixation|command injection)\b", re.I)),),
    },
    "jvm": {
        "paths": re.compile(r"(?:^|/)(?:pom\.xml|build\.gradle(?:\.kts)?|.*\.(?:java|kt|scala))$", re.I),
        "patterns": (("jvm-security", re.compile(r"\b(?:deseriali[sz]ation|xxe|expression language|request smuggling|path traversal)\b", re.I)),),
    },
    "ruby": {
        "paths": re.compile(r"(?:^|/)(?:Gemfile|.*\.gemspec|.*\.rb)$", re.I),
        "patterns": (("ruby-security", re.compile(r"\b(?:marshal load|yaml load|mass assignment|open redirect|command injection)\b", re.I)),),
    },
    "php": {
        "paths": re.compile(r"(?:^|/)(?:composer\.json|.*\.php)$", re.I),
        "patterns": (("php-security", re.compile(r"\b(?:object injection|unserialize|file inclusion|sql injection|xss|csrf)\b", re.I)),),
    },
    "dotnet": {
        "paths": re.compile(r"(?:^|/)(?:.*\.(?:csproj|fsproj|cs|fs))$", re.I),
        "patterns": (("dotnet-security", re.compile(r"\b(?:binaryformatter|deseriali[sz]ation|viewstate|path traversal|authorization bypass)\b", re.I)),),
    },
}


def git(repo, *args, check=True):
    proc = subprocess.run(
        ["git", "-C", repo, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc


def clean_scope_path(value):
    if not value:
        return ""
    value = value.strip()
    parts = value.split("/")
    if value.startswith(("/", "\\")) or "\\" in value or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("--path must be a normalized repository-relative path")
    return "/".join(parts)


def repository_paths(repo, scope_path, head):
    args = ["ls-tree", "-r", "--name-only", head]
    if scope_path:
        args.extend(["--", scope_path])
    return [line for line in git(repo, *args).stdout.splitlines() if line]


def detect_ecosystems(paths):
    detected = []
    for name, config in ECOSYSTEMS.items():
        if any(config["paths"].search(path) for path in paths):
            detected.append(name)
    return detected or ["generic"]


def patterns_for(ecosystems):
    patterns = list(BASE_PATTERNS)
    for ecosystem in ecosystems:
        config = ECOSYSTEMS.get(ecosystem)
        if config:
            patterns.extend(config["patterns"])
    return patterns


def cache_state(repo, base, head):
    if not base:
        return False, "no prior cache"
    if not COMMIT_RE.fullmatch(base):
        return False, "cached analyzed_head is not a full commit id"
    if git(repo, "cat-file", "-e", f"{base}^{{commit}}", check=False).returncode != 0:
        return False, "cached analyzed_head is unavailable in this clone"
    if git(repo, "merge-base", "--is-ancestor", base, head, check=False).returncode != 0:
        return False, "cached analyzed_head is not an ancestor of HEAD"
    return True, None


def selected_head(repo, requested_head):
    checkout_head = git(repo, "rev-parse", "HEAD").stdout.strip()
    if not COMMIT_RE.fullmatch(checkout_head):
        raise RuntimeError("HEAD is not a full commit id")
    if not requested_head:
        return checkout_head
    if not COMMIT_RE.fullmatch(requested_head):
        raise ValueError("--head must be a full commit id")
    if git(repo, "cat-file", "-e", f"{requested_head}^{{commit}}", check=False).returncode != 0:
        raise ValueError("--head commit is unavailable in this clone")
    if git(repo, "merge-base", "--is-ancestor", requested_head, checkout_head, check=False).returncode != 0:
        raise ValueError("--head commit is not an ancestor of the checkout HEAD")
    return requested_head


def parse_log(raw):
    records = []
    for record in raw.split("\x1e"):
        fields = record.strip("\n").split("\x1f", 2)
        if len(fields) != 3:
            continue
        commit, subject, body = fields
        if COMMIT_RE.fullmatch(commit):
            records.append((commit, subject.strip(), body.strip()))
    return records


def list_candidates(args):
    scope_path = clean_scope_path(args.path)
    head = selected_head(args.repo, args.head)
    reusable, invalid_reason = cache_state(args.repo, args.base, head)
    if args.after and args.base and not reusable:
        raise ValueError(f"--after cannot be used with an invalid --base: {invalid_reason}")
    revision = f"{args.base}..{head}" if reusable else head
    paths = repository_paths(args.repo, scope_path, head)
    ecosystems = detect_ecosystems(paths)
    log_args = ["log", "--reverse", "--no-merges", "--format=%H%x1f%s%x1f%b%x1e", revision]
    if scope_path:
        log_args.extend(["--", scope_path])
    records = parse_log(git(args.repo, *log_args).stdout)
    patterns = patterns_for(ecosystems)
    candidates = []
    for commit, subject, body in records:
        message = f"{subject}\n{body}"
        matched = [label for label, pattern in patterns if pattern.search(message)]
        if matched:
            candidates.append({"commit": commit, "title": subject, "matched_terms": sorted(set(matched))})
    total = len(candidates)
    page_offset = 0
    if args.after:
        if not COMMIT_RE.fullmatch(args.after):
            raise ValueError("--after must be a full commit id")
        try:
            page_offset = next(
                index + 1 for index, candidate in enumerate(candidates) if candidate["commit"] == args.after
            )
        except StopIteration as exc:
            raise ValueError("--after commit is not a candidate in the selected history range") from exc
    page = candidates[page_offset : page_offset + args.max_candidates]
    has_more = page_offset + len(page) < total
    shallow = git(args.repo, "rev-parse", "--is-shallow-repository").stdout.strip() == "true"
    result = {
        "head": head,
        "requested_base": args.base or None,
        "cache_reusable": reusable,
        "cache_invalid_reason": invalid_reason or "",
        "range": revision,
        "scope_path": scope_path,
        "shallow": shallow,
        "ecosystems": ecosystems,
        "total_matched": total,
        "page_offset": page_offset,
        "truncated": has_more,
        "next_cursor": page[-1]["commit"] if has_more else "",
        "candidates": page,
    }
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output == "-":
        sys.stdout.write(encoded)
    else:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(encoded)


def bounded_text(value, max_bytes):
    raw = value.encode("utf-8", errors="replace")
    if len(raw) <= max_bytes:
        return value, False
    clipped = raw[:max_bytes].decode("utf-8", errors="ignore")
    return clipped + "\n... diff truncated by history_candidates.py ...\n", True


def dump_patterns(args):
    out = []
    for label, pattern in BASE_PATTERNS:
        out.append({"label": label, "ecosystem": "", "pattern": pattern.pattern, "flags": pattern.flags})
    for name, config in ECOSYSTEMS.items():
        for label, pattern in config["patterns"]:
            out.append({"label": label, "ecosystem": name, "pattern": pattern.pattern, "flags": pattern.flags})
    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def commit_batch(args):
    scope_path = clean_scope_path(args.path)
    head = git(args.repo, "rev-parse", "HEAD").stdout.strip()
    if len(args.commit) > 5:
        raise ValueError("batch accepts at most five --commit values")
    results = []
    for commit in args.commit:
        if not COMMIT_RE.fullmatch(commit):
            raise ValueError(f"invalid commit id: {commit}")
        if git(args.repo, "merge-base", "--is-ancestor", commit, head, check=False).returncode != 0:
            raise ValueError(f"commit is not reachable from HEAD: {commit}")
        path_args = ["--", scope_path] if scope_path else []
        changed = git(args.repo, "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", commit, *path_args).stdout.splitlines()
        shown = git(
            args.repo,
            "show",
            "--no-ext-diff",
            "--find-renames",
            "--find-copies",
            "--format=fuller",
            commit,
            *path_args,
        ).stdout
        diff, truncated = bounded_text(shown, args.max_diff_bytes)
        results.append({
            "commit": commit,
            "changed_paths": [path for path in changed if path],
            "diff": diff,
            "diff_truncated": truncated,
        })
    json.dump({"head": head, "scope_path": scope_path, "commits": results}, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)

    listing = commands.add_parser("list", help="list security-shaped commit-message candidates")
    listing.add_argument("--repo", default="./src")
    listing.add_argument("--head", default="")
    listing.add_argument("--base", default="")
    listing.add_argument("--path", default="")
    listing.add_argument("--after", default="")
    listing.add_argument("--max-candidates", type=int, default=200)
    listing.add_argument("--output", default="-")
    listing.set_defaults(func=list_candidates)

    patterns = commands.add_parser("patterns", help="dump the message-matching regex set as JSON")
    patterns.add_argument("--repo", default=".")
    patterns.set_defaults(func=dump_patterns)

    batch = commands.add_parser("batch", help="render one bounded batch of candidate diffs")
    batch.add_argument("--repo", default="./src")
    batch.add_argument("--path", default="")
    batch.add_argument("--commit", action="append", required=True)
    batch.add_argument("--max-diff-bytes", type=int, default=24000)
    batch.set_defaults(func=commit_batch)
    return root


def main():
    args = parser().parse_args()
    if hasattr(args, "max_candidates") and args.max_candidates < 1:
        raise ValueError("--max-candidates must be positive")
    if hasattr(args, "max_diff_bytes") and args.max_diff_bytes < 1024:
        raise ValueError("--max-diff-bytes must be at least 1024")
    args.repo = os.path.abspath(args.repo)
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"history_candidates.py: {exc}", file=sys.stderr)
        sys.exit(2)
