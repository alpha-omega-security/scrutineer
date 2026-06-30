#!/usr/bin/env python3
import json
import os
import urllib.request
import subprocess
import re
import sys
import urllib.error


def get_json(url, token=None):
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                data = response.read().decode("utf-8")
                if data:
                    return json.loads(data)
    except Exception:
        pass
    return None


def main():
    if not os.path.exists("context.json"):
        print("No context.json found")
        sys.exit(1)

    with open("context.json", "r") as f:
        ctx = json.load(f)

    api_base = ctx.get("scrutineer", {}).get("api_base")
    token = ctx.get("scrutineer", {}).get("token")
    repo_id = ctx.get("scrutineer", {}).get("repository_id")
    repo_url = ctx.get("repository", {}).get("url", "")

    summary = {
        "commits_data": None,
        "issues_data": None,
        "packages_data": None,
        "fallback_git_shortlog": None,
        "fallback_git_log": None,
        "security_md": None,
        "codeowners": None,
        "pvr_enabled": False,
        "pvr_checked": False,
    }

    if api_base and token and repo_id:
        base_url = f"{api_base}/repositories/{repo_id}/ecosystems"
        raw = get_json(f"{base_url}/commits/raw", token)
        if isinstance(raw, dict):
            summary["commits_data"] = {
                "past_year_committers": (raw.get("past_year_committers") or [])[:20],
                "total_committers": raw.get("total_committers"),
            }

        raw = get_json(f"{base_url}/issues/raw", token)
        if isinstance(raw, dict):
            summary["issues_data"] = {
                "maintainers": raw.get("maintainers"),
                "active_maintainers": raw.get("active_maintainers"),
                "past_year_issue_authors": raw.get("past_year_issue_authors"),
                "past_year_pull_request_authors": raw.get(
                    "past_year_pull_request_authors"
                ),
            }

        summary["packages_data"] = get_json(f"{base_url}/packages/raw", token)

    if (
        not summary["commits_data"]
        and not summary["issues_data"]
        and not summary["packages_data"]
    ):
        try:
            summary["fallback_git_shortlog"] = subprocess.check_output(
                [
                    "git",
                    "-C",
                    "./src",
                    "shortlog",
                    "-sne",
                    "--since=1 year ago",
                    "HEAD",
                ],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            summary["fallback_git_log"] = subprocess.check_output(
                [
                    "git",
                    "-C",
                    "./src",
                    "log",
                    "--no-merges",
                    "-20",
                    "--format=%aN <%aE>",
                ],
                text=True,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

    for path in ["SECURITY.md", ".github/SECURITY.md"]:
        full_path = os.path.join("./src", path)
        if os.path.exists(full_path):
            with open(full_path, "r", errors="ignore") as f:
                summary["security_md"] = f.read()
            break

    for path in ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]:
        codeowners_path = os.path.join("./src", path)
        if os.path.exists(codeowners_path):
            with open(codeowners_path, "r", errors="ignore") as f:
                summary["codeowners"] = f.read()
            break

    for path in ["README.md", "README", "README.txt", "readme.md"]:
        readme_path = os.path.join("./src", path)
        if os.path.exists(readme_path):
            with open(readme_path, "r", errors="ignore") as f:
                summary["readme_md"] = f.read()
            break

    match = re.search(r"github\.com/([^/]+)/([^/]+?)(?:\.git)?$", repo_url)
    if match:
        owner, repo = match.groups()
        pvr_url = f"https://api.github.com/repos/{owner}/{repo}/private-vulnerability-reporting"
        req = urllib.request.Request(pvr_url)
        req.add_header("Accept", "application/vnd.github+json")
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8"))
                    summary["pvr_checked"] = True
                    summary["pvr_enabled"] = data.get("enabled", False)
        except urllib.error.HTTPError:
            summary["pvr_checked"] = True
        except Exception:
            pass

    with open("summary.json", "w") as f:
        json.dump(summary, f, indent=2)


if __name__ == "__main__":
    main()
