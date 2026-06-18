---
name: maintainers
description: Identify the real maintainers of a repository and the best way to contact them about a security issue. Distinguishes active leads from occasional contributors and bots, using commit history, issue activity, and registry ownership. Use when preparing a disclosure and needing to know who to reach.
license: MIT
compatibility: Needs network access to commits.ecosyste.ms, issues.ecosyste.ms, packages.ecosyste.ms, and api.github.com (to verify private vulnerability reporting before proposing the GitHub advisories channel).
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: maintainers
  scrutineer.requires_remote: true
  scrutineer.model: mid
---

# maintainers

You are identifying who maintains a repository so a security disclosure can reach the right person. The answer needs to distinguish:

- active leads (primary decision makers, recent activity)
- regular maintainers (active but not decision makers)
- occasional contributors (one-off PRs, not reviewers)
- bots (dependabot, renovate, github-actions, etc)

## Workspace

- `./src` — the cloned repository. Useful for reading `SECURITY.md`, `CODEOWNERS`, `.github/`, and `git log`.
- `./context.json` — the repository URL and metadata. Read the `repository.url` field.
- `./report.json` — write your final report here.
- `./schema.json` — the JSON schema for `./report.json`.

## Data sources

Fetch each of these using your fetch tool. Each returns JSON. Include the repository URL from `context.json` as the query parameter.

1. **Commits**: `https://commits.ecosyste.ms/api/v1/repositories/lookup?url={repo_url}` — who has written code, how much, past-year activity. Follow redirects.
2. **Issues and PRs**: `https://issues.ecosyste.ms/api/v1/repositories/lookup?url={repo_url}` — who reviews, responds, closes issues. Follow redirects.
3. **Packages**: `https://packages.ecosyste.ms/api/v1/packages/lookup?repository_url={repo_url}` — registry owners and publishers.

URL-encode the repository URL before substituting it into the query string.

If all three lookups return empty or 404, fall back to `git -C ./src shortlog -sne --since='1 year ago'` plus `git -C ./src log --no-merges -20 --format='%aN <%aE>'` and classify from that alone; say so in `notes`.

Also read `SECURITY.md`, `.github/SECURITY.md`, `CODEOWNERS`, and `README.md` in `./src` if they exist. These often name a security contact directly.

## How to classify

- **lead** — named in SECURITY.md, owns the repo on the registry, or is consistently the final reviewer on PRs over the past year.
- **maintainer** — has merged PRs in the past year, reviews other people's PRs, has commit access.
- **contributor** — authored commits but has not merged or reviewed anyone else's work. Infrequent activity.
- **bot** — account name matches a bot (`dependabot`, `renovate`, `github-actions`, `*[bot]`), or all commits are automated.

- **active** — evidence of any activity (commit, comment, review, release) in the past year.
- **inactive** — no activity in the past year.

Keep `evidence` to one sentence: which data you used to classify (e.g. "98% of past-year commits", "merged 14 PRs in 2025", "registry owner and listed in SECURITY.md").

Filter bots out of the final list unless the repo's only active account is a bot, in which case include them and say so in `notes`.

## Disclosure channel

Pick the best one, based on what you found:

- `SECURITY.md` email or contact block if present
- GitHub Security Advisories **only when private vulnerability reporting is actually enabled**: fetch `https://api.github.com/repos/{owner}/{repo}/private-vulnerability-reporting` (no auth needed for public repos) and require `{"enabled": true}`. If it returns `{"enabled": false}`, a 404, or any error, the GitHub advisories URL would 404 for a reporter — skip this option and fall through to the next channel. Do not infer this from a SECURITY.md that merely *says* "report via GitHub advisories"; the maintainer may not have turned the feature on.
- Registry owner contact if packages data surfaced one
- The lead's git-log author email if none of the above; if it is a `noreply.github.com` address, skip it

Put the concrete channel name or URL in `disclosure_channel`. Leave empty if nothing reliable was found.

## Output

Write `./report.json` conforming to `./schema.json`. Include every human you classified, not just the top few; bots stay out of the list (per the filter above) but mention in `notes` how many were dropped. Use `notes` for anything a reviewer would want to know that does not fit the schema — bus factor, recent turnover, maintainer handoff, corporate sponsorship.
