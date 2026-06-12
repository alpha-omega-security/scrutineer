---
name: report-upstream
description: File a finding on the upstream repository through GitHub's private vulnerability reporting, request the temporary private fork, and push the proposed patch to it when available. Use after disclose has produced a draft and (optionally) patch has produced a gated diff. This is the step that crosses the line to the maintainer; everything before it is internal.
license: MIT
compatibility: Needs the gh CLI authenticated with a token that can submit private vulnerability reports on public github.com repositories. Needs network access to api.github.com and the scrutineer API. github.com upstreams only. Finding-scoped.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: freeform
  scrutineer.requires_remote: true
---

# report-upstream

Submit a finding to the upstream repository's maintainers through GitHub's private vulnerability reporting (PVR), and hand them the proposed fix. Unlike `fork`, which stands up a private staging repo in the org for internal review, this skill files against the upstream repo and is visible to its maintainers. Do not run it on a finding the analyst has not signed off on.

## Workspace

- `./src` — the upstream clone
- `./context.json` — has `repository.url`, `repository.full_name`, and the `scrutineer` block with `api_base`, `token`, `repository_id`, `scan_id`, `finding_id`
- `./report.json` — write what you did
- `./schema.json` — shape of `report.json`

Use the `gh` CLI for every GitHub call.

## Preconditions

Read `./context.json`, then `GET {api_base}/repositories/{repository_id}` and `GET {api_base}/findings/{finding_id}` (both with `Authorization: Bearer {token}`). Refuse to continue (write `{"error": "..."}` to `report.json` and exit 0) if any of:

- `scrutineer.finding_id` is missing — this skill is finding-scoped
- `repository.url` host is not `github.com`
- `gh auth status` fails — the runner has no GitHub credentials
- the finding's `status` is `reported`, `acknowledged`, `fixed`, `published`, `rejected`, or `duplicate` — already past the reporting step or closed
- the finding's `disclosure_draft` is empty — run `disclose` first
- the finding already has a reference tagged `ghsa-upstream` (`GET {api_base}/findings/{finding_id}/references`) — a previous run of this skill already filed it
- PVR is not enabled on the upstream: `gh api repos/{owner}/{repo}/private-vulnerability-reporting` does not return `{"enabled": true}`. Include `repository.posture` and `posture_summary` (from the repository fetch) in the error so the operator sees why

Derive `{owner}/{repo}` from `repository.full_name` (fall back to parsing the path of `repository.url`, stripping a trailing `.git`).

## 1. Build the report body

Write `./advisory.json` with the GitHub `/reports` body. Field-by-field:

- `summary` — the finding's `title`. Trim to 1024 characters; GitHub rejects longer.
- `description` — the finding's `disclosure_draft`, then a `## Proposed fix` section, then a final marker line. See below.
- `vulnerabilities[]` — build from `GET {api_base}/repositories/{repository_id}/packages` using the GHSA ecosystem mapping (rubygems, npm, pip, maven, nuget, composer, go, rust, erlang, actions, pub, swift, other). One entry per package; `vulnerable_version_range` from the finding's `affected` field, normalised to comma-separated `OP VERSION` clauses or omitted if it cannot be reduced to that shape. If the repository has no packages, send `[{"package": {"ecosystem": "other", "name": "{owner}/{repo}"}}]` — the endpoint requires at least one entry.
- `cwe_ids` — split the finding's `cwe` field on commas into an array of `CWE-N` strings. Omit if empty.
- `cvss_vector_string` — the finding's `cvss_vector` when set; otherwise omit and send `severity` instead (the finding's `severity` lowercased to `critical`/`high`/`medium`/`low`). Never send both.
- `start_private_fork` — `true`.

For the `## Proposed fix` section: when `suggested_fix` on the finding is non-empty, append to the description:

```
## Proposed fix

The diff below applies against commit `{suggested_fix_commit}`.

```diff
{suggested_fix}
```
```

When `suggested_fix` is empty, append `## Proposed fix\n\nNo patch is attached. {one sentence saying why: the patch skill has not run, or its output did not pass scrutineer's applicability gate.}` so the maintainer knows it was considered.

GitHub caps `description` at 65535 characters. If the assembled description exceeds that, drop the diff block (keep the prose explaining a diff is available on request) and try again. If it still exceeds the cap, truncate `disclosure_draft` from the bottom and note `truncated: true` in `report.json`.

End the description with a final line `[scrutineer-finding:{finding_id}]` so re-runs can recognise this advisory and the staging issue filed by `fork` carries the same marker.

## 2. File the report

```
gh api -X POST repos/{owner}/{repo}/security-advisories/reports --input ./advisory.json
```

This is the external-reporter endpoint; do not use the bare `/security-advisories` admin endpoint, which only works for repo admins. Capture `ghsa_id` and `html_url` from the response.

A 422 with `Private vulnerability reporting is disabled` means PVR was turned off between the precondition check and the POST; treat as a refusal. A 422 mentioning a specific field (`vulnerabilities`, `cvss_vector_string`) means the body shape was rejected; fix the named field (drop `vulnerable_version_range`, drop `cvss_vector_string` in favour of `severity`) and retry once. Any other non-2xx is a refusal with the response body in `error`.

## 3. Push the patch to the temporary private fork

The temporary private fork is created by GitHub when the maintainer accepts the report into draft, so it is usually not available to the reporter immediately. Poll for it briefly anyway in case it is:

```
gh api repos/{owner}/{repo}/security-advisories/{ghsa_id} --jq '.private_fork.full_name'
```

Try up to six times with a five-second gap. If `private_fork` stays `null`, set `private_fork: null` and `patch_pushed: false` in `report.json` with `notes` explaining the maintainer has to accept the report before the fork exists; the diff is already in the description so they have it either way. Skip to step 4.

If a `private_fork.full_name` appears and `suggested_fix` is non-empty:

```
gh auth setup-git
git -C ./src fetch origin {suggested_fix_commit} || git -C ./src fetch --unshallow
git -C ./src checkout -b fix/{ghsa_id} {suggested_fix_commit}
printf '%s' "$SUGGESTED_FIX" | git -C ./src apply -
git -C ./src add -A
printf '%s' "$COMMIT_MSG" | git -C ./src commit -F -
git -C ./src push "https://github.com/{private_fork.full_name}.git" fix/{ghsa_id}
```

Read `suggested_fix` and the commit message (subject `Fix {ghsa_id}: {finding.title}`) into shell variables and pipe them through stdin rather than interpolating into the command line — finding titles can contain backticks, `$()`, or other shell-special characters. `gh auth setup-git` configures git's credential helper to use the gh token for github.com pushes; without it the push hangs on a credential prompt on any runner where it has not already been called.

If `git apply` fails the diff no longer applies cleanly to `suggested_fix_commit` as fetched; do not improvise a fix, set `patch_pushed: false` with the apply error in `notes`. If the push is rejected (no write access yet), same: `patch_pushed: false`, reason in `notes`.

If `suggested_fix` is empty, skip the push and record `patch_pushed: false` with `notes: "no gated patch on the finding"`.

## 4. Write back to scrutineer

All with `Authorization: Bearer {token}`:

- `PATCH {api_base}/findings/{finding_id}` with `{"fields": {"status": "reported"}, "by": "report-upstream"}`
- `POST {api_base}/findings/{finding_id}/references` with `{"url": "<html_url>", "tags": "ghsa-upstream", "summary": "PVR report {ghsa_id} on {owner}/{repo}"}`
- `POST {api_base}/findings/{finding_id}/communications` with `{"channel": "ghsa", "direction": "outbound", "actor": "report-upstream", "body": "<body>"}`. Build `<body>` as `Filed PVR report {ghsa_id} on {owner}/{repo}. ` followed by `Patch pushed to fix/{ghsa_id} on {private_fork}.` when `patch_pushed` is true, or `Patch included in the report description; private fork pending maintainer acceptance.` when false.

## Output

Write `./report.json`:

```json
{
  "upstream": "owner/repo",
  "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
  "url": "https://github.com/owner/repo/security/advisories/GHSA-...",
  "private_fork": "owner/repo-ghsa-xxxx-xxxx-xxxx",
  "patch_pushed": true,
  "patch_branch": "fix/GHSA-xxxx-xxxx-xxxx",
  "truncated": false,
  "notes": "anything that did not go cleanly",
  "error": null
}
```

`private_fork` and `patch_branch` are `null` when the fork was not available. `error` is set only on refusal, in which case `ghsa_id` and `url` are absent and nothing was filed upstream.

## Constraints

- Do not file unless every precondition passes. A bad report to a maintainer costs trust that is hard to win back.
- Do not improvise content. Every field in the body comes from the finding, the packages list, or `disclosure_draft`. If `disclosure_draft` is thin, refuse and tell the operator to re-run `disclose`.
- Do not retry the POST more than once, and only when the 422 names a specific field you can drop.
- Do not change any finding field other than `status`. `cvss_vector`, `affected`, `disclosure_draft` belong to `disclose` and the analyst.
- Do not touch the upstream repository's settings, issues, or pull requests. The only write is the `/reports` POST and, when available, the branch push to the temporary private fork.
