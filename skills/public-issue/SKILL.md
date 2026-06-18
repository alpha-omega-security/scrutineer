---
name: public-issue
description: File a low-severity finding as an ordinary public GitHub issue after explicit analyst confirmation. Use for hardening gaps, defence-in-depth misses, and other bugs that do not warrant coordinated private disclosure.
license: MIT
compatibility: Needs the gh CLI authenticated with permission to open issues on the upstream GitHub repository. Needs network access to api.github.com and the scrutineer API. github.com upstreams only. Finding-scoped.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: freeform
  scrutineer.requires_remote: true
---

# public-issue

Open an ordinary public GitHub issue for a confirmed low-severity finding that does not need private vulnerability reporting. This is still a disclosure act: do not file unless the analyst has explicitly chosen this skill for this finding.

## Workspace

- `./src` — the upstream clone
- `./context.json` — has `repository.url`, `repository.full_name`, and the `scrutineer` block with `api_base`, `token`, `repository_id`, `scan_id`, `finding_id`
- `./report.json` — write what you did
- `./schema.json` — shape of `report.json`

Use the `gh` CLI for every GitHub call.

## Preconditions

Read `./context.json`, then `GET {api_base}/repositories/{repository_id}` and `GET {api_base}/findings/{finding_id}` with `Authorization: Bearer {token}`. Refuse to continue by writing `{"error": "..."}` to `report.json` and exit 0 if any of these are true:

- `scrutineer.finding_id` is missing — this skill is finding-scoped
- `repository.url` host is not `github.com`
- `gh auth status` fails — the runner has no GitHub credentials
- the finding's `status` is `reported`, `acknowledged`, `fixed`, `published`, `rejected`, or `duplicate`
- the finding's `status` is not `ready`; the analyst must review and mark it ready before public filing
- the finding's `severity` is `High` or `Critical`; those should stay on the private disclosure path unless the analyst manually overrides outside this skill
- the finding already has a reference tagged `public-issue` (`GET {api_base}/findings/{finding_id}/references`)
- the repository has issues disabled: `gh api repos/{owner}/{repo} --jq '.has_issues'` is not `true`

Derive `{owner}/{repo}` from `repository.full_name`, falling back to parsing `repository.url` and stripping a trailing `.git`.

## Build the issue

Draft for maintainers, not for scrutineer operators. The title should be concise and non-alarmist. The body must explain:

- what is wrong
- where it is in the code, including `location` when present
- why it matters despite being low severity
- suggested fix or hardening direction, using `suggested_fix`, `mitigation`, or `rating` when available

Use the finding's prose (`trace`, `boundary`, `validation`, `rating`, `disclosure_draft`, `mitigation`) as source material, but do not include exploit-heavy detail that would make the issue unsafe for public posting. If the finding only makes sense with exploit instructions, refuse and tell the analyst to use private disclosure instead.

End the body with:

```
[scrutineer-finding:{finding_id}]
```

This marker lets re-runs recognise the issue.

GitHub caps issue titles and bodies. Keep the title under 256 characters and the body under 65535 characters; trim from the bottom and set `truncated: true` in `report.json` if needed.

## File the issue

Write `./issue.md` with the body, then run:

```sh
gh issue create --repo {owner}/{repo} --title "$TITLE" --body-file ./issue.md
```

Pass the title through an environment variable or stdin-safe shell assignment, not by interpolating raw finding text into a command line. Capture the issue URL from stdout. If `gh issue create` fails, write `{"error": "<stderr or response>"}` to `report.json` and do not write back to scrutineer.

## Write back to scrutineer

All with `Authorization: Bearer {token}`:

- `PATCH {api_base}/findings/{finding_id}` with `{"fields": {"status": "reported"}, "by": "public-issue"}`
- `POST {api_base}/findings/{finding_id}/references` with `{"url": "<issue_url>", "tags": "public-issue", "summary": "Public issue on {owner}/{repo}"}`
- `POST {api_base}/findings/{finding_id}/communications` with `{"channel": "issue", "direction": "outbound", "actor": "public-issue", "body": "Filed public issue on {owner}/{repo}: <issue_url>"}`

## Output

Write `./report.json`:

```json
{
  "upstream": "owner/repo",
  "title": "Issue title",
  "url": "https://github.com/owner/repo/issues/123",
  "truncated": false,
  "error": null
}
```

On refusal or failure, write:

```json
{
  "error": "why nothing was filed"
}
```

## Constraints

- Do not file unless every precondition passes.
- Do not open private vulnerability reports, pull requests, discussions, or comments.
- Do not change repository settings.
- Do not mark the finding reported unless the issue was successfully created.
- Do not include secrets, private notes, or exploit walkthroughs in the public body.
