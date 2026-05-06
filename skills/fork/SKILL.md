---
name: fork
description: Fork the scanned repository into the configured GitHub organisation, enable private vulnerability reporting on the fork, record the scan as a git note, and file each finding as a draft security advisory on the fork with a relevant org team invited as collaborator. Run after a scan has produced findings; the fork is the staging area for disclosure work.
license: MIT
compatibility: Needs the gh CLI authenticated with a token that can create forks in the fork_org and manage repository settings and security advisories there. Needs network access to api.github.com and the scrutineer API. github.com upstreams only for now.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: freeform
---

# fork

Stage a scanned repository into the disclosure org. Forks the upstream into `fork_org`, turns on private vulnerability reporting on the fork, leaves a git note recording when scrutineer last scanned the upstream, and opens one draft advisory per finding on the fork so analysts and the relevant team can collaborate on the write-up before anything goes upstream.

## Workspace

- `./src` — the upstream clone at the commit that was scanned
- `./context.json` — has `repository.url`, `repository.full_name`, `scrutineer.api_base`, `scrutineer.token`, `scrutineer.repository_id`, `scrutineer.scan_id`, and `scrutineer.fork_org`
- `./report.json` — write what you did

Use the `gh` CLI for every GitHub call. Do not use curl against api.github.com.

## Preconditions

Read `./context.json`. Refuse to continue (write `{"error": "..."}` to `report.json` and exit 0) if:

- `scrutineer.fork_org` is missing or empty — the operator has not configured `fork_org` in scrutineer.yaml
- `repository.url` does not have host `github.com` — only GitHub upstreams are supported for now; non-GitHub hosts will get a create-in-org path later
- `gh auth status` fails — the runner has no GitHub credentials

Derive `{owner}/{repo}` from `repository.full_name` (fall back to parsing the path of `repository.url`, stripping a trailing `.git`).

## 1. Fork into the org

First check whether scrutineer already knows the fork: `GET {api_base}/repositories/{repository_id}` returns a `fork` field. If it is non-empty and `gh repo view {fork}` succeeds with `.parent` pointing at `{owner}/{repo}`, use it as `{fork_org}/{fork_name}`, record `"forked": "exists"`, and skip to step 2.

Otherwise the fork normally lives at `{fork_org}/{repo}`, but that slot may already be taken by an unrelated repository (e.g. forking `foo/redis` when `fork-central/redis` is already a fork of `bar/redis`). Resolve the fork name as follows.

For each candidate name, in order `{repo}` then `{owner}-{repo}`:

```
gh repo view {fork_org}/{candidate} --json name,parent
```

- not found — the slot is free; remember this candidate as `{fork_name}` and stop
- found and `.parent.owner.login == {owner}` and `.parent.name == {repo}` — this is already our fork; set `{fork_name}` to this candidate, record `"forked": "exists"`, and skip to step 2
- found but the parent is something else (or null) — the name is taken by an unrelated repo; move to the next candidate

If both candidates are taken by unrelated repositories, write `{"error": "no free fork name for {owner}/{repo} in {fork_org}"}` and exit 0.

If you found a free slot, create the fork there:

```
gh repo fork {owner}/{repo} --org {fork_org} --fork-name {fork_name} --clone=false --default-branch-only
```

`gh repo fork` is asynchronous on GitHub's side. Poll `gh repo view {fork_org}/{fork_name}` until it returns 0 (a few seconds is normal; give up after a minute and report `{"error": "fork did not become available"}`). Record `"forked": "created"`.

Whichever path you took, persist the resolved name back to scrutineer so the next run and the UI can find it without re-probing:

```
PATCH {api_base}/repositories/{repository_id}
Authorization: Bearer {token}
{"fork": "{fork_org}/{fork_name}"}
```

## 2. Enable private vulnerability reporting on the fork

Use the dedicated endpoint; the `security_and_analysis` block on `PATCH /repos/...` accepts the field but does not actually flip it.

```
gh api -X PUT repos/{fork_org}/{fork_name}/private-vulnerability-reporting
```

A 204 means it is on. Confirm with `gh api repos/{fork_org}/{fork_name}/private-vulnerability-reporting` which returns `{"enabled": true|false}`. A 422 usually means the org has it forced on or off at the org level; record that in `notes` and carry on.

## 3. Record the scan on the fork

Record when scrutineer last looked at this repository, regardless of whether there were findings, as a git note on the scanned commit and push it to the fork. The note lives under `refs/notes/scrutineer` so it does not collide with anything upstream uses.

```
HEAD=$(git -C ./src rev-parse HEAD)
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
git -C ./src notes --ref=scrutineer add -f -m "scrutineer: scanned $NOW at $HEAD (scan {scan_id})" "$HEAD"
git -C ./src push -f "https://github.com/{fork_org}/{fork_name}.git" refs/notes/scrutineer
```

If the workspace clone is shallow `git push` may need `git -C ./src fetch --unshallow` first; only do that if the push is rejected for shallow reasons. If the push fails for any other reason (branch protection on notes refs, auth), record the error in `notes` and carry on — the note is a convenience, not a hard requirement.

## 4. File draft advisories for findings

Fetch the repository's findings: `GET {api_base}/repositories/{repository_id}/findings` with `Authorization: Bearer {token}`. File an advisory for every finding whose `status` is one of `new`, `enriched`, `triaged`, or `ready` — that is, anything that has not already been reported upstream or closed out. Skip `reported`, `acknowledged`, `fixed`, `published`, `rejected`, and `duplicate`; record those under `"skipped_advisories"` with the status as the reason. If nothing is left, record `"advisories": []` and skip to step 5.

For each remaining finding fetch the full record (`GET {api_base}/findings/{id}`) so you have `disclosure_draft`, `cvss_vector`, `cwe`, `affected`, and `title`.

Before filing, list the advisories already on the fork so re-runs do not duplicate:

```
gh api repos/{fork_org}/{fork_name}/security-advisories --paginate --jq '.[].summary'
```

Skip a finding whose title already appears as an advisory summary; record it under `"skipped_advisories"`.

For each remaining finding, build the request body and create a draft repository security advisory on the fork. Use the admin create endpoint, not `/reports` — `/reports` is for external reporters and is rejected when the caller is a repo admin, which we are.

```
gh api -X POST repos/{fork_org}/{fork_name}/security-advisories --input ./advisory-{finding_id}.json
```

The body shape is the GHSA create schema:

```json
{
  "summary": "<finding.title>",
  "description": "<finding.disclosure_draft>",
  "severity": "<critical|high|medium|low, lowercased from finding.severity>",
  "cvss_vector_string": "<finding.cvss_vector, omit severity if this is set>",
  "cwe_ids": ["CWE-79"],
  "vulnerabilities": [
    {"package": {"ecosystem": "<ghsa enum>", "name": "<pkg>"}, "vulnerable_version_range": "<finding.affected>"}
  ]
}
```

Build `vulnerabilities` from `GET {api_base}/repositories/{repository_id}/packages` using the same ecosystem mapping the disclose skill uses (rubygems, npm, pip, maven, nuget, composer, go, rust, erlang, actions, pub, other). If the repository has no packages, send `"vulnerabilities": [{"package": {"ecosystem": "other", "name": "{owner}/{repo}"}}]` — the endpoint requires at least one entry.

`vulnerable_version_range` must be a bare constraint string. `finding.affected` is analyst prose and often carries annotations like `<= 0.9.1 (all published versions)` or `1.x through 2.3`; reduce it to comma-separated `OP VERSION` clauses where OP is one of `<`, `<=`, `>`, `>=`, `=` and VERSION is dotted-numeric (a leading `v` is fine). Drop anything in parentheses, drop the package name if it was repeated, and turn `all versions` / `every release` into `>= 0`. If you cannot confidently reduce it to that shape, omit `vulnerable_version_range` from the entry and keep the original prose in the description's Affected versions section instead.

If `disclosure_draft` is empty the disclose skill has not run on this finding yet. Assemble the description yourself from the finding's six-step prose (the full `GET {api_base}/findings/{id}` response includes `trace`, `boundary`, `validation`, `prior_art`, `reach`, `rating` even for `new` findings). Use this template, dropping any section whose source field is empty:

```
> Draft staged by scrutineer from finding {finding_id} (scan {scan_id}). Not yet reviewed by an analyst.

## Summary

{title}. {first sentence of rating, or "Severity: {severity}" if rating is empty}.

## Location

`{location}` on `{owner}/{repo}`.

## Details

{trace}

## Trigger

{boundary}

## Reproduction

{validation}

## Impact

{rating}

## Reach

{reach}

## References

- {repository.html_url}/blob/{default_branch}/{location path without :line}
- https://cwe.mitre.org/data/definitions/{n}.html  (one per CWE in finding.cwe)
- {each URL that appears verbatim in prior_art}
```

Do not invent content for missing sections; the draft is allowed to be sparse. Note in `notes` that disclose has not run on that finding.

Capture the `ghsa_id` and `html_url` from the response. Then write them back to scrutineer so the finding page links to the draft:

- `POST {api_base}/findings/{id}/references` with `{"url": "<html_url>", "tags": "ghsa-draft", "summary": "Draft advisory on {fork_org} fork"}`
- `POST {api_base}/findings/{id}/communications` with `{"channel": "ghsa", "direction": "outbound", "actor": "fork", "body": "Draft advisory <ghsa_id> opened on {fork_org}/{fork_name}"}`

Do not change the finding's `status`. `reported` means reported to the upstream maintainer; a draft on the staging fork is not that.

## 5. Invite a team

List the org's teams once:

```
gh api orgs/{fork_org}/teams --paginate --jq '.[].slug'
```

Pick at most one team whose slug matches the repository, trying these signals in order and stopping at the first hit:

1. **Foundation / upstream org.** Lowercase the upstream `{owner}` and see if any team slug is a substring of it or vice versa. `eclipse-platform` or `eclipse-ee4j` matches an `eclipse` team, `apache` matches `apache`, a `kubernetes-sigs` repo matches `kubernetes` or `cncf`. Also check `GET {api_base}/repositories/{repository_id}/maintainers` — if a maintainer's affiliation or the repo's funding/SECURITY.md (already in `./src`) names a foundation that appears as a team slug, prefer that.
2. **Ecosystem.** `package_managers[0].name` from `brief ./src`, mapped the same way as the GHSA ecosystem enum: Bundler→`ruby`/`rubygems`, npm/Yarn/pnpm→`npm`/`javascript`/`nodejs`, Cargo→`rust`, Go Modules→`go`/`golang`, pip/Poetry→`python`/`pypi`, Maven/Gradle→`java`/`maven`, Composer→`php`.
3. **Primary language.** `languages[0].name` from `brief ./src`, lowercased.

Match by normalising both the candidate and each team slug (lowercase, strip non-alphanumerics) and testing whether either contains the other. If nothing matches, leave `"team": null` and move on — do not invent a team.

If a team matched and you filed at least one advisory, add the team as a collaborator on each new advisory:

```
gh api -X PATCH repos/{fork_org}/{fork_name}/security-advisories/{ghsa_id} --input - <<'JSON'
{"collaborating_teams": ["<team-slug>"]}
JSON
```

Also give the team push access to the fork itself so they can see it and work on a patch later:

```
gh api -X PUT orgs/{fork_org}/teams/{team-slug}/repos/{fork_org}/{fork_name} -f permission=push
```

## Output

Write `./report.json`:

```json
{
  "fork_org": "fork-central",
  "upstream": "owner/repo",
  "fork": "fork-central/repo",
  "fork_name": "repo",
  "forked": "created",
  "private_reporting": "enabled",
  "scanned_at": "2026-05-04T12:00:00Z",
  "scanned_commit": "abc123...",
  "note_pushed": true,
  "advisories": [
    {"finding_id": 17, "ghsa_id": "GHSA-xxxx-xxxx-xxxx", "url": "https://github.com/fork-central/repo/security/advisories/GHSA-..."}
  ],
  "skipped_advisories": [{"finding_id": 18, "reason": "already filed"}],
  "team": "rust",
  "notes": "anything that did not go cleanly",
  "error": null
}
```

`forked` is one of `created`, `exists`. `private_reporting` is `enabled`, `already-enabled`, or `org-managed`. `team` is the slug you invited or `null`.

## Constraints

- Do not touch the upstream repository's settings or file anything against it. Everything in this skill targets the fork.
- Do not run if `fork_org` is unset; the operator must opt in.
- Do not delete or overwrite an existing fork.
- Do not invent CVE IDs, CWEs, or package names that are not on the finding.
