---
name: fork
description: Stage a scanned repository into a private repo in the configured GitHub organisation. Creates the repo (no fork relationship), seeds it with the upstream tree, writes scrutineer metadata under the configured metadata directory, files one issue per open finding, and gives an org team push access. The staging repo is the per-project working surface for triage, fix development, and the disclosure paper trail.
license: MIT
compatibility: Needs the gh CLI authenticated with a token that can create private repos in `fork_org`, write to issues there, and manage team repo access. Needs network access to api.github.com and the scrutineer API. github.com upstreams only for now; other hosts will route through the same skill once `host__owner__repo` naming generalises.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: freeform
  scrutineer.requires_remote: true
---

# fork

Stand up a private staging repo for one scanned upstream. The staging repo is a plain clone of the upstream tree (no GitHub fork relationship), lives in `fork_org`, and is the working surface for everything that follows: finding issues, PoC files, patch diffs, and validation reports all live here. Scrutineer's metadata sits at the repo root in the directory named by `scrutineer.metadata_dir` (default `.scrutineer/`). Run after a scan has produced findings; idempotent on re-runs.

Below, the placeholder `{metadata_dir}` stands for the value of `scrutineer.metadata_dir` from `./context.json`. Substitute it verbatim before issuing any git or shell command.

## Workspace

- `./src` — the upstream clone at the commit that was scanned
- `./context.json` — has `repository.url`, `repository.full_name`, `repository.default_branch`, `scrutineer.api_base`, `scrutineer.token`, `scrutineer.repository_id`, `scrutineer.scan_id`, `scrutineer.fork_org`, and `scrutineer.metadata_dir`
- `./report.json` — write what you did

Use the `gh` CLI for every GitHub call. Do not use curl against api.github.com.

## Preconditions

Read `./context.json`. Refuse to continue (write `{"error": "..."}` to `report.json` and exit 0) if:

- `scrutineer.fork_org` is missing or empty — the operator has not configured `fork_org` in scrutineer.yaml
- `repository.url` does not have host `github.com` — other hosts get the same treatment but the host-prefix mapping (below) is hard-coded to `gh` for now
- `gh auth status` fails — the runner has no GitHub credentials

Derive `{owner}/{repo}` from `repository.full_name` (fall back to parsing the path of `repository.url`, stripping a trailing `.git`).

## 1. Resolve the staging repo name

The staging repo lives at `{fork_org}/{host}__{owner}__{repo}`, lowercased:

- `host` is `gh` for `github.com`
- `owner` and `repo` come straight from the upstream URL

So `https://github.com/madler/zlib` becomes `{fork_org}/gh__madler__zlib`. Deterministic and collision-free across hosts, so no probing for free slots.

If scrutineer already knows the staging repo (`GET {api_base}/repositories/{repository_id}` has a non-empty `fork`), use it as `{staging}` and skip to step 3. The field is named `fork` for legacy reasons; semantically it is the staging repo URL.

## 2. Create and seed the staging repo

Check whether it already exists:

```
gh repo view {fork_org}/{host}__{owner}__{repo}
```

If `view` succeeds, record `"created": "exists"` and skip to step 3.

Otherwise create it:

```
gh repo create {fork_org}/{host}__{owner}__{repo} --private \
  --description "scrutineer staging for {owner}/{repo}"
```

Then seed it from `./src`. The goal is a default branch on the staging repo that contains the upstream tree at its full history (so VIDs, fingerprints, locations, and patches all resolve the same way they do on the upstream):

```
cd ./src
# Make sure history is complete enough to push. Shallow clones cannot be pushed.
git fetch --unshallow origin || true
git remote add scrutineer-staging https://github.com/{fork_org}/{host}__{owner}__{repo}.git
git push scrutineer-staging HEAD:{repository.default_branch}
```

If `git fetch --unshallow` fails (the clone was already complete) ignore it. If the push fails because of unshallow, record `"error": "could not push full history"` and exit 0 — half-seeded repos cause more confusion than they fix.

Record `"created": "created"` and persist the resolved name back to scrutineer so the next run skips the probe:

```
PATCH {api_base}/repositories/{repository_id}
Authorization: Bearer {token}
{"fork": "{fork_org}/{host}__{owner}__{repo}"}
```

## 3. Write the repo-level metadata

Build the per-repo metadata block:

```yaml
# {metadata_dir}/metadata.yaml
upstream:
  url: {repository.url}
  host: github.com
  owner: {owner}
  repo: {repo}
seeded_at: {ISO-8601 timestamp, UTC}
seeded_commit: {git -C ./src rev-parse HEAD}
last_scan_at: {same timestamp, refreshed on every run}
last_scan_id: {scan_id}
last_scan_commit: {same as seeded_commit on first run; refresh on re-runs}
```

On re-runs only the `last_scan_*` fields change.

The simplest write path is one commit per skill run carrying every file under `{metadata_dir}` that changed in this run. Clone the staging repo into a temp working tree, write the files, commit, push:

```
TMP=$(mktemp -d)
git clone --depth 1 https://github.com/{fork_org}/{host}__{owner}__{repo}.git "$TMP/staging"
cd "$TMP/staging"
mkdir -p {metadata_dir}
# write {metadata_dir}/metadata.yaml and per-finding files (see step 4) here
git add {metadata_dir}
git -c user.email=scrutineer@local -c user.name=scrutineer \
  commit -m "scrutineer: scan {scan_id} at {short-commit}" -m "Updated {metadata_dir} from scrutineer run."
git push origin {repository.default_branch}
```

The commit author is local; the push uses the gh CLI's credentials. One commit per run keeps the history readable.

## 4. Per-finding metadata files

Fetch the repository's findings: `GET {api_base}/repositories/{repository_id}/findings` with `Authorization: Bearer {token}`. Include findings whose `status` is one of `new`, `enriched`, `triaged`, `ready`, `reported`, `acknowledged`, `fixed`. Skip `rejected`, `duplicate`, and `published` — those do not have a staging-side life. Record skipped ones under `"skipped"` with the status as reason.

For each remaining finding fetch the full record (`GET {api_base}/findings/{id}`) so you have its prose, severity, status, CVSS, CWE, `disclosure_draft`, and `suggested_fix`.

In the staging working tree, write the following files under `{metadata_dir}/findings/{finding_id}/`:

- `metadata.yaml`:
  ```yaml
  finding_id: {id}
  title: {title}
  severity: {severity}
  status: {status}
  cwe: {cwe}
  cvss_vector: {cvss_vector}
  location: {location}
  opened_at: {ISO-8601, set on first appearance; do not overwrite on re-runs}
  last_updated_at: {ISO-8601, refreshed every run}
  issue_url: {will be set in step 5 once the issue is filed; leave empty for now}
  ```
- `disclosure-draft.md`: contents of the finding's `disclosure_draft` field. Omit if empty.
- `patch.diff`: contents of `suggested_fix`. Omit if empty.

If a finding directory already exists in the clone, preserve the `opened_at` field from the existing `metadata.yaml`; everything else is overwritten by the new run's values. Validation reports and PoC files written by other skills (`fix-validation`, future PoC writer) live in the same directory and are also preserved across re-runs.

## 5. File one issue per finding

List existing issues on the staging repo once, capturing the marker line from each body:

```
gh api repos/{fork_org}/{host}__{owner}__{repo}/issues --paginate \
  --jq '.[] | {number, body, state, labels: [.labels[].name]}'
```

Every issue this skill files carries a `[scrutineer-finding:{finding_id}]` marker on its last line. Skip a finding whose marker already appears in any existing issue body; back-fill its `issue_url` in `metadata.yaml` from the existing issue. Record it under `"skipped_issues"` with reason `"already filed"`.

For each remaining finding, build the issue body. Use `disclosure_draft` when present; otherwise assemble from the finding's six-step prose. Drop any section whose source field is empty.

```
{title}

> Staged by scrutineer from finding {finding_id} (scan {scan_id}).

## Summary

{first sentence of rating, or "Severity: {severity}" if rating is empty}

## Location

`{location}` on `{owner}/{repo}`

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
- https://cwe.mitre.org/data/definitions/{n}.html  (one per CWE)
- {each URL in prior_art}

[scrutineer-finding:{finding_id}]
```

The marker on the last line is the dedup contract — do not move it, do not change its shape.

File the issue with severity labelled:

```
gh issue create -R {fork_org}/{host}__{owner}__{repo} \
  --title "{title}" \
  --body-file ./issue-{finding_id}.md \
  --label "severity:{severity-lowercase}"
```

Create the `severity:{level}` label first if it does not exist:

```
gh label create "severity:{level}" -R {fork_org}/{host}__{owner}__{repo} \
  --color "{matching colour}" --description "Finding severity" --force
```

Colours: `severity:critical` `#8b0000`, `severity:high` `#dc3545`, `severity:medium` `#ffc107`, `severity:low` `#6c757d`. `--force` makes label creation idempotent across runs.

Status labels (`status:*`) are not applied by this skill yet; they belong with a future state-sync pass. Filing them prematurely would conflict with the future taxonomy.

Capture the issue URL from the create response. Update `{metadata_dir}/findings/{finding_id}/metadata.yaml` with `issue_url`. Then write the issue link back to scrutineer:

- `POST {api_base}/findings/{id}/references` with `{"url": "<issue_url>", "tags": "staging-issue", "summary": "Issue on {fork_org} staging repo"}`
- `POST {api_base}/findings/{id}/communications` with `{"channel": "github-issue", "direction": "outbound", "actor": "fork", "body": "Issue #{number} opened on {fork_org}/{host}__{owner}__{repo}"}`

Do not change the finding's `status`. A staging issue is not a report upstream.

After all writes, the working tree should contain one updated `{metadata_dir}/metadata.yaml`, the per-finding directories with refreshed metadata and (where present) draft/patch files, and an unmodified upstream tree. Commit and push as described in step 3.

## 6. Pick a team and give it push access

List the org's teams once:

```
gh api orgs/{fork_org}/teams --paginate --jq '.[].slug'
```

Pick at most one team whose slug matches the repository, trying these signals in order and stopping at the first hit:

1. **Foundation / upstream org.** Lowercase the upstream `{owner}` and check whether any team slug is a substring of it or vice versa. `eclipse-platform` or `eclipse-ee4j` matches an `eclipse` team, `apache` matches `apache`, a `kubernetes-sigs` repo matches `kubernetes` or `cncf`. Also check `GET {api_base}/repositories/{repository_id}/maintainers` — if a maintainer's affiliation or the repo's funding/SECURITY.md (already in `./src`) names a foundation that appears as a team slug, prefer that.
2. **Ecosystem.** `package_managers[0].name` from `brief ./src`, mapped the same way as the GHSA ecosystem enum: Bundler→`ruby`/`rubygems`, npm/Yarn/pnpm→`npm`/`javascript`/`nodejs`, Cargo→`rust`, Go Modules→`go`/`golang`, pip/Poetry→`python`/`pypi`, Maven/Gradle→`java`/`maven`, Composer→`php`.
3. **Primary language.** `languages[0].name` from `brief ./src`, lowercased.

Match by normalising both the candidate and each team slug (lowercase, strip non-alphanumerics) and testing whether either contains the other. If nothing matches, leave `"team": null` and move on — do not invent a team.

Give the team push access on the staging repo:

```
gh api -X PUT orgs/{fork_org}/teams/{team-slug}/repos/{fork_org}/{host}__{owner}__{repo} \
  -f permission=push
```

Idempotent — re-running with the same team produces the same access.

## Output

Write `./report.json`:

```json
{
  "fork_org": "fork-central",
  "upstream": "owner/repo",
  "staging": "fork-central/gh__owner__repo",
  "created": "created",
  "seeded_commit": "abc123...",
  "scanned_at": "2026-05-04T12:00:00Z",
  "issues": [
    {"finding_id": 17, "number": 3, "url": "https://github.com/fork-central/gh__owner__repo/issues/3"}
  ],
  "skipped_issues": [{"finding_id": 18, "reason": "already filed"}],
  "skipped": [{"finding_id": 19, "reason": "duplicate"}],
  "team": "rust",
  "notes": "anything that did not go cleanly",
  "error": null
}
```

`created` is one of `created`, `exists`. `team` is the slug you gave push access, or `null`.

## Constraints

- Do not touch the upstream repository's settings or file anything against it. Everything in this skill targets the staging repo.
- Do not run if `fork_org` is unset; the operator must opt in.
- Do not delete or overwrite an existing staging repo.
- Do not invent CVE IDs, CWEs, or package names that are not on the finding.
- Do not file or modify draft GHSA advisories. Private staging repos have no PVR / no advisory surface; that path belongs to `report-upstream` against the github.com upstream.
- Do not apply `status:*` labels — that taxonomy belongs to the future state-sync pass.
