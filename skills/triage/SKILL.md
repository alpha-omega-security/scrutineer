---
name: triage
description: Default pipeline scrutineer runs when a repository is added. Triggers a standard set of other skills in parallel, then writes a short summary of what was enqueued. Edit the list below to change the default scan coverage without touching scrutineer's Go code.
license: MIT
compatibility: Needs network access to the scrutineer API (http://host:port/api). Uses `brief` (github.com/git-pkgs/brief) to classify the repository before deciding which scans to enqueue; falls back to enqueueing everything if brief is unavailable.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: freeform
---

# triage

Kick off the standard set of scans against a freshly-added repository.

## Workspace

- `./context.json` — has `scrutineer.api_base`, `scrutineer.token`, and `scrutineer.repository_id`. Required.
- `./report.json` — write a short summary of what you enqueued.

## Classify the repository

Run `brief ./src` and read its JSON. Two fields decide which scans are worth queueing:

- `languages` — programming languages detected; `null` or empty means no source
- `package_managers` — manifest/lockfile ecosystems detected; `null` or empty means nothing publishes or consumes packages here

From those, set two flags:

- `has_packages` = `package_managers` is present and non-empty
- `has_code` = `languages` is present and non-empty

A docs repo (markdown only) has neither. Anything with detected source gets the code scans, whether it is an application, a library, infra scripts, or a flat-layout package. The cost of running semgrep on a stray shell script is far lower than missing a real library because brief failed to populate `layout.source_dirs`. Do not gate on `layout.source_dirs`; it is a heuristic and routinely empty for legitimate codebases. If `brief` is not on PATH or exits non-zero, set both flags true and carry on.

`brief` does not report CI configuration, so set a third flag from a direct filesystem check:

- `has_workflows` = `./src/.github/workflows` exists and is a directory

This gates `zizmor`, which only audits GitHub Actions workflows; with no workflows directory its scan immediately no-ops, so skipping it at triage avoids enqueueing a scan that can do nothing. Unlike the code/package flags this is a definitive check, not a heuristic, so do not default it true on error — if the directory is absent, `has_workflows` is false.

## The scan set

Before enqueueing anything, check what already ran so a re-trigger does not double-enqueue work that is already current.

Get the commit you are running at: `git -C ./src rev-parse HEAD`. Then fetch `GET {api_base}/repositories/{repository_id}/scans`, which returns every scan on this repository with `skill_name`, `status`, and `commit`. If that fetch fails, treat the skip set as empty and carry on. Otherwise build a set of skill names to skip: a skill goes in the skip set if it has a scan with `status` in {`queued`, `running`}, or a scan with `status="done"` whose `commit` equals the current HEAD. A `done` scan at any other commit does not count; the repository has moved since then and the skill should run again. `failed` scans are re-enqueued.

Classify each skill in the list below into exactly one bucket, checking in this order and stopping at the first match: `gated` (its `has_code`/`has_packages`/`has_workflows` flag is false), `already_done` (it is in the skip set), `triggered` (enqueue it). Enqueue with `POST {api_base}/repositories/{id}/skills/{name}/run` and an `Authorization: Bearer {token}` header. Order does not matter; the scrutineer worker runs them as they come in. A 404 response moves the skill from `triggered` to `skipped`.

If `scrutineer.scan_ref` is set in `context.json`, include it in the POST body as `{"ref": "<value>"}` so child scans clone the same branch. If it is empty, send an empty JSON body or omit the body. Verify runs (below) always send `{}`; they are finding-scoped and do not take a ref.

Always:

- `metadata`
- `repo-overview`
- `packages`
- `advisories`

Only when `has_workflows`:

- `zizmor`

Only when `has_packages`:

- `dependencies`
- `sbom`

`packages` and `advisories` query ecosyste.ms by repository URL rather than reading local manifests, so they run unconditionally even though they sound package-related.

Only when `has_code`:

- `subprojects`
- `recon`
- `threat-model`
- `semgrep`

After `threat-model` finishes, Scrutineer reads its durable `scan_config` and
enqueues one `security-deep-dive` per focus area. Do not enqueue
`security-deep-dive` here: starting it before the threat model is complete
would create an unscoped repository-wide audit and defeat the partition.

If a skill name comes back `404 skill not found or inactive`, skip it and note which one in your report; the operator may have disabled it on purpose.

## Re-verify reported findings

If this repository has been scanned before there may be findings already reported to the maintainer that have since been fixed upstream. For each of `status=reported` and `status=acknowledged`, fetch `GET {api_base}/repositories/{repository_id}/findings?status={status}` and collect the returned `id` values. For every finding id, enqueue a verify run: `POST {api_base}/findings/{id}/skills/verify/run` with the bearer header and an empty JSON body. Record the ids you enqueued in the `verify` field of your report; if there are none, write an empty list. If the verify endpoint returns `404 skill not found or inactive`, leave `verify` empty and carry on.

Do not verify findings in `new`, `enriched`, `triaged`, `ready`, `published`, `rejected`, or `duplicate` states. The audit skills re-running above handle the first four; the last three are closed.

## Watch fixed findings for an upstream release

When a finding reaches `fixed` the maintainer has landed a patch, but consumers cannot pin to a commit — they need a tagged release. For findings in `status=fixed`, enqueue release-watch the same way: `POST {api_base}/findings/{id}/skills/release-watch/run`. Record the ids in a `release_watch` field of your report. If the endpoint returns `404 skill not found or inactive`, leave the field empty and carry on. Release-watch is idempotent: a finding that already has a release recorded re-confirms the existing value rather than flapping.

## Output

Write `./report.json` as:

```json
{
  "has_code": true,
  "has_packages": true,
  "has_workflows": false,
  "brief": {"languages": ["Ruby"], "package_managers": ["Bundler"]},
  "triggered": ["packages", "advisories", ...],
  "skipped":   ["semgrep"],
  "gated":     ["zizmor"],
  "already_done": ["metadata"],
  "verify":        [12, 34],
  "release_watch": [55, 56],
  "errors":        []
}
```

`gated` lists skills that were not enqueued because `has_code`, `has_packages`, or `has_workflows` was false. `already_done` holds skills that were skipped because a scan is currently running or already completed at this commit. `skipped` is for skills that came back `404 skill not found or inactive`. `brief` is the subset of brief's output the gates were derived from, so an operator can see why a repo got the short treatment and re-run triage manually if the classification was wrong.

Do not wait for any of the scans to finish. The API returns a scan id immediately; your job is to fire them off and exit.

Do not fabricate scans or invent skill names. If the `api_base` or `token` is missing from context.json, write `{"error": "context.json missing scrutineer block"}` and exit 0 so the failure is visible on the scan page.
