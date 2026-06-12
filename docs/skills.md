# Skills

Every scan scrutineer runs is a [claude-code skill](https://agentskills.io): a directory containing a `SKILL.md` (YAML frontmatter plus a markdown body), an optional `schema.json` describing the report it writes, and any helper scripts the body refers to. Scrutineer stages the skill into a workspace next to a clone of the target repository, invokes `claude -p` with the skill loaded, validates and parses whatever the skill wrote to its output file, and stores the result against the scan row.

Adding a scan type is a directory drop. No Go changes are needed unless you want a new typed parser for the output.

## Bundled skills

These ship in `skills/` and are loaded with `-skills ./skills`. The `triage` skill is the entry point: when a repository is added scrutineer enqueues `triage`, which classifies the repo with `brief` and enqueues the rest in parallel.

| Skill | What it does |
|---|---|
| `triage` | Default pipeline orchestrator. Classifies the repo, enqueues the appropriate scan set via the scrutineer API, and re-verifies any findings already reported upstream. Edit its body to change what runs by default. |
| `metadata` | Fetches description, default branch, languages, license, stars, archived status, and icon from repos.ecosyste.ms. |
| `repo-overview` | Runs `brief --json` for a structured project summary used by other skills as orientation. |
| `packages` | Looks up every published package the repository produces across all registries, with download and dependent counts. |
| `advisories` | Fetches published GHSA and CVE records that affect any of those packages. |
| `dependents` | Top runtime dependents per published package, ranked, so reach analysis has a shortlist. |
| `dependencies` | Indexes every manifest and lockfile in the tree with `git-pkgs list`. |
| `sbom` | Generates a CycloneDX SBOM with `git-pkgs sbom`. |
| `subprojects` | Enumerates monorepo packages and workspaces so deep-dive scans can be scoped to a sub-path. |
| `maintainers` | Identifies who actually maintains the repo and the best contact route for a security report, distinguishing leads from drive-by contributors and bots. |
| `posture` | Scores readiness to receive a vulnerability report: SECURITY.md, private vulnerability reporting, prior advisories, scanning workflows. |
| `cna-match` | Matches the repository to its CVE Numbering Authority so disclosures route to the right contact. |
| `semgrep` | Runs semgrep with the `p/security-audit` and `p/secrets` rulesets and maps hits into the findings shape. |
| `zizmor` | Audits GitHub Actions workflows and maps hits into the findings shape. |
| `ingest` | Normalizes an externally-produced security report in an arbitrary format into findings. Runs when `/v1/import` cannot recognise the payload; the raw report is staged at `import/report`. |
| `threat-model` | Derives the project's security contract from source and docs: components, entry-point trust table, claimed and disclaimed properties, and disposition labels. Loaded by `security-deep-dive` so it does not re-derive boundaries per run. |
| `security-deep-dive` | The model-driven audit. Inventories trust boundaries and sinks, then runs a six-step trace/boundary/validate/prior-art/reach/rate analysis on each. |
| `finding-dedup` | Compares open findings in one repository and marks findings that describe the same underlying vulnerability as duplicates. |
| `reachability` | Traces sinks already found in this app's dependencies through the app's own code to see which are reachable from its trust boundaries. |
| `exposure` | For one (finding, dependent) pair, decides whether the dependent's published code actually reaches the upstream library finding. Emits one CSAF 2.0 product_status verdict so scrutineer can record affected vs not_affected and stamp the right VEX justification. |
| `verify` | Re-checks one finding against current HEAD and records reproduces / fixed / cannot-reproduce. |
| `revalidate` | Cheap, read-only classifier. Reads a finding's prose plus `git log` over its location and emits `true_positive`/`false_positive`/`already_fixed`/`uncertain`, with an optional adjusted severity. Auto-enqueued for High/Critical findings from `security-deep-dive` and for every imported finding so the human queue is pre-sorted. A `true_positive` verdict on a High/Critical finding chains automatically to `verify`, completing the triage pipeline for imports and high-severity scan output. |
| `breaking-change` | Static breaking-change check: reads the finding's suggested-fix diff and the top dependents list, identifies public API surface changes, and records a verdict (`breaking`/`non_breaking`/`unknown`) with a rationale and the list of affected dependents. Read-only; reasons from the diff and dependent metadata. |
| `release-watch` | After a finding reaches `fixed`, lists the upstream's releases and looks for one that contains `fix_commit` (or whose tag matches `fix_version`). Records the release tag, URL, and timestamp on the finding so the lifecycle visibly ends at a shipped version rather than at the commit landing. The triage skill auto-enqueues this for every `fixed` finding on each repo run. |
| `disclose` | Drafts a GHSA-shaped advisory (title, description, CVSS, CWEs, references) for one finding. |
| `patch` | Proposes a unified diff fixing one finding; a diff that passes the applicability gate is stored on the finding as its suggested fix. |
| `fork` | Forks the repository into the configured org, enables private vulnerability reporting on the fork, and files each finding as a draft advisory there. Only useful when `-fork-org` is set. |
| `report-upstream` | Files one finding on the upstream repository through GitHub's private vulnerability reporting, requests the temporary private fork, and pushes the proposed patch to it when available. github.com only. When upstream has no PVR or is hosted elsewhere, the [disclosure-fallback runbook](disclosure-fallback.md) walks through the CNA, SECURITY.md, and registry routes. |

The descriptions above are the first sentence of each skill's frontmatter `description`; the `/skills` page shows the full text.

## Directory layout

    skills/my-skill/
      SKILL.md          required
      schema.json       optional, JSON Schema for the output file
      scripts/          optional, helper programs the body invokes
      ...               anything else the body references

The loader walks each `-skills` directory looking for `SKILL.md` files up to six levels deep and skipping `.git`, `node_modules`, `vendor`, `.venv`, and `__pycache__`. Each is parsed and upserted into the database keyed by `name`. A content hash over `SKILL.md` and `schema.json` decides whether the row's version is bumped on restart, so editing a skill's body and restarting is enough to roll out a change.

## Frontmatter

The `SKILL.md` frontmatter follows the [agentskills.io specification](https://agentskills.io/specification). Spec violations (name format, field length) are warnings: the skill loads anyway and the warning is logged. The `scrutineer.*` keys under `metadata` are scrutineer's own and are checked strictly: an unknown key, an unrecognised `output_kind`, or an unsupported `scrutineer.version` is a hard error and stops server startup.

```yaml
---
name: my-skill
description: One paragraph saying what the skill does and when to use it.
license: MIT
compatibility: Tools and network access this skill assumes.
allowed-tools: Read,Write,Bash,WebFetch
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: findings
  scrutineer.max_turns: 30
  scrutineer.model: claude-sonnet-4-6
  scrutineer.min_confidence: medium
  scrutineer.report_on: Medium
  scrutineer.fail_on: Critical
  scrutineer.paths:
    - src/**
    - lib/**
  scrutineer.ignore_paths:
    - "**/*.test.*"
---
```

| Key | Type | Meaning |
|---|---|---|
| `name` | string | Skill identifier. Lowercase letters, digits, hyphens. Should match the directory name. |
| `description` | string | Required. Shown on `/skills` and used by claude when deciding whether the skill applies. |
| `license` | string | SPDX identifier. Informational. |
| `compatibility` | string | Free-text note on what the skill needs (binaries on PATH, network access, host APIs). Shown on `/skills`. |
| `allowed-tools` | string | Comma-separated claude-code tool names. Passed through to `claude --allowedTools`. Omit to allow the default set. |
| `metadata.scrutineer.version` | int | Schema version of the `scrutineer.*` keys themselves. This build accepts `1`. |
| `metadata.scrutineer.output_file` | string | Path, relative to the workspace, the skill writes its result to. Almost always `report.json`. |
| `metadata.scrutineer.output_kind` | string | Picks the parser scrutineer runs over `output_file` after the scan. See the table below. |
| `metadata.scrutineer.max_turns` | int | Per-skill cap on `claude --max-turns`. Overrides the global `-max-turns` flag for this skill only. |
| `metadata.scrutineer.model` | string | Model id from the configured list. Overrides the server default for this skill only. Ignored with a warning if not in the list. |
| `metadata.scrutineer.min_confidence` | `low` `medium` `high` | Findings below this confidence are dropped before they reach the database. |
| `metadata.scrutineer.report_on` | `Low` `Medium` `High` `Critical` | Lowest severity that produces a Finding row. Lower-severity hits are recorded on the scan but not surfaced. |
| `metadata.scrutineer.fail_on` | `Low` `Medium` `High` `Critical` | If any finding meets or exceeds this severity, the scan is marked failed. Useful for CI-style gating. |
| `metadata.scrutineer.requires_remote` | bool | When `true`, this skill is skipped on local-directory scans (`file://` repos). Set on skills that need a forge URL or remote-only data such as `advisories`, `dependents`, `exposure`, `fork`, `maintainers`, `metadata`, `packages`, `report-upstream`. Defaults to `false` so new skills run on both remote and local repositories. |
| `metadata.scrutineer.requires_profile` | string | Pins the skill to a single registered runner profile (e.g. `php`). The enqueue API returns `400` when the requested profile mismatches; if the operator does not force a profile, the worker fails the scan when auto-detection resolves to a different one. Must name a profile registered in `internal/worker/profile.go` — `default` and the empty string are not valid here (use the absence of the key for "no constraint"). |
| `metadata.scrutineer.paths` | list of string | Shell-glob allow-list (`*`, `?`, `**`) of paths the skill sees inside the workspace `src/`. When set, only matching files are exposed and the builtin skip list is bypassed. |
| `metadata.scrutineer.ignore_paths` | list of string | Shell-glob deny-list applied on top of `paths` (or, by default, the builtin skip list). |

`min_confidence`, `report_on`, and `fail_on` only apply when `output_kind` is `findings`.

## Path filtering

Before each scan, scrutineer prunes `workRoot/src/` so the skill only sees the files it cares about. The default filter drops lockfiles, minified bundles, build outputs, and generated trees:

```
**/pnpm-lock.yaml, **/package-lock.json, **/yarn.lock, **/Cargo.lock,
**/go.sum, **/Gemfile.lock, **/poetry.lock, **/composer.lock,
**/*.min.js, **/*.min.css,
**/dist/**, **/node_modules/**,
**/generated/**, **/__generated__/**
```

Declaring `scrutineer.paths` replaces this skip list entirely: the skill sees only files matching one of its patterns. `scrutineer.ignore_paths` always layers on top. `.git/` is always preserved so git-aware skills can read history. Skills that walk external APIs and never touch the clone can leave both keys unset. The scan log reports `N file(s) excluded by path filters` whenever the filter trims at least one file.

## Output kinds

`scrutineer.output_kind` picks how scrutineer interprets `report.json` after the run.

| Kind | Stored as |
|---|---|
| `freeform` or empty | Raw text on the scan row. No further parsing. |
| `findings` | Parsed into Finding rows with fingerprint dedupe against prior scans. |
| `repo_metadata` | Repository row fields (description, languages, license, stars, archived). |
| `repo_overview` | Brief summary stored for other skills to read. |
| `packages` | Package rows. |
| `advisories` | Advisory rows. |
| `dependents` | Dependent rows. |
| `dependencies` | Dependency rows. |
| `finding_dedup` | Duplicate decisions applied to existing Finding rows through status history and notes. |
| `maintainers` | Maintainer rows. |
| `subprojects` | Subproject rows for monorepo scoping. |
| `posture` | Posture tier and check results on the Repository row. |
| `verify` | Verification result and miss-count update on one Finding. |
| `revalidate` | Cheap classifier verdict (`true_positive`/`false_positive`/`already_fixed`/`uncertain`) appended as a Note on one Finding. `true_positive` transitions a `new` finding to `enriched`; an optional `adjusted_severity` overwrites the finding's severity with the change recorded in FindingHistory. |
| `breaking_change` | `breaking_change` verdict and `breaking_change_rationale` prose on one Finding, with the verdict change recorded in FindingHistory. |
| `patch` | Suggested-fix diff and base commit on one Finding. |
| `mitigation` | Mitigation prose and optional semgrep rule on one Finding (`mitigation`, `mitigation_semgrep` columns), with the change recorded in FindingHistory. |
| `release_watch` | `release_tag`, `release_url`, `released_at` on one Finding (with history rows), plus a `FindingReference` tagged `upstream-release`. |
| `threat_model` | Raw on the scan row; rendered on the repository's Threat Model tab. |
| `exposure` | One CSAF product_status verdict upserted into a `finding_dependents` row keyed by `(finding_id, dependent_id)`. |

If you need an output shape that is not in this list, see "When you need Go changes" in [development.md](development.md). For most custom skills `freeform` (store the JSON as-is, render it on the scan's Data tab) or `findings` (surface as triaged vulnerabilities) is enough.

## The workspace at runtime

When a scan starts, the worker creates `./data/work/scan-{id}/` with:

    ./src/                       working copy of the target repository at the requested ref
    ./context.json               who you are scanning and how to call scrutineer back
    ./.claude/skills/{name}/     this skill's SKILL.md, schema.json, and any aux files
    ./schema.json                copy of the skill's schema for the model to read
    ./report.json                the skill writes its output here

`./src/` is copied from a per-URL persistent clone under `./data/work/repo-cache/<sha256(url)>/src/` so the second scan of the same repository only fetches the delta. The cache is always full-history; the code browser at `/repositories/{id}/blob/{commit}/{path}` resolves historical commits against it via `git show`.

The worker then runs `claude -p "Use the {name} skill in this workspace"` with the working directory set to the workspace root. Anything the skill writes outside `./report.json` is discarded when the workspace is cleaned. Write intermediate files under `./` rather than `/tmp`; concurrent scans share `/tmp` in the docker runner.

## context.json

```json
{
  "repository": {
    "url": "https://github.com/owner/repo",
    "html_url": "https://github.com/owner/repo",
    "name": "repo",
    "full_name": "owner/repo",
    "default_branch": "main"
  },
  "commit": "abc123",
  "packages": [
    {"name": "repo", "ecosystem": "npm", "purl": "pkg:npm/repo@1.0.0"}
  ],
  "scrutineer": {
    "api_base": "http://host.docker.internal:8080/api",
    "scan_id": 42,
    "token": "per-scan bearer, 32 random hex bytes",
    "repository_id": 7,
    "skill_id": 3,
    "finding_id": 19,
    "dependent_id": 11,
    "scan_ref": "release/2.x",
    "scan_subpath": "packages/core",
    "fork_org": "your-security-forks",
    "metadata_dir": ".scrutineer/"
  }
}
```

`finding_id` is only present for finding-scoped skills (`verify`, `revalidate`, `breaking-change`, `disclose`, `patch`, `mitigate`, `release-watch`, `exposure`). `dependent_id` is only set on `exposure` runs and points to the dependent whose code is under audit; `./src` is then a copy of that dependent's clone, not of the finding's repository. `scan_ref` is empty when the scan is on the default branch. `scan_subpath` is set when the operator scoped the scan to a monorepo sub-folder; skills that walk source honour it, skills that query external APIs by repository URL ignore it. `fork_org` is absent unless `-fork-org` is configured. `metadata_dir` is the directory inside a staging repo where scrutineer keeps its per-project metadata (`.scrutineer/` by default); operators with a different consortium-flavoured convention set `metadata_dir` in scrutineer.yaml. `packages` is a convenience copy of the package rows when the `packages` skill has already run; otherwise it is omitted.

## schema.json

If a `schema.json` sits next to `SKILL.md`, scrutineer stages it into the workspace so the model can read the expected output shape, and after the run validates `report.json` against it with a draft 2020-12 validator. By default a mismatch is logged to the scan transcript and the parser still runs, so a stricter schema does not break ingestion. Start scrutineer with `-schema-strict` (or `schema_strict: true` in the config file) to turn that warning into a scan failure with the validator output in `Scan.Error`; useful while iterating on a skill locally.

Bundled skills with typed output kinds carry a schema; skills with `output_kind: freeform` generally do not.

## Calling scrutineer from a skill

`context.json` carries `scrutineer.api_base` and a per-scan bearer `scrutineer.token`. With those a skill can read prior scan results for the same repository, enqueue further scans, fetch maintainers, packages, advisories, dependents, and findings, and write notes and field updates back to a finding. The full surface is documented in [openapi.yaml](../openapi.yaml) at the repository root. The `triage` skill is the reference example for enqueueing; `disclose` and `patch` are the reference examples for finding writes.

The token is scoped to the scan's own repository: a skill cannot read or write rows belonging to other repositories.

## Loading skills

Skills are loaded at startup from any combination of:

- `-skills <dir>` (repeatable) for local directories,
- `-skills-repo <owner/repo[@ref]>` (or full `https://host/path[@ref]`) to clone a git repository of skills on startup; an `@ref` suffix pins a branch, tag or commit, and the resolved SHA is stamped onto every scan. The ref must be a single segment (`main`, `v1.0`, or a SHA; not `refs/heads/main`), which leaves `https://<token>@host/...` usable for private repos,
- the `/skills` page in the UI to create or edit a skill in the browser.

A skill loaded from disk replaces any UI-edited skill of the same name on the next restart. Disable a skill on `/skills` to keep it in the database but reject any attempt to run it.
