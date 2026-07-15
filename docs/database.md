# Database schema

SQLite with WAL mode. GORM handles migrations on startup. The queue table (`goqite`) is managed separately with an embedded SQL schema.

See [backup.md](backup.md) for backing up and restoring this file: WAL mode means a plain `cp` can be inconsistent, so use `scrutineer backup`/`restore` or one of the documented strategies.

## repositories

The central entity. One row per git URL.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| url | text, unique | The git clone URL (`https://...`) or, for a local-directory scan, `file://<abs-path>`. |
| name | text | Short display name derived from the URL. |
| full_name | text | Owner/repo from ecosyste.ms (e.g. `splitrb/split`). |
| owner | text | Repository owner from ecosyste.ms. |
| description | text | From the metadata skill. |
| default_branch | text | e.g. `main`. |
| languages | text | Primary language. |
| license | text | SPDX identifier, e.g. `mit`. |
| stars | integer | Stargazers count. |
| forks | integer | Fork count. |
| archived | boolean | Whether the repo is archived on the forge. |
| pushed_at | datetime | Last push timestamp. |
| html_url | text | Browser URL. Used for source links. |
| icon_url | text | Avatar/icon URL. |
| metadata | text | Full ecosyste.ms JSON response. Queryable with `json_extract`. |
| fetched_at | datetime | When the metadata skill last ran. |
| ecosystems_repo_data | text | Cached raw `repos.ecosyste.ms` lookup payload, pre-fetched server-side. |
| ecosystems_repo_fetched_at | datetime | When `ecosystems_repo_data` was last refreshed. TTL 30 days. |
| ecosystems_packages_data | text | Cached raw `packages.ecosyste.ms` lookup payload. |
| ecosystems_packages_fetched_at | datetime | When `ecosystems_packages_data` was last refreshed. TTL 30 days. |
| ecosystems_advisories_data | text | Cached `advisories.ecosyste.ms` payload, paginated and concatenated. |
| ecosystems_advisories_fetched_at | datetime | When `ecosystems_advisories_data` was last refreshed. TTL 7 days. |
| ecosystems_commits_data | text | Cached raw `commits.ecosyste.ms` lookup payload. |
| ecosystems_commits_fetched_at | datetime | When `ecosystems_commits_data` was last refreshed. TTL 7 days. |
| ecosystems_issues_data | text | Cached raw `issues.ecosyste.ms` lookup payload. |
| ecosystems_issues_fetched_at | datetime | When `ecosystems_issues_data` was last refreshed. TTL 7 days. |
| ecosystems_dependents_data | text | Cached dependents, chained off the packages lookup (per-package top dependents, capped). |
| ecosystems_dependents_fetched_at | datetime | When `ecosystems_dependents_data` was last refreshed. TTL 30 days. |
| disclosure_channel | text | Preferred reporting vector (email, GHSA URL, registry owner handle, SECURITY.md URL). Written by `maintainers`/`cna-match`; analyst-editable. |
| posture | text | Disclosure-readiness tier from the `posture` skill: `ready`, `partial`, `unprepared`. |
| posture_summary | text | One-line explanation that goes with `posture`. |
| fork | text | `owner/name` of the staging fork inside `-fork-org`. Written by the `fork` skill. |
| clone_error | text | Last clone/fetch failure message; non-empty means the repo is currently unreachable. Cleared on next successful clone. |
| disk_bytes | integer | Cached on-disk size of the persistent clone cache, so the repo list renders the disk badge from a column instead of walking each repo's cache per row. Refreshed by the worker after each scan and backfilled once at startup; 0 for local repos and remote repos not scanned since the column was added. |
| threat_model | text | Operator's working-copy threat-model JSON. When set, the worker writes it to `./threat_model.json` in every skill workspace and `security-deep-dive` loads it instead of fetching the latest `threat-model` scan. Edited via the threat-model workbench tab. Empty = no override. |
| scan_config | text | Analyst-authored YAML with `focus_areas`, `known_bugs`, `attack_surface`, and `skip` patterns. Validated by the repository editor, staged as `scrutineer.scan_config` in every skill workspace, and its `skip` patterns layer onto each skill's path-filter deny list. Empty = no repository-specific guidance. |
| scan_schedule | text | Recurring-scan schedule: `daily`, `weekly`, or a cron expression. Empty inherits the global `scan_schedule` setting; `off` disables scheduling even when a global default is set. |
| upstream_url | text | Upstream this repository is a pushed staging copy of (no forge fork relationship). When set, the scheduler force-syncs the repository from it (a mirror push that overwrites local-only commits) before the new-commit check. Empty for ordinary repos. |
| next_scheduled_scan_at | datetime | Scheduler bookkeeping: when the next scheduled run is due. Null means "recompute on the next tick"; schedule edits reset it instead of computing inline. |
| created_at | datetime | |
| updated_at | datetime | |

## audit_events

Append-only audit trail for lifecycle and future operator/system actions. It
coexists with `finding_histories`, which remains the specialised per-field
change history for findings. `payload` is JSON stored portably as text.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| kind | text | Event name, for example `scan.started`, `scan.finished`, `scan.failed`, `scan.cancelled`, or `scan.paused`. Indexed with `created_at` for chronological dashboards. |
| subject_type | text | Polymorphic subject type, currently `scan`. Part of the timeline index with `subject_id`. |
| subject_id | integer | ID of the subject row, for example `scans.id`. |
| actor | text | Skill name when available, otherwise the scan kind. |
| source | text | Existing provenance enum, currently `system` for worker lifecycle events. |
| payload | text | JSON metadata. Scan events include stable execution metadata and terminal metrics, without duplicating reports or logs. |
| created_at | datetime | |

## scans

One row per skill execution or external import. `skill_name` / `skill_version` pin which skill ran; for imports `skill_name` records the originating tool.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| repository_id | integer FK | References `repositories.id`. Cascade delete. |
| kind | text | `skill` for native scans, `import` for findings ingested via `POST /api/v1/import`, `schedule` for the scheduler's skipped-run trace rows (never queued). |
| status | text | `queued`, `paused`, `running`, `done`, `failed`, `skipped`, `cancelled`. Stale `running` rows are swept to `failed` on startup. `skipped` rows are written terminal by the scheduler when a due run decides not to enqueue (remote HEAD unchanged, scan in flight, ...); `error` carries the reason. |
| status_priority | integer | Denormalised sort key for the scans index: 0 running, 1 queued, 2 paused, 3 terminal. |
| model | text | Claude model ID resolved from the explicit scan model, skill model preference, or skill default model tier at enqueue time. |
| effort | text | Claude `--effort` level (`low`–`max`) snapshotted from the runtime setting at enqueue. Empty on legacy rows; the runner falls back to its configured default. |
| skill_id | integer FK | References `skills.id`. Null for legacy non-skill rows. |
| skill_version | integer | Version of the skill at run time; the skill row's `version` bumps on every edit so older scans stay readable. |
| skill_schema_version | integer | Snapshot of the skill frontmatter `metadata.scrutineer.version` at enqueue time. Used by the benchmark page to attribute expected-finding results to the report schema/version the skill was asked to emit. |
| skill_name | text | Denormalised skill name for UI display. |
| finding_id | integer FK | Set when the scan is finding-scoped (verify/patch/disclose/exposure). References `findings.id`. |
| dependent_id | integer FK | Set on `exposure` scans only. References `dependents.id`; identifies which downstream consumer the skill is auditing for reachability of the upstream finding. |
| baseline_scan_id | integer FK | Set on a fix-validation scan (`POST /repositories/{id}/validate-fix`). References the baseline `scans.id` the fix ref is diffed against. Marks the scan as a validation anchor (the auto triage funnel skips it) and, when it finalises, drives the fingerprint diff written back to `report`. Null on ordinary scans. |
| api_token | text | Per-scan bearer token that the skill presents when calling `/api`. Only valid while the scan is running. |
| ref | text | Git ref to checkout after cloning. Empty means the default branch. |
| skills_repo_sha | text | Commit of `-skills-repo` resolved at startup and stamped on every skill scan. Empty when `-skills-repo` is unset or for `import` scans. |
| sub_path | text | Scopes code analysis to a sub-folder of the clone (monorepo packages). Empty means repo root. |
| rescan_mode | text | `full` for ordinary scans, `diff` for scans that compare the current commit against a baseline. Requested diff scans can fall back to `full` when no baseline exists or the diff is too large. |
| diff_base_scan_id | integer FK | Baseline scan chosen for a diff rescan, or the caller-pinned baseline. References `scans.id`. Null for full scans and for diff requests that fall back before a baseline is resolved. |
| diff_base_commit | text | Baseline commit used to generate `diff.patch` and `changed_files.json`. Empty for full scans. |
| diff_threat_model_scan_id | integer FK | Prior `threat-model` scan staged as `old_threat_model.json` for a diff-aware run, when one is available. |
| diff_stats | text | JSON metadata for the generated diff: base/head commits, changed-file count, patch size, file statuses, staged file names, and limits. |
| coverage | text | JSON coverage metadata. Diff scans record requested versus actual mode and fallback reasons; threat-model scans also record whether the repository working model was updated or skipped for a small diff. |
| scan_group | text | Groups a cohort of scans launched as one batch (Scan-all-subprojects, a single New-scan run, or a Diff rescan group). Each sibling streams a finding to `POST /repositories/{id}/findings` the moment it confirms it and reads `GET /repositories/{id}/findings?scan_group=...` before reporting, so an in-flight skill sees what a sibling has filed so far — not only after that sibling finishes — and can avoid re-filing it. Empty when not part of a batch. |
| focus_area | text | Normalized JSON snapshot of the input-processing focus area assigned to a split `security-deep-dive`. It keeps queued work reproducible if repository `scan_config` changes. Empty means the scan is unscoped and covers its normal repository or subproject scope. |
| profile | text | Runner profile that ran the scan (e.g. `php`). Empty = the default runner image. Set explicitly via `?profile=` or auto-detected from the clone by `brief` before launch; persisted so retries reuse the choice. |
| backend | text | Agent CLI (`-backend`) that ran the scan: `claude` or `codex`. Stamped by the worker so a retry after switching `-backend` starts fresh instead of passing one harness's session id to another's resume command. Empty on rows predating the column or that never reached the runner. |
| commit | text | Git HEAD at scan time. |
| started_at | datetime | |
| finished_at | datetime | |
| cost_usd | real | From claude's `total_cost_usd` in stream-json result. |
| turns | integer | Number of claude turns. |
| input_tokens | integer | Input tokens billed. |
| output_tokens | integer | Output tokens billed. |
| cache_read_tokens | integer | `cache_read_input_tokens` from the result event. |
| cache_write_tokens | integer | `cache_creation_input_tokens` from the result event. |
| max_turns_hit | boolean | True when the scan is `done` with partial output because Claude hit the configured max-turns cap. Such scans keep their session id so Retry can resume. |
| prompt | text | Activation prompt sent to claude. The skill body lives in the Skill row, not here. |
| report | text | The skill's primary output. JSON for parsed kinds, freeform for everything else. On a fix-validation anchor (`baseline_scan_id` set) it is replaced, once the scan finalises, by the JSON validation report: the resolved/surviving/new fingerprint diff against the baseline plus the finding-scoped verify verdicts. |
| refusal_audit | text | Structured post-report `security-deep-dive` follow-up listing analysis the agent declined or skipped. Kept separate from the primary report. |
| refusal_audit_warning | boolean | Denormalized flag set when `refusal_audit` reports a refusal or one or more skipped paths; used to flag incomplete coverage in scan lists. |
| log | text | Line-by-line transcript of the scan. Streamed to the UI via SSE. |
| error | text | Error message if the scan failed. |
| findings_count | integer | Denormalised count of findings parsed from the report. |
| created_at | datetime | |
| updated_at | datetime | |

## expected_findings

Operator-supplied benchmark targets for a repository. Each row is a known file/CWE pair that model-backed scans should rediscover. Matching ignores line numbers, treats CWE case-insensitively, and currently compares Medium+ findings for benchmark metrics.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| repository_id | integer FK | References `repositories.id`. Cascade delete. Part of the unique key with `file` and `cwe`. |
| file | text | Repository-root-relative path, without line number. Absolute paths and parent-directory traversal are rejected by the write path. Part of the unique key with `repository_id` and `cwe`. |
| cwe | text | Normalised CWE identifier, e.g. `CWE-79`. Part of the unique key with `repository_id` and `file`. |
| cve | text | Optional external CVE identifier for operator context. Not used for matching. |
| note | text | Optional free-text note explaining the expected target. |
| created_at | datetime | |
| updated_at | datetime | |

## skills

One row per installed skill. Loaded from `skills/` directories on disk or the UI. Editing a skill creates no new row but bumps `version`.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| name | text, unique | Matches SKILL.md `name` frontmatter. |
| description | text | |
| license | text | |
| compatibility | text | |
| allowed_tools | text | From SKILL.md `allowed-tools`. |
| metadata | text | Raw frontmatter metadata map as JSON. Scrutineer reads `scrutineer.output_file` and `scrutineer.output_kind` from here. |
| body | text | Markdown body after the frontmatter. The prompt. |
| schema_json | text | Optional schema.json contents. |
| output_file | text | Relative path the skill writes to. Promoted from metadata. |
| output_kind | text | Parser key: `findings`, `maintainers`, `packages`, `advisories`, `dependencies`, `finding_dedup`, `repo_metadata`, `repo_overview`, `subprojects`, `posture`, `verify`, `patch`, `threat_model`, `exposure`, `freeform`. Promoted from metadata. |
| version | integer | Bumps on every save. |
| active | boolean | |
| requires_remote | boolean | When true, scrutineer refuses to enqueue this skill against a local-directory repository (file:// URL). Set via `scrutineer.requires_remote: true` in SKILL.md frontmatter. Use for skills that depend on a forge URL or remote-only data (advisories, exposure, fork, maintainers, metadata, packages, report-upstream). |
| requires_profile | text | Constrains the skill to a single registered runner profile (e.g. `php`). Empty means no constraint. Set via `scrutineer.requires_profile` in SKILL.md frontmatter. Enqueue returns 400 when the requested profile mismatches; the worker fails the scan when auto-detection resolves to a different profile. |
| paths | text | Newline-joined shell-glob allow-list from `scrutineer.paths`. When non-empty, the skill sees only matching files inside the workspace `src/` and the builtin skip list is bypassed. |
| ignore_paths | text | Newline-joined shell-glob deny-list from `scrutineer.ignore_paths`. Always layered on top of the active include set. |
| source | text | `bundled`, `local`, `remote`, or `ui`. |
| source_path | text | Directory on disk (for bundled/local/remote). Empty for UI-created. |
| source_hash | text | sha256 of SKILL.md + schema.json. Used by the loader to detect changes. |
| created_at | datetime | |
| updated_at | datetime | |

## findings

One row per vulnerability. Lifecycle columns are mutated through `db.WriteFindingField`, which logs every change to `finding_history`.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| scan_id | integer FK | The scan that first produced this finding. Cascade delete. |
| repository_id | integer FK | Denormalised from scan so list queries skip the join. |
| commit | text | Denormalised from scan. |
| sub_path | text | Denormalised from scan; sub-folder the finding's `location` is relative to. |
| fingerprint | text | Content hash for cross-scan dedupe; `(repository_id, fingerprint)` is indexed. |
| last_seen_scan_id | integer | Most recent scan that re-observed this fingerprint. |
| last_seen_commit | text | Commit at re-observation. |
| seen_count | integer | Total times re-observed across rescans. |
| missed_count | integer | Consecutive same-skill rescans where the fingerprint did not reappear; reset on next re-observation. Non-zero is a hint the issue may be fixed upstream. |
| last_missed_scan_id | integer | Scan where it most recently went missing. |
| finding_id | text | ID within the originating report, e.g. `F1`. |
| sinks | text | Comma-joined sink IDs. Links to the threat model tab. |
| title | text | |
| severity | text | `Critical`, `High`, `Medium`, `Low`. |
| confidence | text | `high`, `medium`, `low`; how certain the audit is. |
| status | text | Lifecycle state: `new`, `enriched`, `triaged`, `ready`, `reported`, `acknowledged`, `fixed`, `published`, `rejected`, `duplicate`. |
| cwe | text | e.g. `CWE-352`. Tooltips come from the embedded MITRE catalogue. |
| location | text | Primary `file:line` or `file:start-end`. |
| locations | text | Newline-joined set of every `file:line` that hit the same fingerprint in this scan. `location` is the first; the rest render as a `+N` badge and an expandable list on the finding page. Empty on rows that predate the column until the next rescan. |
| snippet | text | Source excerpt around `location` (a few lines either side), captured at ingest while the scanned checkout is still on disk. Renders as a fenced code block in the markdown report. Empty for rows written before the column, locations without a line, or paths that did not resolve to a readable file in the checkout; not backfilled. Refreshed on re-observation, never wiped when a later scan cannot recompute it. |
| reachability | text | `reachable`, `harness_only`, `unclear`. `harness_only` is a real bug but not disclosable as a vulnerability on its own. |
| quality_tier | text | `high` (heap overflow, UAF, type confusion, controllable write, shell/eval injection) or `low` (stack exhaustion, assertion failure, fixed-offset null deref, log injection). |
| imported_from | text | Originating tool name when the finding came in via `POST /api/v1/import`; empty for native scans. |
| affected | text | Version range, e.g. `>=0.2.0, <=4.0.5`. |
| cve_id | text | e.g. `CVE-2026-12345`. |
| ghsa_id | text | GitHub Security Advisory id, e.g. `GHSA-xxxx-xxxx-xxxx`; set once the advisory is published on GitHub. |
| cvss_vector | text | CVSS v3.x base vector, e.g. `CVSS:3.1/AV:N/AC:L/...`. |
| cvss_score | real | Derived from `cvss_vector` on write. Cleared when the vector is empty or unparseable. |
| cvss_v4_vector | text | CVSS v4.0 base vector, e.g. `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`. Stored independently of `cvss_vector` because the v4 metric set and scoring formula differ. |
| cvss_v4_score | real | Derived from `cvss_v4_vector` on write. Cleared on empty/unparseable, same as the v3 score. |
| fix_version | text | |
| fix_commit | text | |
| release_tag | text | Tag of the upstream release that first contained the fix (e.g. `v2.3.1`). Set by the release-watch skill once `status=fixed`. |
| release_url | text | Permalink to the release page. |
| released_at | datetime | When the release was published upstream. Together with `release_tag` and `release_url`, these close the gap between fix-landed and fix-shipped for the metrics in dora-metrics. |
| resolution | text | `fix`, `migrate`, `workaround`, `adopt`, `wontfix`. |
| disclosure_draft | text | Draft advisory text. |
| suggested_recipients | text | File-level owners for the finding's `location`: CODEOWNERS entries or, absent those, recent non-bot committers. Comma-joined free text with provenance. Usually produced by the `disclose` skill, but also editable via the finding form and the PATCH API. |
| assignee | text | Free-text. |
| suggested_fix | text | Unified diff from the `patch` skill that passed the applicability gate. Empty when no patch run or the gate rejected it. |
| suggested_fix_commit | text | Sha the suggested_fix applies cleanly against. |
| breaking_change | text | `breaking`, `non_breaking`, or `unknown`; verdict of the `breaking-change` skill on the suggested fix. Empty when the skill has not run. |
| breaking_change_rationale | text | Human-readable rationale plus the list of affected dependents from the same skill run. |
| exploited_in_wild | text | Analyst's call: `yes`, `no`, or empty (unknown). On the OSS-SIRT intake list; surfaced on the finding page, in the OSV `database_specific` block, in the CSAF audit notes, and in the markdown report. Automation never writes this. |
| exploited_in_wild_evidence | text | Free-text source note: researcher, ticket link, traffic observation. |
| mitigation | text | Markdown body from the `mitigate` skill: workarounds consumers can apply before the fix ships, plus detection guidance. |
| mitigation_semgrep | text | Optional YAML semgrep rule from the same skill that flags the vulnerable pattern. Empty when no rule was warranted. |
| last_revalidate_verdict | text | Cached latest verdict from the `revalidate` skill (`true_positive`, `false_positive`, `already_fixed`, `uncertain`). Indexed so the audit queue can filter without scanning `finding_notes`. Empty when revalidate has not run on this finding. |
| trace | text | Step 1 prose. Markdown. |
| boundary | text | Step 2. |
| validation | text | Step 3: reproduction. |
| prior_art | text | Step 4. |
| reach | text | Step 5: dependent exposure. |
| rating | text | Step 6: severity justification. |
| dup_check | text | The audit agent's one-sentence rationale for why this finding is distinct from siblings already filed under the same `scan_group`: which it compared against and why this is not a duplicate. The dedup judge weighs it alongside fingerprint matching. Empty for skills that do not emit it. |
| created_at | datetime | |
| updated_at | datetime | |

Notes, communications, references, labels, and history live in separate tables (see below).

## finding_labels + finding_labels_join

Tags independent of the status lifecycle. `finding_labels_join` is the many-to-many.

| Column | Type | Notes |
|--------|------|-------|
| finding_labels.id | integer PK | |
| finding_labels.name | text, unique | e.g. `wontfix`, `needs-info`. Defaults seeded at startup. |
| finding_labels.color | text | CSS hex for the badge. |
| finding_labels.created_at | datetime | |

## finding_notes

Timestamped internal notes on a finding. Replaced the old `findings.notes` column.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| finding_id | integer FK | Cascade delete. |
| body | text | |
| by | text | Free-text author. |
| created_at | datetime | |

## finding_reviews

Structured human verdicts on a finding, mirroring the revalidate skill's
enum so reviewer agreement with the model is computable. Populated by the
`/audit` page and its browser-only `POST /findings/{id}/reviews` form. The
scan-token API can list reviews but cannot create them. The audit queue excludes
findings that already have a row here.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| finding_id | integer FK | Cascade delete. |
| verdict | text | `true_positive`, `false_positive`, `already_fixed`, `uncertain`. |
| reason | text | Free-text justification. |
| automated_outcome | text | Snapshot of the automation verdict (typically the latest revalidate verdict) at review time. Empty when no automation has spoken. |
| reviewer | text | Optional free-text reviewer identity. |
| created_at | datetime | |

## finding_communications

External interactions about a finding: emails, GHSA submissions, issue replies, etc.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| finding_id | integer FK | Cascade delete. |
| channel | text | `email`, `ghsa`, `issue`, `pr`, `direct`, `registry`. |
| direction | text | `outbound` or `inbound`. |
| actor | text | Other party's name/handle. |
| body | text | |
| offered_help | text | `pr`, `funding`, `adoption`, or empty. |
| at | datetime | When the interaction happened. |
| created_at | datetime | When the row was inserted. |

## finding_references

External URLs related to a finding.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| finding_id | integer FK | Cascade delete. |
| url | text | |
| tags | text | Comma-joined: `issue`, `pr`, `cve`, `ghsa`, `patch`, `advisory`, `discussion`, `article`. |
| summary | text | |
| created_at | datetime | |

## finding_history

Every mutable-field change on a finding, with source attribution.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| finding_id | integer FK | Cascade delete. |
| field | text | `severity`, `status`, `cve_id`, etc. |
| old_value | text | |
| new_value | text | |
| source | text | `tool`, `model_suggested`, or `analyst`. |
| by | text | Author for analyst edits, skill name for model_suggested. |
| created_at | datetime | |

## dependencies

Package dependencies discovered by the `dependencies` skill. Replaced wholesale each run.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| repository_id | integer FK | |
| name | text | |
| ecosystem | text | PURL type, e.g. `gem`, `npm`, `golang`. Derived from `p_url` (or the source ecosystem string when no PURL was recorded). Indexed. |
| p_url | text | Package URL. |
| requirement | text | Version constraint from the manifest. |
| requirement_unresolved | boolean | True when `requirement` still contains an unresolved manifest expression such as `${project.version}`. |
| requirement_resolution | text | Resolver tag for `requirement`, e.g. `resolved`, `unresolved_property`, `unresolved_env`, `unresolved_parent`, `unresolved_profile_gated`, or `unresolved_missing`. |
| dependency_type | text | Normalised dependency phase: `runtime`, `dev`, `test`, `build`, or an unrecognised source value kept verbatim. |
| manifest_path | text | Which file declared this dependency. |
| manifest_kind | text | `manifest` or `lockfile`. |
| created_at | datetime | |

The UI groups dependencies by name+ecosystem. Lockfile versions are preferred over manifest ranges.

## packages

Registry entries from the `packages` skill. Replaced each run.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| repository_id | integer FK | |
| name | text | |
| ecosystem | text | PURL type, derived as in `dependencies`. |
| p_url | text | |
| licenses | text | |
| latest_version | text | |
| versions_count | integer | |
| downloads | integer | |
| dependent_packages | integer | |
| dependent_repos | integer | |
| registry_url | text | |
| latest_release_at | datetime | |
| dependent_packages_url | text | ecosyste.ms API URL for fetching dependents. |
| metadata | text | Full upstream JSON for this package. |
| created_at | datetime | |

## dependents

Top runtime dependents of this repository's packages. Populated by the ecosystems dependents prefetch.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| repository_id | integer FK | |
| name | text | |
| ecosystem | text | PURL type, derived as in `dependencies`. |
| p_url | text | |
| repository_url | text | Git URL of the dependent. Used by the import button. |
| downloads | integer | |
| dependent_repos | integer | |
| registry_url | text | |
| latest_version | text | |
| created_at | datetime | |

## finding_dependents

One row per (finding, dependent) pair the `exposure` skill has audited. Status mirrors the CSAF 2.0 product_status buckets so the VEX export streams the value through unchanged. Upserted on each rerun; the unique index on `(finding_id, dependent_id)` prevents duplicates.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| finding_id | integer FK | References `findings.id`. Part of the unique index. |
| dependent_id | integer FK | References `dependents.id`. Part of the unique index. |
| status | text | `known_affected`, `known_not_affected`, `under_investigation`, or `fixed`. |
| justification | text | CSAF VEX flag label. Only valid when status is `known_not_affected`; cleared by the parser otherwise. |
| rationale | text | One-paragraph explanation written by the skill, rendered in the finding page's per-dependent table. |
| scan_id | integer FK | Exposure scan that wrote this row. |
| scan_commit | text | HEAD of the dependent's clone when the verdict was made; lets the operator tell whether a later rescan would still apply. |
| created_at | datetime | |
| updated_at | datetime | |

## advisories

Known security advisories from the `advisories` skill. Replaced each run.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| repository_id | integer FK | |
| uuid | text | advisories.ecosyste.ms identifier. |
| url | text | |
| title | text | |
| description | text | |
| severity | text | `CRITICAL`, `HIGH`, `MODERATE`, `LOW`. Note: uppercase, unlike finding severity. |
| cvss_score | real | 0-10. |
| classification | text | |
| packages | text | Comma-joined affected package names. |
| published_at | datetime | |
| withdrawn_at | datetime | Non-null if the advisory was withdrawn. |
| created_at | datetime | |

## maintainers

People who maintain repositories. Populated by the `maintainers` skill. Many-to-many with repositories via `repository_maintainers`.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| login | text, unique | GitHub username or equivalent. |
| name | text | |
| email | text | Validated: must contain `@`, no noreply addresses. |
| company | text | |
| avatar_url | text | |
| status | text | `active`, `inactive`, `unknown`. |
| notes | text | Role and evidence from the analysis. |
| created_at | datetime | |
| updated_at | datetime | |

## repository_maintainers

Join table. No extra columns.

| Column | Type | Notes |
|--------|------|-------|
| maintainer_id | integer FK | |
| repository_id | integer FK | |

## subprojects

Monorepo sub-paths discovered by the `subprojects` skill.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| repository_id | integer FK | |
| path | text, not null | Sub-folder relative to repo root. The root itself is represented by absence of a row, not an empty path. |
| name | text | Short human label; falls back to the last path segment. |
| kind | text | Detected flavour: `go-module`, `npm-workspace`, `python-package`, `rust-crate`, `composer-package`, `monorepo-root`, etc. Free-form. |
| description | text | |
| created_at | datetime | |
| updated_at | datetime | |

## sbom_uploads

User-uploaded CycloneDX or SPDX documents. Packages are replaced wholesale on re-upload (cascade delete) but resolved repository rows survive so prior scan results stay attached.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| name | text | Display name for the upload. |
| filename | text | Original filename. |
| format | text | `CycloneDX` or `SPDX`. |
| spec_version | text | e.g. `1.5`. |
| raw | blob | The original document bytes. |
| package_count | integer | Denormalised count of components. |
| import_pending | boolean | True for a newly parsed upload until the operator confirms repository resolution. Legacy and confirmed uploads are false. |
| created_at | datetime | |
| updated_at | datetime | |

## sbom_packages

One component from an uploaded SBOM. `repository_id` is set asynchronously once the PURL resolves to a source repo.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| sbom_upload_id | integer FK | Cascade delete. |
| name | text | |
| version | text | |
| p_url | text | Package URL. Indexed. |
| ecosystem | text | |
| license | text | |
| scope | text | `direct`, `transitive`, or empty when the document had no dependency graph. |
| repository_id | integer FK, nullable | Set once resolved. References `repositories.id`. |
| resolve_error | text | Error message if PURL resolution failed. |
| created_at | datetime | |

## cnas

CVE Numbering Authorities from the public cve.org partner list. Used by the `cna-match` skill to route disclosures.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| short_name | text, unique | e.g. `GitHub_M`. |
| cna_id | text | cve.org CNA identifier. |
| organization | text | Full org name. |
| scope | text | Free-text coverage description as published. |
| email | text | Security contact email. |
| contact_url | text | |
| policy_url | text | |
| advisory_url | text | |
| root | text | Root CNA if this is a sub-CNA. |
| types | text | |
| country | text | |
| metadata | text | Full upstream JSON. |
| fetched_at | datetime | When the CNA list was last refreshed. |
| created_at | datetime | |
| updated_at | datetime | |

## goqite

Job queue managed by the goqite library. Not accessed directly by application code except through the queue package.

| Column | Type | Notes |
|--------|------|-------|
| id | text PK | Random hex, e.g. `m_81b1ef...`. |
| created | text | ISO 8601. |
| updated | text | ISO 8601, auto-updated by trigger. |
| queue | text | Always `scans`. |
| body | blob | Gob-encoded `{Name, Message}` where Message is JSON `{"scan_id": N}`. |
| timeout | text | Visibility timeout. Extended while a job runs. |
| received | integer | Delivery count. Max 3 before dead-lettering. |
| priority | integer | Higher = delivered first. Skill scans use `PrioScan=0`; `PrioFastTool=8` and `PrioMetadata=10` remain defined but are not used by the default pipeline. |
