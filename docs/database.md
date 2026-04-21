# Database schema

SQLite with WAL mode. GORM handles migrations on startup. The queue table (`goqite`) is managed separately with an embedded SQL schema.

## repositories

The central entity. One row per git URL.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| url | text, unique | The git clone URL. Always https://. |
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
| created_at | datetime | |
| updated_at | datetime | |

## scans

One row per skill execution. Every scan is a skill; `kind` is always `skill`. `skill_name` / `skill_version` pin which skill ran.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| repository_id | integer FK | References `repositories.id`. Cascade delete. |
| kind | text | Always `skill`. Retained so legacy rows from before the skill framework still render. |
| status | text | `queued`, `running`, `done`, `failed`. Stale `running` rows are swept to `failed` on startup. |
| model | text | Claude model ID. |
| skill_id | integer FK | References `skills.id`. Null for legacy non-skill rows. |
| skill_version | integer | Version of the skill at run time; the skill row's `version` bumps on every edit so older scans stay readable. |
| skill_name | text | Denormalised skill name for UI display. |
| finding_id | integer FK | Set when the scan is finding-scoped (verify/patch/disclose). References `findings.id`. |
| api_token | text | Per-scan bearer token that the skill presents when calling `/api`. Only valid while the scan is running. |
| commit | text | Git HEAD at scan time. |
| started_at | datetime | |
| finished_at | datetime | |
| cost_usd | real | From claude's `total_cost_usd` in stream-json result. |
| turns | integer | Number of claude turns. |
| prompt | text | Activation prompt sent to claude. The skill body lives in the Skill row, not here. |
| report | text | The skill's primary output. JSON for parsed kinds, freeform for everything else. |
| log | text | Line-by-line transcript of the scan. Streamed to the UI via SSE. |
| error | text | Error message if the scan failed. |
| findings_count | integer | Denormalised count of findings parsed from the report. |
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
| output_kind | text | Parser key: `findings`, `maintainers`, `packages`, `advisories`, `dependents`, `dependencies`, `repo_metadata`, `verify`, `freeform`. Promoted from metadata. |
| version | integer | Bumps on every save. |
| active | boolean | |
| source | text | `local`, `remote`, or `ui`. |
| source_path | text | Directory on disk (for local/remote). Empty for UI-created. |
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
| finding_id | text | ID within the originating report, e.g. `F1`. |
| sinks | text | Comma-joined sink IDs. Links to the threat model tab. |
| title | text | |
| severity | text | `Critical`, `High`, `Medium`, `Low`. |
| status | text | Lifecycle state: `new`, `enriched`, `triaged`, `ready`, `reported`, `acknowledged`, `fixed`, `published`, `rejected`, `duplicate`. |
| cwe | text | e.g. `CWE-352`. Tooltips come from the embedded MITRE catalogue. |
| location | text | `file:line` or `file:start-end`. |
| affected | text | Version range, e.g. `>=0.2.0, <=4.0.5`. |
| cve_id | text | e.g. `CVE-2026-12345`. |
| cvss_vector | text | e.g. `CVSS:3.1/AV:N/AC:L/...`. |
| cvss_score | real | |
| fix_version | text | |
| fix_commit | text | |
| resolution | text | `fix`, `migrate`, `workaround`, `adopt`, `wontfix`. |
| disclosure_draft | text | Draft advisory text. |
| assignee | text | Free-text. |
| trace | text | Step 1 prose. Markdown. |
| boundary | text | Step 2. |
| validation | text | Step 3: reproduction. |
| prior_art | text | Step 4. |
| reach | text | Step 5: dependent exposure. |
| rating | text | Step 6: severity justification. |
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
| ecosystem | text | e.g. `gem`, `npm`, `go`. Indexed. |
| p_url | text | Package URL. |
| requirement | text | Version constraint from the manifest. |
| dependency_type | text | `runtime` or `development`. |
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
| ecosystem | text | |
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

Top runtime dependents of this repository's packages. Populated by the `dependents` skill.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| repository_id | integer FK | |
| name | text | |
| ecosystem | text | |
| p_url | text | |
| repository_url | text | Git URL of the dependent. Used by the import button. |
| downloads | integer | |
| dependent_repos | integer | |
| registry_url | text | |
| latest_version | text | |
| created_at | datetime | |

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
