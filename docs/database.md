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
| description | text | From ecosyste.ms metadata job. |
| default_branch | text | e.g. `main`. |
| languages | text | Primary language from ecosyste.ms. |
| license | text | SPDX identifier, e.g. `mit`. |
| stars | integer | Stargazers count. |
| forks | integer | Fork count. |
| archived | boolean | Whether the repo is archived on the forge. |
| pushed_at | datetime | Last push timestamp from ecosyste.ms. |
| html_url | text | Browser URL, validated to http/https scheme. Used for source links. |
| icon_url | text | Avatar/icon URL, validated to http/https. |
| metadata | text | Full ecosyste.ms JSON response. Queryable with `json_extract`. |
| fetched_at | datetime | When the metadata job last ran. |
| created_at | datetime | |
| updated_at | datetime | |

## scans

One row per job execution. The `kind` field names the job type; the `status` field tracks the queue lifecycle.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| repository_id | integer FK | References `repositories.id`. Cascade delete. |
| kind | text | Job type: `metadata`, `packages`, `advisories`, `commits`, `dependents`, `brief`, `git-pkgs`, `sbom`, `semgrep`, `zizmor`, `maintainers`, `claude`. |
| status | text | `queued`, `running`, `done`, `failed`. Stale `running` rows are swept to `failed` on startup. |
| model | text | Claude model ID for model-backed jobs. Validated against `internal/web/models.go`. |
| commit | text | Git HEAD at scan time. |
| started_at | datetime | |
| finished_at | datetime | |
| cost_usd | real | From claude's `total_cost_usd` in stream-json result. |
| turns | integer | Number of claude turns. |
| prompt | text | The full prompt sent to claude. Only populated for model-backed jobs. |
| report | text | The job's primary output. JSON for most jobs, SARIF for semgrep/zizmor. |
| log | text | Line-by-line transcript of the job. Streamed to the UI via SSE. |
| error | text | Error message if the job failed. |
| findings_count | integer | Denormalised count of findings parsed from the report. |
| created_at | datetime | |
| updated_at | datetime | |

## findings

One row per vulnerability identified by a claude audit scan. Parsed from the spec-json report schema. Has a lifecycle workflow with human gates.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| scan_id | integer FK | References `scans.id`. Cascade delete. |
| finding_id | text | ID within the report, e.g. `F1`, `F2`. |
| sinks | text | Comma-joined sink IDs from the inventory, e.g. `S9, S25, S26`. Links to the threat model tab. |
| title | text | Short descriptive title. |
| severity | text | `Critical`, `High`, `Medium`, `Low`. |
| status | text | Lifecycle state: `new`, `enriched`, `triaged`, `ready`, `reported`, `acknowledged`, `fixed`, `published`, `rejected`, `duplicate`. Default `new`. |
| cwe | text | CWE identifier, e.g. `CWE-352`. Linked to embedded MITRE catalogue for tooltips. |
| location | text | `file:line` or `file:start-end`, relative to repo root. Linked to forge source view. |
| affected | text | Version range, e.g. `>=0.2.0, <=4.0.5`. |
| notes | text | Free-text field for human triage notes, communication log. |
| trace | text | Step 1: backwards trace from sink to library boundary. Markdown. |
| boundary | text | Step 2: which trust boundary the input crosses. Markdown. |
| validation | text | Step 3: reproduction script and output. Markdown. |
| prior_art | text | Step 4: issue/PR/commit search for this finding. Markdown. |
| reach | text | Step 5: dependent exposure analysis. Markdown. |
| rating | text | Step 6: severity justification and confidence. Markdown. |
| confidence | text | Legacy field from old schema. |
| summary | text | One-paragraph summary. Derived from trace for spec-json reports. |
| details | text | Legacy field from old schema. |
| created_at | datetime | |

## dependencies

Package dependencies discovered by the `git-pkgs` job. Replaced wholesale each time the job runs for a repository.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| repository_id | integer FK | |
| name | text | Package name. |
| ecosystem | text | e.g. `gem`, `npm`, `go`. Indexed. |
| p_url | text | Package URL (PURL). Used to match against the packages table for import buttons. |
| requirement | text | Version constraint from the manifest. |
| dependency_type | text | `runtime` or `development`. |
| manifest_path | text | Which file declared this dependency. |
| manifest_kind | text | `manifest` or `lockfile`. |
| created_at | datetime | |

Note: the UI groups dependencies by name+ecosystem and shows all manifest paths. Lockfile versions are preferred over manifest ranges.

## packages

Registry entries from packages.ecosyste.ms. One row per published package linked to this repository. Replaced each time the packages job runs.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| repository_id | integer FK | |
| name | text | Package name on the registry. |
| ecosystem | text | e.g. `rubygems`, `npm`. |
| p_url | text | Package URL. |
| licenses | text | License string from the registry. |
| latest_version | text | Latest release number. |
| versions_count | integer | Total published versions. |
| downloads | integer | Download count (period varies by registry). |
| dependent_packages | integer | How many other packages depend on this one. |
| dependent_repos | integer | How many repositories use this package. |
| registry_url | text | HTML page on the registry. |
| latest_release_at | datetime | |
| dependent_packages_url | text | ecosyste.ms API URL for fetching dependents. Used by the dependents job. |
| metadata | text | Full ecosyste.ms JSON response for this package. |
| created_at | datetime | |

## dependents

Top runtime dependents of this repository's packages. Fetched from packages.ecosyste.ms by the dependents job. Sorted by dependent_repos descending, capped at 25 per package.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| repository_id | integer FK | |
| name | text | Dependent package name. |
| ecosystem | text | |
| p_url | text | |
| repository_url | text | Git URL of the dependent. Used by the import button. |
| downloads | integer | |
| dependent_repos | integer | How widely the dependent itself is used. |
| registry_url | text | |
| latest_version | text | |
| created_at | datetime | |

## advisories

Known security advisories from advisories.ecosyste.ms. Replaced each time the advisories job runs.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| repository_id | integer FK | |
| uuid | text | ecosyste.ms advisory identifier. |
| url | text | Link to the advisory page. |
| title | text | |
| description | text | |
| severity | text | `CRITICAL`, `HIGH`, `MODERATE`, `LOW`. Note: uppercase, unlike finding severity. |
| cvss_score | real | 0-10. |
| classification | text | e.g. `GENERAL`. |
| packages | text | Comma-joined affected package names. One advisory can affect multiple packages. |
| published_at | datetime | |
| withdrawn_at | datetime | Non-null if the advisory was withdrawn. Shown with a badge in the UI. |
| created_at | datetime | |

## maintainers

People who maintain repositories. Populated by the model-backed maintainers job (which fetches from commits, issues, and packages ecosyste.ms endpoints and hands the data to claude for analysis). Many-to-many with repositories via `repository_maintainers`.

| Column | Type | Notes |
|--------|------|-------|
| id | integer PK | |
| login | text, unique | GitHub username or equivalent. |
| name | text | |
| email | text | Validated: must contain `@`, no noreply addresses. |
| company | text | |
| avatar_url | text | |
| status | text | `active`, `inactive`, `unknown`. Set by the maintainer analysis job. |
| notes | text | Role and evidence from the analysis, e.g. `lead: 292 commits, publishes to rubygems`. |
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
| priority | integer | Higher = delivered first. 10 for HTTP lookups, 8 for fast tools, 5 for slow tools, 0 for claude. |
