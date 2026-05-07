# scrutineer

A local tool for scanning open source repositories for security vulnerabilities and managing the disclosure process. You add a repo by URL, scrutineer runs a pipeline of [claude-code skills](https://agentskills.io) against it, and presents the results in a web UI where you can triage findings, identify maintainers, and track disclosures.

## Quick start

You need [Go 1.26+](https://go.dev/dl/) and [Docker](https://docs.docker.com/get-docker/) running.

    git clone https://github.com/alpha-omega-security/scrutineer
    cd scrutineer

Authenticate Claude with one of two options:

**Option A: Claude Code subscription** (Max, Pro, Team, or Enterprise) -- generate a long-lived OAuth token with the [Claude CLI](https://docs.anthropic.com/en/docs/claude-code):

    claude setup-token
    export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...

**Option B: Anthropic API key** from [console.anthropic.com](https://console.anthropic.com):

    export ANTHROPIC_API_KEY=sk-ant-api03-...

Then start scrutineer:

    export ANTHROPIC_BASE_URL=https://...  # optional: custom API endpoint
    go run ./cmd/scrutineer -skills ./skills

Then open http://127.0.0.1:8080.

Scrutineer detects Docker and starts using it automatically: each scan runs in an ephemeral container with a read-only source mount and an egress allowlist proxy. The runner image (`ghcr.io/alpha-omega-security/scrutineer-runner`) is pulled on first use, so the first scan is slower while it downloads. If Docker isn't available scans run directly on the host with no isolation; see the Security section before doing that.

Click **Add repository** in the sidebar, paste a git HTTPS URL, and scrutineer enqueues the `triage` skill. A `/tree/<branch>` suffix on the URL scans that branch instead of the default. Triage then enqueues the rest of the pipeline in parallel. Metadata and package lookups finish in seconds; the security deep-dive takes a few minutes depending on repo size. Open the repo page and switch to the Scans tab to watch progress, or wait for the Findings tab to fill in.

The optional analysis tools (semgrep, zizmor, git-pkgs, brief) are bundled in the runner image, so you don't need them installed locally when Docker is in use.

## Git authentication

Scrutineer shells out to `git clone` with no explicit token passing, so it uses whatever credentials are already configured on the host: SSH keys, credential helpers, `gh auth login`, a `.netrc` file, or the macOS keychain.

To scan private repos, make sure `git clone https://github.com/org/repo` works in your terminal before adding the URL to scrutineer. If it does, scrutineer can clone it too.

Common setups:

    # GitHub CLI (easiest)
    gh auth login

    # Git credential helper
    git config --global credential.helper store   # or osxkeychain / manager-core

    # SSH-based clone URLs are not supported -- scrutineer only accepts https:// URLs.
    # Use a credential helper to authenticate HTTPS clones instead.

When running inside Docker (`docker run ...`), the container has no access to host credentials. Mount a credential store or set `GIT_ASKPASS` to provide access to private repos from inside the container.

When the containerised runner is active (the default when Docker is available), each scan runs in a separate container but the clone happens on the host before the source is mounted in. Host credentials are used for the clone; the container never sees them.

## Features

- **Skill-based scan pipeline** -- every scan is a claude-code skill on disk (SKILL.md + schema + optional scripts). The default pipeline for a new repo is itself a skill (`triage`) that enqueues the others; edit its SKILL.md to change what runs
- **Structured findings** -- vulnerability reports parsed into a database with severity, CWE, location (linked to source), affected versions, and a six-step analysis trace
- **Finding workflow** -- guided triage flow from new through verification, disclosure, and publication with human gates at each step
- **Threat model view** -- trust boundaries, sink inventory, ruled-out entries, and the full audit reasoning rendered from the scan report
- **Dependency exploration** -- dependency and dependent tables with one-click import to scan any package's source repository
- **Package registry data** -- downloads, dependents, versions, and registry links for every published package
- **Known advisories** -- existing CVEs and security advisories pulled automatically
- **Maintainer identification** -- model-backed skill combining commit history, issue/PR activity, and registry ownership to identify who to contact for disclosure
- **CWE catalogue** -- embedded MITRE CWE data with tooltips on finding tables and full descriptions on finding pages
- **Live updates** -- SSE streaming of scan logs and status changes, no polling
- **Themes** -- six colour themes plus a light/dark/system toggle, set on the Settings page
- **Containerised runner** -- optional per-scan Docker isolation with read-only source mounts, dropped capabilities, and an authenticated egress allowlist proxy
- **Skill HTTP API** -- running skills can call back into scrutineer to list prior scans and enqueue further skills; surface documented in `openapi.yaml`
- **Organisation rollup** -- repos, findings, and maintainers grouped by owning org, with per-org markdown exports
- **Usage tracking** -- per-scan token and cost figures plus a `/usage` page totalling spend per skill
- **SBOM import** -- upload a CycloneDX or SPDX document, resolve each component to a source repository, and queue scans automatically
- **CNA matching** -- identify the CVE Numbering Authority whose scope covers a repo so disclosures go to the right contact
- **Reachability analysis** -- trace sinks found in dependencies through application code to see which are actually reachable
- **Rescan dedup** -- findings carry a content fingerprint so re-running a scan updates existing rows instead of creating duplicates; findings that stop appearing are marked "not seen" with a miss count
- **CSAF export** -- download any finding as a schema-validated CSAF 2.0 advisory document
- **JSONL export** -- stream all findings or scans as line-delimited JSON for ingestion elsewhere
- **Markdown report export** -- download a single consolidated `report.md` per repository or organisation

## The default pipeline

When a repo is added, the `triage` skill is enqueued. Its SKILL.md lists the skills to trigger. The bundled skills live in `skills/`:

| Skill | What it does |
|-------|--------------|
| `triage` | Orchestrates the default scan set via the scrutineer API |
| `metadata` | Fetches repo metadata from repos.ecosyste.ms |
| `packages` | Looks up published packages from packages.ecosyste.ms |
| `advisories` | Fetches known security advisories |
| `dependents` | Top runtime dependents per package |
| `dependencies` | Runs `git-pkgs list` to index every manifest |
| `sbom` | Runs `git-pkgs sbom` for a CycloneDX SBOM |
| `maintainers` | Model-backed analysis identifying real maintainers and contact routes |
| `repo-overview` | Runs `brief --json` for a structured project summary |
| `subprojects` | Enumerates monorepo packages/workspaces so deep-dives can be scoped to a sub-path |
| `semgrep` | Static analysis mapped into findings shape |
| `zizmor` | GitHub Actions workflow audit mapped into findings shape |
| `security-deep-dive` | The model-backed audit producing structured findings |
| `verify` | Re-checks one finding against current HEAD; records reproduces / fixed / can't-reproduce |
| `disclose` | Drafts a GHSA-shaped advisory (title, description, CVSS, CWEs, references) for one finding |
| `patch` | Proposes a unified diff fixing one finding, written back as a note for analyst review |
| `reachability` | Traces dependency sinks through application code to determine which are reachable from trust boundaries |
| `cna-match` | Matches a repository to its CVE Numbering Authority so disclosures route to the right contact |
| `posture` | Records the repo's security posture (reporting policy, response history, hardening) on the Repository row |

Edit `skills/triage/SKILL.md` to change what gets run by default. Drop new skill directories in `skills/` to add scan types; no code changes needed.

## Adding or editing skills

A skill is a directory with a `SKILL.md` (YAML frontmatter + markdown body), optionally plus a `schema.json`, a `scripts/` folder, and any other files the body references. The format is the [agentskills.io specification](https://agentskills.io/specification). Scrutineer-specific metadata under the frontmatter's `metadata` key:

    scrutineer.output_file: report.json
    scrutineer.output_kind: findings
    scrutineer.max_turns:   30

The output kind picks the parser. Supported: `findings`, `maintainers`, `packages`, `advisories`, `dependents`, `dependencies`, `repo_metadata`, `freeform`. Skills without these metadata keys run and their output is captured verbatim.

Skills are loaded from `-skills ./path` (repeatable) or `-skills-repo https://github.com/org/skills` on startup. The `/skills` UI page lets you inspect them, or create/edit them in the browser.

## Skill HTTP API

While a skill runs, its workspace contains `./context.json` with `scrutineer.api_base` and a per-scan bearer `token`. The skill can call back into scrutineer to read scans and trigger more skills. See `openapi.yaml` at the repo root for the surface; the `triage` skill is the reference example.

## Navigating the UI

Every index page has a search box plus filter and sort dropdowns; the specifics vary by page. The sidebar sections:

- **Repositories** -- your scanned repos with language, last-scan status, and finding counts. Click into one for tabs covering Summary, Findings, Threat Model, Packages, Dependencies, Dependents, Advisories, Maintainers, Data, and Scans, plus an "Export report" button for a markdown rollup.
- **Organizations** -- repos, findings, and maintainers grouped by owning org, with per-org markdown exports.
- **Findings** -- every vulnerability across all repos. A finding page shows the six-step analysis (trace, boundary, validation, prior art, reach, rating), scoring fields, notes, communications log, references, labels, and a change history.
- **Packages** -- registry entries discovered across all repos.
- **Advisories** -- known CVEs and security advisories pulled for any scanned package.
- **Maintainers** -- people identified as maintainers, with their linked repos and findings.
- **SBOMs** -- uploaded CycloneDX/SPDX documents. Each component is resolved to a source repository and can be imported for scanning.
- **Scans** -- every scan that has run. Running or queued scans can be cancelled; failed ones retried.
- **Skills** -- installed skills from disk and from the UI; view, edit, or run any of them.
- **Usage** -- token and cost totals across all scans, broken down by skill.
- **Settings** -- theme, colour scheme, default model, and system stats (record counts, DB size, concurrency, paths).

## Finding workflow

Each finding from the `security-deep-dive` skill starts at **new** and moves through a guided workflow:

1. **new** -- just identified. Click "Verify" to trigger independent confirmation, or "Skip to triage" if you trust the audit, or "Reject"
2. **enriched** -- verification ran. Review and click "Triage"
3. **triaged** -- confirmed real. Click "Prepare disclosure"
4. **ready** -- draft prepared. Click "Mark as reported"
5. **reported** -- sent to maintainer. Click "Acknowledged" when they respond
6. **acknowledged** -- maintainer working on fix. Click "Mark fixed" when it ships
7. **fixed** -- patch available. Click "Publish" to issue the advisory
8. **published** -- done

Each finding page has a notes section for recording triage reasoning and communication history.

## Exploring dependencies

The Dependencies tab on a repo groups packages by name and shows all manifest files where each appears. The import button (arrow icon) next to a dependency resolves it to a repository URL via packages.ecosyste.ms and queues the full pipeline for it. Dependencies you've already imported show a link icon instead.

The same applies to the Dependents tab -- you can import any dependent's repository with one click.

## Docker

    docker build -t scrutineer .
    docker run -p 127.0.0.1:8080:8080 -v scrutineer-data:/data \
      -e ANTHROPIC_API_KEY=sk-ant-api03-... \
      -e ANTHROPIC_BASE_URL=https://... \
      scrutineer

Or with a Claude Code OAuth token instead of an API key:

    docker run -p 127.0.0.1:8080:8080 -v scrutineer-data:/data \
      -e CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-... \
      scrutineer

Always bind to `127.0.0.1`. The UI has no authentication; binding to `0.0.0.0` exposes your findings database to anyone on the network.

If docker is available on the host, scrutineer runs each scan in an ephemeral container for isolation. The runner image is published to GHCR and pulled automatically on first use:

    go run ./cmd/scrutineer -skills ./skills

Use `--no-docker` to disable containerised execution, or `--runner-image` to specify a different image. To build the runner locally instead of pulling from GHCR:

    docker build -t scrutineer-runner -f Dockerfile.runner .
    go run ./cmd/scrutineer -skills ./skills --runner-image scrutineer-runner

When the docker runner is active, scrutineer starts an authenticated egress proxy on the host and points `HTTPS_PROXY`/`HTTP_PROXY` inside the container at it. The proxy only tunnels to an allowlist of hosts: the Anthropic API, `*.ecosyste.ms`, the major forges (GitHub, GitLab, Codeberg, Bitbucket), common package registries (npm, PyPI, RubyGems, crates.io, Go module proxy, Packagist, Hex, NuGet), advisory sources (semgrep.dev, OSV, NVD, cwe.mitre.org), and `host.docker.internal` for the local skill API. Requests to anything else get a 403 and are logged. Extend the list with `egress_allow` in the config file. When `-anthropic-base-url` is set (or falls back to the `ANTHROPIC_BASE_URL` env var), its hostname is automatically added to the allowlist. The proxy uses a per-process random token so it isn't an open relay; tools that ignore the proxy env are not blocked at the network layer (see `threatmodel.md`).

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | `./scrutineer.yaml` if present | Path to YAML config file |
| `-addr` | `127.0.0.1:8080` | Listen address |
| `-data` | `./data` | Data directory for the database and workspaces |
| `-effort` | `high` | Claude effort level |
| `-skills` | - | Local directory to load SKILL.md files from (repeatable) |
| `-skills-repo` | - | Git HTTPS URL to clone skills from on startup |
| `--no-docker` | false | Disable containerised runner |
| `--runner-image` | `ghcr.io/alpha-omega-security/scrutineer-runner:latest` | Docker image for per-scan containers |
| `-concurrency` | `4` | Number of scans to run in parallel |
| `-clone` | `shallow` | Clone depth: `shallow` (`--depth 1`) or `full` |
| `-scan-timeout` | `1h` | Wall-clock limit per scan; exceeded scans fail |
| `-max-turns` | `0` | Passed as `--max-turns` to claude-code (0 = unlimited) |
| `-schema-strict` | `false` | Fail a scan when its `report.json` does not validate against the skill's `schema.json` (default: warn in the scan log and parse anyway) |
| `-anthropic-base-url` | - | Custom Anthropic API base URL (env: `ANTHROPIC_BASE_URL`) |

## Config file

Every flag above can be set in a YAML config file instead. The loader checks `./scrutineer.yaml` by default; override with `-config path/to/file`. Command-line flags always win. See [scrutineer.sample.yaml](scrutineer.sample.yaml) for the full shape.

The config file can also replace the model pick list and pin the default model:

    default_model: claude-sonnet-4-6
    models:
      - name: Sonnet
        id:   claude-sonnet-4-6
      - name: Opus
        id:   claude-opus-4-7

## Security

See [SECURITY.md](SECURITY.md) for the reporting policy and [threatmodel.md](threatmodel.md) for the full threat model. The short version: scanning a repository is equivalent to running code from it. The containerised runner (when available) isolates each scan, but the default bare-metal mode runs everything as your user. Only scan repositories you'd be willing to clone and build locally.

## Further documentation

- [openapi.yaml](openapi.yaml) -- the skill-facing HTTP API
- [docs/database.md](docs/database.md) -- full database schema reference
- [docs/development.md](docs/development.md) -- project layout, adding skills, regenerating embedded data, running tests

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Alpha-Omega.
