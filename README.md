# scrutineer

A local tool for scanning open source repositories for security vulnerabilities and managing the disclosure process. You add a repo by URL, scrutineer runs a pipeline of [claude-code skills](https://agentskills.io) against it, and presents the results in a web UI where you can triage findings, identify maintainers, and track disclosures.

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
- **Dark mode** -- follows system preference
- **Containerised runner** -- optional per-scan Docker isolation with read-only source mounts, dropped capabilities
- **Skill HTTP API** -- running skills can call back into scrutineer to list prior scans and enqueue further skills; surface documented in `openapi.yaml`
- **Search** -- LIKE-based search box on repositories, findings, packages, and maintainers indexes, combining with the existing filters and sort
- **Markdown report export** -- download a single consolidated `report.md` per repository covering threat model, findings (with six-step prose), packages, advisories, dependents, maintainers

## Getting started

You need Go 1.26+ and an Anthropic API key. Analysis tools (semgrep, zizmor, git-pkgs, brief) are optional -- skills that need a missing tool report the failure in their scan output while the rest complete.

    export ANTHROPIC_API_KEY=sk-...
    go run ./cmd/scrutineer -skills ./skills
    open http://127.0.0.1:8080

Click "Add repository" in the sidebar, paste a git URL, and scrutineer enqueues the `triage` skill against it. Triage then enqueues the rest of the default set in parallel. The fast ones (metadata, packages) finish in seconds; the deep audit takes a few minutes depending on the codebase.

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
| `semgrep` | Static analysis mapped into findings shape |
| `zizmor` | GitHub Actions workflow audit mapped into findings shape |
| `security-deep-dive` | The model-backed audit producing structured findings |

Edit `skills/triage/SKILL.md` to change what gets run by default. Drop new skill directories in `skills/` to add scan types; no code changes needed.

## Adding or editing skills

A skill is a directory with a `SKILL.md` (YAML frontmatter + markdown body), optionally plus a `schema.json`, a `scripts/` folder, and any other files the body references. The format is the [agentskills.io specification](https://agentskills.io/specification). Scrutineer-specific metadata under the frontmatter's `metadata` key:

    scrutineer.output_file: report.json
    scrutineer.output_kind: findings

The output kind picks the parser. Supported: `findings`, `maintainers`, `packages`, `advisories`, `dependents`, `dependencies`, `repo_metadata`, `freeform`. Skills without these metadata keys run and their output is captured verbatim.

Skills are loaded from `-skills ./path` (repeatable) or `-skills-repo https://github.com/org/skills` on startup. The `/skills` UI page lets you inspect them, or create/edit them in the browser.

## Skill HTTP API

While a skill runs, its workspace contains `./context.json` with `scrutineer.api_base` and a per-scan bearer `token`. The skill can call back into scrutineer to read scans and trigger more skills. See `openapi.yaml` at the repo root for the surface; the `triage` skill is the reference example.

## Navigating the UI

The sidebar has six sections:

- **Repositories** -- your scanned repos with language, last scan status, and finding counts. Search by name/url/description; filter by language; sort by newest/name/stars/language. Click into one for tabs: Summary, Findings, Threat Model, Packages, Dependencies, Dependents, Advisories, Maintainers, Data, Scans. An "Export report" button downloads a markdown summary of everything on the page.
- **Findings** -- all vulnerability findings across repos. Search by title/location/CWE/CVE/affected range. Filter by severity, sort by severity/newest/repo. Click into a finding for the six-step analysis (trace, boundary, validation, prior art, reach, rating), scoring fields (CVE, CVSS, fix version/commit, resolution), timestamped notes, communications log, references, labels, and a full change history.
- **Packages** -- registry entries across all repos. Search by name/purl/license, ecosystem filter, sort by name/downloads/dependents/ecosystem.
- **Maintainers** -- people identified as maintainers across repos, with their linked repos and findings. Search by login/name/email/company/notes, status filter, sort by name/login/status/newest.
- **Scans** -- every scan that has run, filterable by skill and status. Failed scans have a retry button.
- **Skills** -- installed skills from disk and from the UI; view, edit, or run any of them.

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

## Desktop app

`cmd/scrutineer-desktop` builds a self-contained binary that starts the server on a random localhost port and opens it in the OS-native webview, so it runs like a standalone app rather than a browser tab. Closing the window shuts the server down.

    go build ./cmd/scrutineer-desktop
    ./scrutineer-desktop

On macOS this links the system WebKit framework so there are no extra dependencies. On Linux you need the WebKitGTK development headers (`apt install libwebkit2gtk-4.1-dev` on Debian/Ubuntu, `dnf install webkit2gtk4.1-devel` on Fedora). On Windows it uses WebView2, which ships with Windows 11 and recent Windows 10.

The desktop build always uses the local runner and reads `./data` and `./skills` relative to where you launch it. For flags, the config file, or the docker runner, use `cmd/scrutineer`.

## Docker

    docker build -t scrutineer .
    docker run -p 127.0.0.1:8080:8080 -v scrutineer-data:/data -e ANTHROPIC_API_KEY=sk-... scrutineer

Always bind to `127.0.0.1`. The UI has no authentication; binding to `0.0.0.0` exposes your findings database to anyone on the network.

If docker is available on the host, scrutineer can run each scan in an ephemeral container for isolation. Build the runner image and scrutineer will detect docker at startup:

    docker build -t scrutineer-runner -f Dockerfile.runner .
    go run ./cmd/scrutineer -skills ./skills

Use `--no-docker` to disable containerised execution, or `--runner-image` to specify a different image.

Note: the containerised runner currently uses `--network none`, which blocks skills from calling scrutineer's HTTP API or fetching from ecosyste.ms. Hardening the egress policy so those skills still work under isolation is tracked in the sandbox issue.

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
| `--runner-image` | `scrutineer-runner` | Docker image for per-scan containers |
| `-concurrency` | `4` | Number of scans to run in parallel |

## Config file

Every flag above can be set in a YAML config file instead. The loader checks `./scrutineer.yaml` by default; override with `-config path/to/file`. Command-line flags always win. See [scrutineer.sample.yaml](scrutineer.sample.yaml) for the full shape.

The config file can also replace the model pick list and pin the default model:

    default_model: claude-sonnet-4-6
    models:
      - name: Sonnet
        id:   claude-sonnet-4-6
      - name: Opus
        id:   claude-opus-4-6

## Security

See [threatmodel.md](threatmodel.md) for the full threat model. The short version: scanning a repository is equivalent to running code from it. The containerised runner (when available) isolates each scan, but the default bare-metal mode runs everything as your user. Only scan repositories you'd be willing to clone and build locally.

## Further documentation

- [openapi.yaml](openapi.yaml) -- the skill-facing HTTP API
- [docs/database.md](docs/database.md) -- full database schema reference
- [docs/development.md](docs/development.md) -- project layout, adding skills, regenerating embedded data, running tests

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Alpha-Omega.
