# scrutineer

A local tool for scanning open source repositories for security vulnerabilities and managing the disclosure process. You add a repo by URL, scrutineer runs a pipeline of scans against it (metadata, dependencies, semgrep, zizmor, claude-powered audit), and presents the results in a web UI where you can triage findings, identify maintainers, and track disclosures.

## Features

- **Automated scan pipeline** -- twelve jobs run against each repo: metadata lookups, dependency indexing, SBOM generation, static analysis, workflow auditing, maintainer identification, and a claude security audit
- **Structured findings** -- vulnerability reports parsed into a database with severity, CWE, location (linked to source), affected versions, and a six-step analysis trace
- **Finding workflow** -- guided triage flow from new through verification, disclosure, and publication with human gates at each step
- **Threat model view** -- trust boundaries, sink inventory, ruled-out entries, and the full audit reasoning rendered from the scan report
- **Dependency exploration** -- dependency and dependent tables with one-click import to scan any package's source repository
- **Package registry data** -- downloads, dependents, versions, and registry links for every published package
- **Known advisories** -- existing CVEs and security advisories pulled automatically
- **Maintainer identification** -- model-backed analysis combining commit history, issue/PR activity, and registry ownership to identify who to contact for disclosure
- **CWE catalogue** -- embedded MITRE CWE data with tooltips on finding tables and full descriptions on finding pages
- **Live updates** -- SSE streaming of job logs and status changes, no polling
- **Dark mode** -- follows system preference
- **Containerised runner** -- optional per-job Docker isolation with read-only source mounts, no network, dropped capabilities

## Getting started

You need Go 1.26+ and an Anthropic API key. The analysis tools (semgrep, zizmor, git-pkgs, brief) are optional -- jobs that need a missing tool will fail gracefully while the rest complete.

    export ANTHROPIC_API_KEY=sk-...
    go run ./cmd/scrutineer
    open http://127.0.0.1:8080

Click "Add repository" in the sidebar, paste a git URL, and scrutineer queues twelve jobs against it. The fast ones (metadata lookups, dependency indexing) finish in seconds. The claude audit takes a few minutes depending on the codebase.

## What runs when you add a repo

Jobs run four at a time, highest priority first:

| Job | What it does |
|-----|--------------|
| metadata | Looks up the repo on repos.ecosyste.ms for description, language, stars, license |
| packages | Fetches package registry entries from packages.ecosyste.ms |
| advisories | Fetches known security advisories from advisories.ecosyste.ms |
| commits | Fetches commit stats and committer lists from commits.ecosyste.ms |
| dependents | Fetches the top runtime dependents of each published package |
| brief | Runs `brief --json` for a structured project summary |
| git-pkgs | Indexes all dependency manifests and lockfiles |
| sbom | Generates a CycloneDX SBOM via `git-pkgs sbom` |
| semgrep | Static analysis with `p/security-audit` and `p/secrets` rulesets |
| zizmor | Audits GitHub Actions workflows for security issues |
| maintainers | Gathers data from all three ecosyste.ms endpoints and asks claude to identify the real maintainers, their roles, and the best disclosure channel |
| claude | The main security audit. Clones the repo, runs the spec-deep methodology, produces structured findings with a six-step trace per vulnerability |

## Navigating the UI

The sidebar has six sections:

- **Repositories** -- your scanned repos with language, last scan status, and finding counts. Click into one for tabs: Summary, Findings, Threat Model, Packages, Dependencies, Dependents, Advisories, Maintainers, Data, Scans
- **Findings** -- all vulnerability findings across repos. Filter by severity, sort by severity/newest/repo. Click into a finding for the six-step analysis (trace, boundary, validation, prior art, reach, rating)
- **Packages** -- registry entries across all repos with downloads, dependents, ecosystem filter
- **Maintainers** -- people identified as maintainers across repos, with their linked repos and findings
- **Scans** -- every job that has run, filterable by kind and status. Failed jobs have a retry button
- **Scans catalogue** -- documentation of each job type, including the full prompt and schema for model-backed jobs

## Finding workflow

Each finding from the claude audit starts at **new** and moves through a guided workflow:

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

The Dependencies tab on a repo groups packages by name and shows all manifest files where each appears. The import button (arrow icon) next to a dependency resolves it to a repository URL via packages.ecosyste.ms and queues the full scan pipeline for it. Dependencies you've already imported show a link icon instead.

The same applies to the Dependents tab -- you can import any dependent's repository with one click.

## Docker

    docker build -t scrutineer .
    docker run -p 127.0.0.1:8080:8080 -v scrutineer-data:/data -e ANTHROPIC_API_KEY=sk-... scrutineer

Always bind to `127.0.0.1`. The UI has no authentication; binding to `0.0.0.0` exposes your findings database to anyone on the network.

If docker is available on the host, scrutineer can run each analysis job in an ephemeral container for isolation. Build the runner image and scrutineer will detect docker at startup:

    docker build -t scrutineer-runner -f Dockerfile.runner .
    go run ./cmd/scrutineer

Use `--no-docker` to disable containerised execution, or `--runner-image` to specify a different image.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `127.0.0.1:8080` | Listen address |
| `-data` | `./data` | Data directory for the database and workspaces |
| `-effort` | `high` | Claude effort level |
| `-spec` | built-in | Path to an audit spec file to override the default |
| `--no-docker` | false | Disable containerised runner |
| `--runner-image` | `scrutineer-runner` | Docker image for per-job containers |

## Security

See [threatmodel.md](threatmodel.md) for the full threat model. The short version: scanning a repository is equivalent to running code from it. The containerised runner (when available) isolates each job, but the default bare-metal mode runs everything as your user. Only scan repositories you'd be willing to clone and build locally.

## Further documentation

- [docs/database.md](docs/database.md) -- full database schema reference
- [docs/development.md](docs/development.md) -- project layout, adding jobs, regenerating embedded data, running tests
- [context.md](context.md) -- long-term architecture direction
- [todo.md](todo.md) -- backlog
