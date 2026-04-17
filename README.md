# scrutineer

A local web frontend for queueing security and supply-chain scans against git repositories. You add a repo by URL, a pipeline of jobs runs against it (metadata lookup, dependency indexing, semgrep, zizmor, claude audit), and the results land in a sqlite database you can browse. Built as scaffolding around the prompt work in mythos.

Run it:

    go run ./cmd/scrutineer
    open http://127.0.0.1:8080

Flags:

- `-addr` listen address (default `127.0.0.1:8080`)
- `-data` data directory for the db and workspaces (default `./data`)
- `-effort` claude effort level (default `high`)
- `-spec path/to/spec.md` override the built-in audit prompt

Adding a repository enqueues nine jobs in priority order:

| Prio | Job | What it does |
|------|-----|--------------|
| 10 | metadata | Fetches repo info from `repos.ecosyste.ms`, stores on the repository row |
| 10 | packages | Fetches package registry entries from `packages.ecosyste.ms`, stores in `packages` table |
| 8 | brief | Runs `brief --json` on the clone for a structured project summary |
| 8 | git-pkgs | Runs `git-pkgs init && list` to index dependencies into the `dependencies` table |
| 8 | sbom | Runs `git-pkgs sbom` to generate a CycloneDX SBOM |
| 8 | dependents | Fetches top runtime dependents from `packages.ecosyste.ms` into the `dependents` table |
| 5 | semgrep | Runs `semgrep scan --sarif` with `p/security-audit` and `p/secrets` rulesets |
| 5 | zizmor | Audits GitHub Actions workflows for security issues (SARIF output) |
| 0 | claude | Clones the repo, runs `claude -p` with the audit spec, parses structured findings into the `findings` table |

Docker:

    docker build -t scrutineer .
    docker run -p 127.0.0.1:8080:8080 -v scrutineer-data:/data -e ANTHROPIC_API_KEY=sk-... scrutineer

Always bind to `127.0.0.1` when publishing the port. The UI has no authentication; binding to `0.0.0.0` exposes your findings database and scan controls to anyone who can reach the host.

The queue is goqite on the same sqlite file. One worker, jobs run serially, higher priority first. Postgres works with a driver swap in `internal/db` and `internal/queue`.

The web layer is `net/http` + `html/template`, htmx + SSE for live updates, basecoat + tailwind browser CDN for styling, lucide for icons. No npm.

The claude scan produces JSON conforming to `internal/worker/schema.json`. Findings are parsed into rows with severity, CWE, location (linked to the forge), confidence, summary and details. CWE tooltips and detail pages pull from an embedded MITRE catalogue.

Dependencies and dependents tables are clickable: hitting the `+` button resolves the package to a repository URL via `packages.ecosyste.ms` and enqueues the full pipeline for it.

Layout:

    cmd/scrutineer/      main, embedded default spec
    internal/db/         GORM models: Repository, Scan, Finding, Dependency, Package, Dependent
    internal/queue/      goqite wrapper and embedded schema
    internal/worker/     job handlers, stream-json parser, findings schema
    internal/web/        handlers, templates, static, SSE broker, CWE index, model list

`internal/web/cwe.json` is distilled from MITRE's catalogue (944 entries, 232KB). Regenerate:

    curl -sS https://cwe.mitre.org/data/csv/1000.csv.zip | funzip > /tmp/cwe.csv
    python3 -c 'import csv,json; print(json.dumps({"CWE-"+r["CWE-ID"]:{"name":r["Name"],"description":r["Description"].strip()} for r in csv.DictReader(open("/tmp/cwe.csv"))}, separators=(",",":"), sort_keys=True))' > internal/web/cwe.json

Adding a job kind: write `func (w *Worker) doX(ctx, *db.Scan, emit) (string, error)` in `internal/worker`, register it in `Worker.Register`, add it to `kinds.go`, and call `s.enqueue(ctx, repoID, "x", "", prio)`. The `wrap()` function handles status transitions, log capture, error recording and SSE notifications.
