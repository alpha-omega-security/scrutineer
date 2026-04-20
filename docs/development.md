# Development

## Project layout

    cmd/scrutineer/          main, embedded default spec and audit schema
    internal/db/             GORM models: Repository, Scan, Finding, Dependency, Package, Dependent, Advisory, Maintainer
    internal/queue/          goqite wrapper, embedded SQLite schema, job dispatch
    internal/worker/         job handlers, stream-json parser, findings schema, maintainer analysis
      claude.go              LocalClaude runner (bare-metal)
      docker.go              DockerRunner (ephemeral container per job)
      clone.go               git clone/fetch helpers, URL validation
      tools.go               deterministic job handlers (packages, brief, git-pkgs, semgrep, zizmor, etc)
      maintainer_analysis.go model-backed maintainer identification
      findings.go            spec-json report parser
      stream.go              claude stream-json line parser
      schema.json            spec-json output schema (references defs.schema.json)
      defs.schema.json       shared vocabulary for all model-backed job schemas
      maintainer_schema.json output schema for the maintainer analysis job
    internal/web/            HTTP handlers, templates, static assets, SSE broker
      server.go              routes, handlers, template funcs
      sse.go                 SSE broker for live updates
      cwe.go + cwe.json      embedded MITRE CWE catalogue (944 entries)
      models.go              model pick list
      kinds.go               scan type catalogue for the /scanners page
      location.go            forge URL builder for source links
      jsontree.go            JSON-to-HTML renderer for the Data tab
      templates/             html/template files
      static/                theme CSS, favicon

## Running tests

    go test ./...

## Lint

The full lint command from CLAUDE.md:

    golangci-lint run --enable gocritic,gocognit,gocyclo,maintidx,dupl,mnd,unparam,ireturn,goconst,errcheck ./...
    govulncheck ./...
    deadcode ./...

## Adding a job kind

1. Write `func (w *Worker) doX(ctx context.Context, scan *db.Scan, emit func(Event)) (string, error)` in `internal/worker/`. The return string is stored as `Scan.Report`. Use `emit` to stream log lines to the UI via SSE.

2. Add a constant `JobX = "x"` in `worker.go` and register it in `Worker.Register`:
   ```go
   q.Register(JobX, w.wrap(w.doX))
   ```

3. Add a priority constant if needed (`PrioMetadata = 10`, `PrioFastTool = 8`, `PrioTool = 5`, `PrioScan = 0`).

4. Add it to `defaultJobs()` in `server.go` if it should run automatically when a repo is added.

5. Add an entry in `kinds.go` so it appears on the `/scanners` catalogue page.

6. Add it to the priority `switch` in `scanRetry` so the retry button uses the right priority.

The `wrap()` function in `worker.go` handles the shared lifecycle: load the scan row, set status to running, capture log lines, set done/failed, publish SSE events. Your handler just does the work and returns the report string.

For model-backed jobs, the pattern is: gather context from the DB or APIs, build a prompt with an embedded JSON schema, launch `claude -p`, read `report.json`, parse and store rows. See `maintainer_analysis.go` and `doClaude` for examples.

## Regenerating cwe.json

The CWE catalogue is distilled from MITRE's CSV download:

    curl -sS https://cwe.mitre.org/data/csv/1000.csv.zip | funzip > /tmp/cwe.csv
    python3 -c 'import csv,json; print(json.dumps({"CWE-"+r["CWE-ID"]:{"name":r["Name"],"description":r["Description"].strip()} for r in csv.DictReader(open("/tmp/cwe.csv"))}, separators=(",",":"), sort_keys=True))' > internal/web/cwe.json

## SSE architecture

The `Broker` in `sse.go` fans events from the worker to connected browsers. Clients subscribe via `GET /events?scan={id}&repo={id}` (both optional). The worker publishes two event types:

- `scan-log`: each line from a running job, pushed immediately
- `scan-status`: fires when a job finishes (done/failed)

Templates use `hx-ext="sse"` with `sse-connect` and `sse-swap` to append log lines and trigger page reloads on completion.

## Security hardening

See [threatmodel.md](../threatmodel.md) for the full model. Key mitigations in the code:

- `securityHeaders` middleware: host header check (localhost only) + `Sec-Fetch-Site` on POST
- `validateGitURL`: https-only, `--` separator, `GIT_PROTOCOL_FROM_USER=0`
- `io.LimitReader` on all ecosyste.ms API responses (10 MB cap)
- `safeURL` validation on stored URLs
- Data directory created with mode `0700`
- `SameSite=Strict` on cookies
