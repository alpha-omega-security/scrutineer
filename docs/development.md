# Development

## Project layout

    cmd/scrutineer/          main entry point, flag + config wiring
    internal/config/         YAML config loader (see scrutineer.sample.yaml)
    internal/db/             GORM models + helpers:
      db.go                  Repository, Scan, Skill, Finding + sibling tables
                             (FindingLabel, FindingNote, FindingCommunication,
                              FindingReference, FindingHistory), Dependency,
                              Package, Dependent, Advisory, Maintainer
      finding_helpers.go     WriteFindingField, AddFindingNote,
                             AddFindingCommunication, AddFindingReference,
                             SetFindingLabels, SeedDefaultLabels
    internal/queue/          goqite wrapper, embedded sqlite schema
    internal/skills/         SKILL.md parser + loader for local dirs and
                             remote git repos
    internal/worker/         one job kind (JobSkill) and the runner plumbing:
      claude.go              LocalClaude runner (bare-metal)
      docker.go              DockerRunner (ephemeral container per scan)
      clone.go               git clone/fetch helpers, URL validation
      skill.go               doSkill: stage skill + context, invoke claude,
                             dispatch output to the right parser
      skill_parsers.go       one parser per output_kind: findings, maintainers,
                             packages, advisories, dependents, dependencies,
                             repo_metadata, verify
      stream.go              claude stream-json line parser
      findings.go            structured report parser used by output_kind=findings
      metadata.go            FetchPackagesByPURL helper used by the web import button
    internal/web/            HTTP handlers, templates, static assets, SSE broker
      server.go              browser routes + handlers + template funcs
      api.go                 skill-facing /api router + bearer-auth middleware
      api_reads.go           typed read endpoints (maintainers, packages,
                             advisories, dependents, dependencies, findings)
      api_finding_writes.go  PATCH/POST/PUT for finding notes, communications,
                             references, labels, field updates, history
      finding_forms.go       browser-form analogues of the api finding writes
      skills_handlers.go     /skills UI routes
      repo_report.go         markdown report export per repository
      sse.go                 SSE broker, splits data lines per spec
      cwe.go + cwe.json      embedded MITRE CWE catalogue (944 entries)
      models.go              model pick list, swappable from config
      location.go            forge URL builder for source links
      jsontree.go            JSON-to-HTML renderer for the Data tab
      templates/             html/template files
      static/                theme CSS, favicon

## Running tests

    go test ./...

## Lint + vuln + deadcode

The full quality sweep:

    golangci-lint run --enable gocritic,gocognit,gocyclo,maintidx,dupl,mnd,unparam,ireturn,goconst,errcheck ./...
    govulncheck ./...
    deadcode ./...

## Adding a new scan type

Scans are claude-code skills on disk. Adding one is a directory drop, no Go change. See [agentskills.io](https://agentskills.io/specification) for the SKILL.md format.

1. Create `skills/my-skill/SKILL.md` with YAML frontmatter (`name`, `description`, optional `license`/`compatibility`/`metadata`). Scrutineer-specific metadata keys tell the worker how to handle the output:

   ```yaml
   ---
   name: my-skill
   description: Summarises the repository's build outputs.
   metadata:
     scrutineer.output_file: report.json
     scrutineer.output_kind: freeform
   ---
   ```

2. Write the body: instructions for claude. Reference the skill-facing API when the skill needs context scrutineer already holds (prior scans, maintainers, packages, etc.). See `openapi.yaml` at the repo root.

3. Optional: `scripts/` for bundled helpers, `schema.json` for output validation.

4. Restart scrutineer; the skill loader picks it up on startup. No code change.

When a scan runs, the worker stages the skill into `work/{scanID}/.claude/skills/{name}/`, writes a `context.json` with the repo identity plus `scrutineer.api_base` and `scrutineer.token`, and invokes `claude -p "Use the {name} skill..."`. The skill's output goes to `./report.json` (or whatever `output_file` names) and scrutineer's parser for the declared `output_kind` handles it.

### When you do need Go changes

- **New output kind** (row shape not already one of `findings`, `maintainers`, `packages`, `advisories`, `dependents`, `dependencies`, `repo_metadata`, `freeform`, `verify`): add a `parseXOutput` method in `internal/worker/skill_parsers.go` and a case in the switch in `internal/worker/skill.go`.
- **New API surface** for skills to read: add a handler in `internal/web/api_reads.go` and a route in `internal/web/api.go`, then document it in `openapi.yaml`.

## Regenerating cwe.json

The CWE catalogue is distilled from MITRE's CSV download:

    curl -sS https://cwe.mitre.org/data/csv/1000.csv.zip | funzip > /tmp/cwe.csv
    python3 -c 'import csv,json; print(json.dumps({"CWE-"+r["CWE-ID"]:{"name":r["Name"],"description":r["Description"].strip()} for r in csv.DictReader(open("/tmp/cwe.csv"))}, separators=(",",":"), sort_keys=True))' > internal/web/cwe.json

## SSE architecture

The `Broker` in `sse.go` fans events from the worker to connected browsers. Clients subscribe via `GET /events?scan={id}&repo={id}` (both optional). The worker publishes two event types:

- `scan-log`: each line from a running job, pushed immediately
- `scan-status`: fires when a job finishes (done/failed)

Templates use `hx-ext="sse"` with `sse-connect` and `sse-swap` to append log lines and trigger page reloads on completion. Embedded newlines in log lines are emitted as multiple `data:` lines so the browser's EventSource parser reconstructs the original text.

## Skill HTTP API

`/api` is a bearer-authenticated surface that running skills call back into. Each scan gets a random token on enqueue; the worker writes it into the workspace's `context.json`. Middleware (`apiAuth`) validates the token against the active scan row and enforces that a scan only touches resources on its own repository.

See `openapi.yaml` at the repo root for the full surface. The `triage` bundled skill is the reference example.

## Finding workflow tables

Mutable fields on `Finding` (status, severity, resolution, CVE/CVSS fields, etc.) all write through `db.WriteFindingField`, which logs every change to `FindingHistory` with a source tag (`tool`, `model_suggested`, `analyst`). Skill writes come through the API with `source=model_suggested`; browser-form writes use `source=analyst`. Notes, communications, references, and labels are stored in sibling tables rather than blob columns.

## Security hardening

See [threatmodel.md](../threatmodel.md) for the full model. Key mitigations in the code:

- `securityHeaders` middleware on browser routes: host header check (localhost only) + `Sec-Fetch-Site` on POST
- `/api/*` skips browser CSRF but requires a per-scan bearer token (random 32-byte hex)
- `validateGitURL`: https-only, `--` separator, `GIT_PROTOCOL_FROM_USER=0`
- `io.LimitReader` on the one remaining upstream HTTP call (10 MB cap); skills do their own fetching
- Data directory created with mode `0700`
- `SameSite=Strict` on cookies
