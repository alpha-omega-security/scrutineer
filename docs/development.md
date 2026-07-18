# Development

## Project layout

| Path | Description |
| --- | --- |
| `cmd/scrutineer/` | main entry point, flag + config wiring |
| `internal/config/` | YAML config loader (see `scrutineer.sample.yaml`) |
| `internal/db/` | GORM models + helpers |
| `internal/db/db.go` | Repository, Scan, Skill, Finding + sibling tables (FindingLabel, FindingNote, FindingCommunication, FindingReference, FindingHistory), Dependency, Package, Dependent, Advisory, Maintainer, Subproject, SBOMUpload, SBOMPackage, CNA |
| `internal/db/finding_helpers.go` | WriteFindingField, AddFindingNote, AddFindingCommunication, AddFindingReference, SetFindingLabels, SeedDefaultLabels |
| `internal/queue/` | goqite wrapper, embedded sqlite schema |
| `internal/ingest/` | format-neutral parsers for external finding reports (SARIF, CSV, markdown, minimal JSON) used by `POST /api/v1/import` |
| `internal/skills/` | SKILL.md parser + loader for local dirs and remote git repos |
| `internal/worker/` | one job kind (JobSkill) and the runner plumbing |
| `internal/worker/claude.go` | LocalClaude runner (bare-metal) |
| `internal/worker/runtime.go` | ContainerRuntime + DetectRuntime (docker / rootless podman selection) |
| `internal/worker/container.go` | ContainerRunner (ephemeral container per scan; docker or podman) |
| `internal/worker/clone.go` | git clone/fetch helpers, URL validation |
| `internal/worker/skill.go` | doSkill: stage skill + context, invoke claude, dispatch output to the right parser |
| `internal/worker/skill_parsers.go` | one parser per output_kind: findings, maintainers, packages, advisories, dependencies, finding_dedup, repo_metadata, verify, revalidate, breaking_change, mitigation, release_watch, subprojects, repo_overview, posture, patch (plus `exposure` handled by `exposure.go`, and `threat_model` stored as-is for the threat-model tab) |
| `internal/worker/stream.go` | claude stream-json line parser |
| `internal/worker/findings.go` | structured report parser used by `output_kind=findings` |
| `internal/worker/ecosystems.go` | ecosyste.ms cache refresh and dependent-package persistence |
| `internal/web/` | HTTP handlers, templates, static assets, SSE broker |
| `internal/web/server.go` | Server struct, routing, middleware, template funcs, shared helpers; repo + finding + package + advisory handlers |
| `internal/web/orgs.go` | organisation index and show handlers |
| `internal/web/maintainers.go` | maintainer index, show, and do-not-contact toggle |
| `internal/web/scans.go` | scan index (jobs), show, retry, retry-failed, cancel, and log poll |
| `internal/web/api.go` | skill-facing `/api` router + bearer-auth middleware |
| `internal/web/api_reads.go` | typed read endpoints (maintainers, packages, advisories, dependents, dependencies, findings) |
| `internal/web/api_finding_writes.go` | PATCH/POST/PUT for finding notes, communications, references, labels, field updates, history |
| `internal/web/finding_forms.go` | browser-form analogues of the api finding writes |
| `internal/web/finding_patch.go` | patch scan lookup and diff download |
| `internal/web/skills_handlers.go` | `/skills` UI routes |
| `internal/web/repo_report.go` | markdown report export per repository |
| `internal/web/org_report.go` | markdown report export per organisation |
| `internal/web/org_summary.go` | organisation summary page |
| `internal/web/sboms.go` | SBOM upload, list, and component resolution |
| `internal/web/usage.go` | per-skill token and cost totals |
| `internal/web/theme.go` | colour scheme cookie + dark mode toggle |
| `internal/web/parse_repo_url.go` | git URL to forge web URL conversion |
| `internal/web/api_export.go` | bulk JSON export endpoints |
| `internal/web/sse.go` | SSE broker, splits data lines per spec |
| `internal/web/cwe.go` + `cwe.json` | embedded MITRE CWE catalogue (944 entries) |
| `internal/web/models.go` | model pick list, swappable from config |
| `internal/web/location.go` | forge URL builder for source links |
| `internal/web/jsontree.go` | JSON-to-HTML renderer for the Data tab |
| `internal/web/templates/` | html/template files |
| `internal/web/static/` | theme CSS, app.js, favicon, vendored CDN assets |

## Running tests

    go test ./...

## Releasing

The `Release` workflow checks daily at 17:17 UTC and publishes from the latest `main` commit once the most recent release is at least 14 calendar days old. It can also be dispatched manually from `main` for an out-of-cycle release or recovery run. Versions use CalVer (`YYYY.MM.DD.N`): the date comes from the workflow run's creation time, `N` increments when another tag already exists for that date, and retries against the same commit reuse any unpublished version.

Before a release, the `runner-image` workflow for the target commit must have published its multi-platform `sha-<full-commit>` tag. Preflight refuses a version tag that points at a different commit, runs the full Go test suite, and resolves that commit-matched runner manifest to an immutable digest. That digest is injected as the released binary's default runner image, keeping the host and the sidecar-capable runner image on the same source revision. Each platform job builds with `CGO_ENABLED=0`, validates the binary, packages it with the license and README, and generates a GitHub build-provenance attestation. The final job creates `SHA256SUMS`, removes any incomplete same-version drafts, creates a fresh draft tied to the current commit, uploads its complete asset set, and only then publishes it. If the runner image is missing, re-run its workflow before retrying the release. If draft creation, an asset upload, or publication fails, re-run the failed job; the incomplete release remains hidden and the workflow replaces it safely. Re-running an already successful workflow run is a no-op after verification.

The release matrix produces Linux and macOS archives for `amd64` and `arm64`. macOS artifacts are intentionally unsigned and unnotarized until the project adopts an organisation-controlled Apple signing identity and release policy.

## Lint + vuln + deadcode

The full quality sweep:

    golangci-lint run --enable gocritic,gocognit,gocyclo,maintidx,dupl,mnd,unparam,ireturn,goconst,errcheck ./...
    govulncheck ./...
    deadcode ./...

## Adding a new scan type

Scans are claude-code skills on disk; adding one is a directory drop, no Go change. The frontmatter reference, `scrutineer.*` metadata keys, output kinds, workspace layout, `context.json` shape, and schema validation are documented in [skills.md](skills.md).

### When you do need Go changes

- **New output kind**: add the kind to `OutputKinds` in `internal/skills/parse.go`, add a `parseXOutput` method in `internal/worker/skill_parsers.go`, and add a case to the switch in `internal/worker/skill.go`. Without the `OutputKinds` entry the bundled-skills test rejects the SKILL.md at startup.
- **New API surface** for skills to read: add a handler in `internal/web/api_reads.go` and a route in `internal/web/api.go`, then document it in `openapi.yaml`.

## Regenerating cwe.json

The CWE catalogue is distilled from MITRE's XML download so each entry can
carry both the human-readable name/description and its View-1400
("Comprehensive Categorization for Software Assurance Trends") bucket — the
22-way classification the findings UI groups by. Deprecated weaknesses are
dropped to match the existing key set.

    curl -sS -o /tmp/cwec.xml.zip https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
    unzip -p /tmp/cwec.xml.zip > /tmp/cwec.xml
    python3 - <<'PY' > internal/web/cwe.json
    import xml.etree.ElementTree as ET, json, re, sys
    data = re.sub(r' xmlns="[^"]+"', '', open('/tmp/cwec.xml').read(), count=1)
    root = ET.fromstring(data)
    cat_of = {}
    for cat in root.iter('Category'):
        name = cat.get('Name', '')
        if not name.startswith('Comprehensive Categorization:'):
            continue
        label = name.split(':', 1)[1].strip()
        rels = cat.find('Relationships')
        if rels is None:
            continue
        for hm in rels.findall('Has_Member'):
            if hm.get('View_ID') == '1400':
                cat_of['CWE-' + hm.get('CWE_ID')] = label
    out = {}
    for w in root.iter('Weakness'):
        if w.get('Status') == 'Deprecated':
            continue
        cid = 'CWE-' + w.get('ID')
        desc_el = w.find('Description')
        desc = re.sub(r'\s+', ' ', (desc_el.text or '').strip()) if desc_el is not None else ''
        entry = {'name': w.get('Name', ''), 'description': desc}
        if cid in cat_of:
            entry['category'] = cat_of[cid]
        out[cid] = entry
    sys.stdout.write(json.dumps(out, separators=(',', ':'), sort_keys=True))
    PY

## Frontend assets

Tailwind, basecoat, htmx, lucide and highlight.js are vendored under `internal/web/static/vendor/` and embedded into the binary so the UI works offline. To bump a version, edit the pinned URL in `scripts/vendor-assets.sh`, re-run it, update the matching filename in `internal/web/templates/layout.html`, and commit the changed files.

    ./scripts/vendor-assets.sh

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
