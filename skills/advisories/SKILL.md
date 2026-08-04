---
name: advisories
description: Fetch published GHSA and CVE advisories affecting any package this repository produces, via advisories.ecosyste.ms.
license: MIT
compatibility: Prefers the scrutineer API's cached ecosyste.ms payload; needs network access to advisories.ecosyste.ms only when nothing is cached.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: advisories
  scrutineer.requires_remote: true
---

# advisories

## Workspace

- `./context.json` — has `repository.url`, plus `scrutineer.api_base`, `scrutineer.token` and `scrutineer.repository_id`
- `./report.json` — write the advisories array here
- `./schema.json` — output shape

## What to do

1. Read `./context.json` and extract `repository.url`, `scrutineer.api_base`, `scrutineer.token` and `scrutineer.repository_id`.
2. Ask scrutineer for the cached payload first: `GET {api_base}/repositories/{repository_id}/ecosystems/advisories/raw` with the bearer token. A 200 is the verbatim upstream response, already collated by the prefetcher — use it, skip the pagination in step 3, and go to step 4. This is the only path that works under `--hardened`, where ecosyste.ms is not in the egress allowlist.
3. On 404 nothing is cached — the steady state under `ecosystems_enrichment: false` — so fetch `https://advisories.ecosyste.ms/api/v1/advisories?repository_url={URL-ENCODED_URL}` directly. Follow pagination (`Link: <...>; rel="next"`) if present.
4. For each advisory returned, emit one entry in `report.json` under `advisories`:
   - `uuid` from upstream `uuid`
   - `url` from upstream `url` (or the first reference if `url` is empty)
   - `title` from upstream `title`
   - `description` from upstream `description`
   - `severity` from upstream `severity` (upper-case, e.g. `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
   - `cvss_score` from upstream `cvss_score` (number; omit if absent)
   - `classification` from upstream `classification` (e.g. CWE id)
   - `packages` — comma-joined list of affected package names upstream lists under `packages` or `package_names`
   - `published_at` and `withdrawn_at` as RFC3339 strings if upstream has them

Return `{"advisories": []}` if a source answered and upstream has nothing — valid result.

Only write that empty array when a source actually answered. If neither source is reachable — the cached endpoint returned 404 *and* the direct fetch failed, which is what `--hardened` looks like on an uncached repository — do not write `./report.json` at all. Exit non-zero instead. The parser replaces the whole advisory set for the repository, deleting every existing row before inserting what you produced, so an empty array reported as success wipes advisories a previous scan recorded rather than leaving them untouched.
