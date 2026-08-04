---
name: packages
description: Look up every package this repository publishes across all registries via packages.ecosyste.ms, with downloads, dependent counts, latest version, and registry URL.
license: MIT
compatibility: Prefers the scrutineer API's cached ecosyste.ms payload; needs network access to packages.ecosyste.ms only when nothing is cached.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: packages
  scrutineer.requires_remote: true
---

# packages

One repository can ship multiple packages across multiple ecosystems. Ask packages.ecosyste.ms for all of them and record the headline stats.

## Workspace

- `./context.json` — has `repository.url`, plus `scrutineer.api_base`, `scrutineer.token` and `scrutineer.repository_id`
- `./report.json` — write the packages array here
- `./schema.json` — output shape

## What to do

1. Read `./context.json` and extract `repository.url`, `scrutineer.api_base`, `scrutineer.token` and `scrutineer.repository_id`.
2. Ask scrutineer for the cached payload first: `GET {api_base}/repositories/{repository_id}/ecosystems/packages/raw` with the bearer token. A 200 is the verbatim upstream lookup response — use it and go to step 4. This is the only path that works under `--hardened`, where ecosyste.ms is not in the egress allowlist, and it saves re-fetching what the prefetcher already collated.
3. On 404 nothing is cached — the steady state under `ecosystems_enrichment: false` — so fetch `https://packages.ecosyste.ms/api/v1/packages/lookup?repository_url={URL-ENCODED_URL}` directly. Either way the payload is a JSON array, one object per published package.
4. For each package upstream returns, emit one entry in `report.json` under `packages` mapping these fields:
   - `name` from upstream `name`
   - `ecosystem` from upstream `ecosystem` (e.g. `rubygems`, `npm`, `pypi`)
   - `purl` from upstream `purl`
   - `licenses` from upstream `licenses` (string, comma-joined if upstream gives a list)
   - `latest_version` from upstream `latest_release_number` or `latest_version`
   - `versions_count` from upstream `versions_count`
   - `downloads` from upstream `downloads`
   - `dependent_packages` from upstream `dependent_packages_count`
   - `dependent_repos` from upstream `dependent_repos_count`
   - `registry_url` from upstream `registry_url` or the registry's canonical package page
   - `latest_release_at` from upstream `latest_release_published_at` (RFC3339)
   - `dependent_packages_url` from upstream `dependent_packages_url`
   - `metadata` — the whole upstream object for this package, verbatim

If upstream answered and this repository genuinely publishes no packages (the lookup returns `[]`), write `{"packages": []}`. That is a valid result, not an error.

Only write that empty array when a source actually answered. If neither source is reachable — the cached endpoint returned 404 *and* the direct fetch failed, which is what `--hardened` looks like on an uncached repository — do not write `./report.json` at all. Exit non-zero instead. The parser replaces the whole package set for the repository, deleting every existing row before inserting what you produced, so an empty array reported as success wipes packages a previous scan recorded rather than leaving them untouched.
