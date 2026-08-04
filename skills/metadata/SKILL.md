---
name: metadata
description: Fetch repository metadata (description, default branch, languages, license, stars, archived, icon) from repos.ecosyste.ms and save it on the repository row.
license: MIT
compatibility: Prefers the scrutineer API's cached ecosyste.ms payload; needs network access to repos.ecosyste.ms only when nothing is cached.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: repo_metadata
  scrutineer.requires_remote: true
  scrutineer.model: mid
---

# metadata

Populate repository metadata from repos.ecosyste.ms. One API call, one flat JSON document.

## Workspace

- `./context.json` — has `repository.url` (the git URL of the target repo), plus `scrutineer.api_base`, `scrutineer.token` and `scrutineer.repository_id`
- `./report.json` — write the flat metadata here
- `./schema.json` — output shape

## What to do

1. Read `./context.json` and extract `repository.url`, `scrutineer.api_base`, `scrutineer.token` and `scrutineer.repository_id`.
2. Ask scrutineer for the cached payload first: `GET {api_base}/repositories/{repository_id}/ecosystems/repo/raw` with the bearer token. A 200 is the verbatim upstream lookup response — use it and go to step 4. This is the only path that works under `--hardened`, where ecosyste.ms is not in the egress allowlist, and it avoids a redundant external fetch otherwise.
3. On 404 nothing is cached — the steady state under `ecosystems_enrichment: false` — so fetch `https://repos.ecosyste.ms/api/v1/repositories/lookup?url={URL-ENCODED_URL}` directly. Follow redirects.
4. Keep the raw upstream response available for the `metadata` blob (the parser stores it as `Repository.Metadata`).
5. Map the fields below into `./report.json` exactly as `./schema.json` describes:
   - `full_name` from upstream `full_name`
   - `owner` from upstream `owner`
   - `description` from upstream `description`
   - `default_branch` from upstream `default_branch`
   - `languages` as a plain array of names (upstream returns an object like `{"Go": 90, "JavaScript": 10}`; take the keys)
   - `license` from upstream `license` (string, not object)
   - `stars` from upstream `stargazers_count`
   - `forks` from upstream `forks_count`
   - `archived` from upstream `archived`
   - `pushed_at` from upstream `pushed_at` (RFC3339 string)
   - `html_url` from upstream `html_url`
   - `icon_url` from upstream `icon_url` if present

Omit any field upstream did not provide rather than making one up. If the lookup genuinely returns nothing, write `{}` and exit 0 — the parser handles an empty map cleanly.

If neither source is reachable — the cached endpoint returned 404 *and* the direct fetch failed, which is what `--hardened` looks like on an uncached repository — do not write `./report.json` at all. Exit non-zero instead. An empty document here is a claim that upstream knows nothing about this repository, and it blanks the stored `metadata` blob and zeroes `stars`/`forks` on the row.
