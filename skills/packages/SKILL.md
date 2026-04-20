---
name: packages
description: Look up every published package that corresponds to a repository, across all registries, and record download counts, dependent counts, latest version, and registry URL. Use to populate the Packages tab.
license: MIT
compatibility: Needs network access to packages.ecosyste.ms.
metadata:
  scrutineer.output_file: report.json
  scrutineer.output_kind: packages
---

# packages

One repository can ship multiple packages across multiple ecosystems. Ask packages.ecosyste.ms for all of them and record the headline stats.

## Workspace

- `./context.json` — has `repository.url`
- `./report.json` — write the packages array here
- `./schema.json` — output shape

## What to do

1. Read `./context.json` and extract `repository.url`.
2. Fetch `https://packages.ecosyste.ms/api/v1/packages/lookup?repository_url={URL-ENCODED_URL}`. The response is a JSON array, one object per published package.
3. For each package upstream returns, emit one entry in `report.json` under `packages` mapping these fields:
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

If there are no packages (lookup returns `[]`), write `{"packages": []}`. That is a valid result, not an error.
