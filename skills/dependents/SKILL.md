---
name: dependents
description: For each published package of this repository, fetch the top runtime dependents so later exposure-analysis skills have a ranked shortlist to work against. Use after the packages skill has populated which packages exist.
license: MIT
compatibility: Needs network access to packages.ecosyste.ms.
metadata:
  scrutineer.output_file: report.json
  scrutineer.output_kind: dependents
---

# dependents

## Workspace

- `./context.json` — has `repository.url`
- `./report.json` — write the combined dependents array here
- `./schema.json` — output shape

## What to do

1. Read `./context.json` and extract `repository.url`.
2. Look up the repository's packages: `https://packages.ecosyste.ms/api/v1/packages/lookup?repository_url={URL-ENCODED_URL}`. Each entry has a `dependent_packages_url`.
3. For each package's `dependent_packages_url`, fetch up to the first 30 results, ranked by `dependent_repos_count` or `downloads` descending.
4. Emit one entry per dependent under `report.json`'s `dependents` array:
   - `name` from upstream `name`
   - `ecosystem` from upstream `ecosystem`
   - `purl` from upstream `purl`
   - `repository_url` from upstream `repository_url` or `repo_metadata.html_url`
   - `downloads` from upstream `downloads`
   - `dependent_repos` from upstream `dependent_repos_count`
   - `registry_url` from upstream `registry_url`
   - `latest_version` from upstream `latest_release_number`

De-duplicate by `purl` when a dependent appears under more than one of this repo's packages.

If there are no packages or no dependents, write `{"dependents": []}`. Valid result.
