---
name: triage
description: Default pipeline scrutineer runs when a repository is added. Triggers a standard set of other skills in parallel, then writes a short summary of what was enqueued. Edit the list below to change the default scan coverage without touching scrutineer's Go code.
license: MIT
compatibility: Needs network access to the scrutineer API (http://host:port/api).
metadata:
  scrutineer.output_file: report.json
  scrutineer.output_kind: freeform
---

# triage

Kick off the standard set of scans against a freshly-added repository.

## Workspace

- `./context.json` — has `scrutineer.api_base`, `scrutineer.token`, and `scrutineer.repository_id`. Required.
- `./report.json` — write a short summary of what you enqueued.

## The scan set

Enqueue each of these skills against the repository in `scrutineer.repository_id` via `POST {api_base}/repositories/{id}/skills/{name}/run` with an `Authorization: Bearer {token}` header. Empty JSON body. Order does not matter; the scrutineer worker runs them as they come in.

- `metadata`
- `packages`
- `advisories`
- `dependents`
- `dependencies`
- `sbom`
- `maintainers`
- `repo-overview`
- `semgrep`
- `zizmor`
- `security-deep-dive`

If a skill name comes back `404 skill not found or inactive`, skip it and note which one in your report; the operator may have disabled it on purpose.

## Output

Write `./report.json` as:

```json
{
  "triggered": ["metadata", "packages", ...],
  "skipped":   ["semgrep"],
  "errors":    []
}
```

Do not wait for any of the scans to finish. The API returns a scan id immediately; your job is to fire them off and exit.

Do not fabricate scans or invent skill names. If the `api_base` or `token` is missing from context.json, write `{"error": "context.json missing scrutineer block"}` and exit 0 so the failure is visible on the scan page.
