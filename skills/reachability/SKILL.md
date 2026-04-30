---
name: reachability
description: Check whether known sinks in this application's dependencies are reachable from its own trust boundaries. Scrutineer already holds findings against the libraries this app uses; this skill traces each one from the app's entry points to the library call and reports the ones an attacker can reach. Use on applications (Gemfile.lock / package-lock.json present), not on libraries.
license: MIT
metadata:
  scrutineer.output_file: report.json
  scrutineer.output_kind: findings
---

# reachability

Security-deep-dive on a library finds dangerous sinks but stops at the library boundary: "High if the caller passes untrusted input." This skill picks up on the application side. Scrutineer hands you the list of sinks already found in this app's dependencies; you decide, per sink, whether this app wires untrusted input to it.

A reachable sink in an application is usually one severity step above the same sink in the library, because the boundary discount no longer applies. A library High that this app exposes on an unauthenticated route is an application Critical.

## Workspace

- `./src` — the cloned application
- `./context.json` — `scrutineer.api_base`, `scrutineer.token`, `scrutineer.repository_id`, optional `scrutineer.scan_subpath`
- `./report.json` — write findings here
- `./schema.json` — output shape (same as security-deep-dive)

## Inputs

Fetch the candidate sinks:

```
GET {api_base}/repositories/{repository_id}/dependency-findings
Authorization: Bearer {token}
```

Each entry has `package`, `ecosystem`, `requirement`, `manifest_path`, `dependency_type`, `severity`, `cwe`, `title`, `location` (file:line inside the library), `sinks`, `trace`, `boundary`, `library_repository_url`, and `finding_id`. The list is ordered by severity. If it is empty, either the dependencies skill has not indexed this repo yet or none of its dependencies have findings; write `{"findings": [], "ruled_out": [], "inventory": [], ...}` per the schema and stop.

Work the list top-down. Budget your time toward High and Medium; Low entries are mostly resource-exhaustion in parsers and only worth a quick grep.

## Per-sink procedure

For each candidate, the question is fixed: does untrusted input from one of this application's entry points reach the library call named in `location` / `sinks`?

### 1. Locate the call site

Find where this app calls into `package`. Start from the `boundary` field on the candidate — it names the library entry point that leads to the sink (e.g. `Roo::Spreadsheet.open`, `Icalendar::Calendar.parse`, `PDF::Reader.new`). Grep `./src` for that symbol, the `require`/`import` of `package`, and obvious wrappers around it. If `scan_subpath` is set, scope to that folder.

If the package is only in `Gemfile.lock` as a transitive dependency and nothing in `./src` calls it directly, check whether the app calls the intermediate package in a way that forwards input (e.g. crass via `sanitize`/loofah, sawyer via Octokit). If you cannot find a call path in two hops, rule it out: "transitive, no direct or one-hop call site".

If `dependency_type` is `development` or the only call sites are under `test/`, `spec/`, or `script/`, rule it out: "development-only".

### 2. Trace to a boundary

From each call site, walk backwards to where the argument originates. You are looking for:

- request parameters, uploaded files, request bodies
- records read from the database whose value an unprivileged user wrote
- files or URLs fetched from a location an external party controls
- background-job arguments whose enqueue path is one of the above

Name the route, controller action, job class, or CLI entry point. Quote the line where external data enters and each hop to the library call.

If every call site receives only operator-chosen constants, fixtures, or admin-only input, rule it out and say which. Admin-only still counts if the app has self-service signup that grants the relevant role.

### 3. Confirm the sink behaviour applies

Read the candidate's `trace` and `boundary` prose. They describe the input shape that triggers the library bug. Check the app does not already neutralise it: size limits, content-type allowlists, schema validation, a safe-mode flag on the library call. Cite what you checked either way.

You do not need to re-prove the library bug — that is the upstream finding's job. You do need to show this app's input can take the shape the upstream finding requires.

### 4. Rate

- **Critical** — reachable from an unauthenticated or self-service-authenticated request with no precondition beyond "send the payload", and the upstream sink yields code execution, auth bypass, or data exfiltration.
- **High** — reachable from an authenticated user, or upstream impact is denial-of-service / resource exhaustion on a public route.
- **Medium** — reachable but gated by a non-default configuration, an elevated role short of admin, or a multi-step chain.
- **Low** — reachable only from trusted operator input, or the app's own limits reduce impact to nuisance level.

## Output

Write `./report.json` conforming to `./schema.json`.

- `inventory[]` — one entry per candidate you assessed: `id` `S{n}`, `class` derived from the candidate's CWE (best fit from the schema's `sink_class` enum), `location` `"{package} {requirement} → {candidate.location}"`, `consumes` set to the call-site argument you traced.
- `findings[]` — each reachable sink. `title` should name both the app entry point and the library sink, e.g. `"Spreadsheet upload at ImportsController#create reaches roo xlsx range expansion (upstream finding #{finding_id})"`. Put the call-site trace in `trace`, the app's boundary in `boundary`, and what you checked for mitigations in `validation`. Reference the upstream finding by `finding_id` and `library_repository_url` in `prior_art`.
- `ruled_out[]` — every candidate you did not promote to a finding, with `step` 1/2/3 matching the section above where it fell out and a one-line `reason`.
- `boundaries[]` — the application's actors (anonymous web user, authenticated user, admin, background job feeder) as you found them while tracing.

Set `spec_version` to `10`. Use the repository URL and HEAD commit of `./src` for `repository` and `commit`.
