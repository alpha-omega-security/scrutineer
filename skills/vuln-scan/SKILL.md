---
name: vuln-scan
description: High-recall static source-code vulnerability scan adapted from Anthropic's defending-code reference harness. Fans out by focus area, ranks candidates by confidence, and emits Scrutineer findings for later verification.
license: MIT
compatibility: Static and read-only. Needs source in ./src and may use Claude subagents. Does not build, run, install dependencies, or use network.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: findings
  scrutineer.max_turns: 90
  scrutineer.model: max
---

# vuln-scan

Run a broad static source-code vulnerability scan. This skill is adapted from Anthropic's defending-code reference harness: it uses a quick recon pass, splits the repository into security focus areas, and then consolidates high-signal candidate findings into Scrutineer's findings shape.

The target is first-party source code. Do not report vulnerabilities that exist only in dependencies, generated files, fixtures, examples, tests, docs, or unchanged vendored code.

## Workspace

- `./src` - cloned repository
- `./context.json` - repository identity plus a `scrutineer` block with `api_base`, `token`, `repository_id`, and optional `scan_subpath`
- `./report.json` - write the findings report here
- `./schema.json` - output schema

If `scrutineer.scan_subpath` is set, scope every read and report location to `./src/{scan_subpath}`. Do not inspect code outside that subtree except to understand workspace layout. Report locations relative to the scoped project root.

## Safety

This scan is read-only:

- Do not build or run target code.
- Do not install dependencies.
- Do not start services, containers, package managers, or test suites.
- Do not use the network for source analysis. If Scrutineer's local API is reachable through `context.json`, you may read prior Scrutineer scan reports; otherwise reason from `./src`.

## Orientation

First, build a compact map of the target:

1. Read `context.json` and determine the scoped source root.
2. List files with `rg --files` or equivalent.
3. Identify languages, package layout, public entry points, handlers, parsers, CLIs, unsafe/FFI areas, deserializers, archive/file/network operations, authz boundaries, and agent/model/tool integrations.
4. If available, fetch prior local reports from Scrutineer's API and use them as context:
   - `GET {api_base}/repositories/{repository_id}/scans?skill=threat-model&status=done`, then `GET {api_base}/scans/{id}` for trust boundaries
   - `GET {api_base}/repositories/{repository_id}/scans?skill=repo-overview&status=done`, then `GET {api_base}/scans/{id}` for project shape
   - `GET {api_base}/repositories/{repository_id}/findings?skill=semgrep` for static-analysis anchors

If any API request fails or returns no data, continue with source-only review.

## Focus Areas

Create three to ten focus areas. Prefer focus areas from the threat model if one exists; otherwise derive them from recon. Useful focus areas include:

- Memory safety: C/C++, unsafe Rust, raw pointers, unchecked indexes, allocation sizes, integer arithmetic that feeds buffers, FFI, lifetime hazards.
- Injection and execution: eval, shell/process execution, dynamic imports, templates, SQL/NoSQL/query construction, regex construction, format strings.
- Filesystem and archives: path traversal, symlink races, archive extraction, permissions, temporary files, canonicalization before access decisions.
- Deserialization and parsing: unsafe object construction, parser differentials, round-trip integrity, validation bypasses.
- Authn/authz and tenant isolation: object lookup by attacker-controlled ID, missing ownership checks, privilege transitions.
- Network and SSRF: attacker-controlled URLs, redirects, proxy handling, DNS rebinding, TLS verification changes.
- Crypto and secrets: weak primitives, IV/nonce reuse, missing MAC verification, hardcoded or logged secrets.
- Agentic integrations: untrusted content entering prompts, tool definitions, tool arguments, model-visible fetched content, unconstrained loops or cost triggers.
- Shared state and concurrency: global mutable state, cache poisoning, check-then-act races, request cross-talk.

For small repositories, a single pass is fine. For larger repositories, use one subagent per focus area, capped at ten. If subagents are unavailable, review the focus areas sequentially.

## Review Rules

Report only candidate vulnerabilities with a concrete source path, sink, trust boundary, and plausible exploit scenario.

Do not report:

- Best-practice gaps without an exploit path.
- Volumetric denial-of-service issues unless the project explicitly provides a bounded-resource security property.
- Memory-safety concerns in memory-safe code unless unsafe/FFI/native extensions are involved.
- XSS in frameworks that auto-escape by default unless the code uses a raw HTML/script escape hatch.
- Regex injection, log spoofing, open redirect, missing audit logs, old dependencies, or weak configuration defaults without a stronger project-specific impact.
- CLI arguments, environment variables, local config files, or developer-supplied paths as attacker-controlled unless the project documents a privilege boundary where an untrusted actor controls them.

For each candidate, record:

- `id` - stable `F001`, `F002`, ...
- `title` - concise vulnerability statement
- `severity` - `Critical`, `High`, `Medium`, or `Low`
- `confidence` - `high`, `medium`, or `low`
- `cwe` - best matching `CWE-N`; use an empty string only when no mapping fits
- `location` - primary `path:line`
- `locations` - optional supporting `path:line` entries
- `reachability` - `reachable`, `harness_only`, or `unclear`
- `quality_tier` - `high` for concrete exploit paths; `low` for speculative or incomplete paths that still deserve analyst attention
- `trace` - how attacker-controlled input reaches the sink
- `boundary` - why the input crosses a real trust boundary in this project's model
- `validation` - static checks performed, including existing mitigations you looked for; note that no code was executed
- `prior_art` - optional related fixes, advisories, or issues found in local context
- `reach` - optional downstream or deployment reachability notes
- `rating` - severity/confidence rationale, exploit scenario, and recommendation

Use these common CWE mappings when they fit: command injection `CWE-78`, path traversal `CWE-22`, SQL injection `CWE-89`, XSS `CWE-79`, SSRF `CWE-918`, unsafe deserialization `CWE-502`, authz bypass `CWE-862` or `CWE-863`, hardcoded secret `CWE-798`, weak crypto `CWE-327`, buffer overflow `CWE-120`, use-after-free `CWE-416`, integer overflow `CWE-190`, race condition `CWE-367`.

## Consolidation

Before writing the report:

1. Drop candidates that lack a concrete code location.
2. Drop candidates whose exploit depends only on a trusted developer/operator choosing unsafe local configuration.
3. Deduplicate candidates with the same root cause; keep the clearest location and list supporting locations.
4. Convert numeric confidence notes, if any, to Scrutineer's labels: `high` for strong evidence, `medium` for plausible but not fully proven, `low` for weak or incomplete paths.
5. Ensure every finding has the required narrative fields and that locations are relative to the scan scope.

Write `./report.json` as:

```json
{
  "findings": [
    {
      "id": "F001",
      "title": "Archive extraction writes outside the target directory",
      "severity": "High",
      "confidence": "medium",
      "cwe": "CWE-22",
      "location": "pkg/archive/extract.go:88",
      "locations": ["pkg/archive/extract.go:71"],
      "reachability": "reachable",
      "quality_tier": "high",
      "trace": "User-supplied archive entry names flow from ParseArchive to filepath.Join before the file is created.",
      "boundary": "The documented API accepts archives from callers and does not state that entry names are trusted.",
      "validation": "Static-only review. Checked for filepath.Clean, EvalSymlinks, and containment checks around the write path; none guard the joined path before Create.",
      "rating": "High because a crafted archive can overwrite files outside the extraction root. Medium confidence because the scan did not execute a PoC. Reject absolute paths and require the real output path to stay under the destination root."
    }
  ]
}
```

If you find nothing worth reporting, write `{"findings":[]}`.

## Provenance

This skill adapts the focus-area scanning workflow from Anthropic's defending-code reference harness while using Scrutineer's workspace, schema, and finding lifecycle conventions.
