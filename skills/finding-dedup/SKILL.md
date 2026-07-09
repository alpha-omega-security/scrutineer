---
name: finding-dedup
description: Compare open findings in one repository and record how they relate. Marks same-vulnerability findings as duplicates, findings that another finding's fix will close as subsumed, and findings that combine into a higher-severity attack as a chain.
license: MIT
compatibility: Needs network access to the scrutineer API (http://host:port/api). Repository-scoped; compares existing finding rows and does not create new findings.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: finding_dedup
---

# finding-dedup

Find duplicate findings that fingerprinting missed because their line ranges, sink lists, or multi-file locations differed. A duplicate is a finding that describes the same root cause, same vulnerable code path, and same security impact as another open finding in this repository.

## Workspace

- `./context.json` - has `scrutineer.api_base`, `scrutineer.token`, and `scrutineer.repository_id`
- `./src` - repository checkout for spot-checking referenced files when the finding prose is ambiguous
- `./report.json` - write the deduplication decision here
- `./schema.json` - output shape

## What to do

1. Read `./context.json`. If the `scrutineer` block is missing, write `{"duplicates":[]}` and exit.

2. Fetch active findings with the bearer token:
   - `GET {api_base}/repositories/{repository_id}/findings?status=new`
   - `GET {api_base}/repositories/{repository_id}/findings?status=enriched`
   - `GET {api_base}/repositories/{repository_id}/findings?status=triaged`
   - `GET {api_base}/repositories/{repository_id}/findings?status=ready`
   - `GET {api_base}/repositories/{repository_id}/findings?status=reported`
   - `GET {api_base}/repositories/{repository_id}/findings?status=acknowledged`

3. For pairs that look similar from title, location, CWE, sink, or prose fields, fetch details with `GET {api_base}/findings/{id}`. Compare:
   - root cause and vulnerable operation
   - source-to-sink trace
   - trust boundary and attacker control
   - validation or reproduction
   - affected package/version scope
   - impact rating

   Weigh each finding's `dup_check` field: when several deep-dives run in parallel, the audit agent records there which siblings it already compared this finding against and why it judged it distinct. Treat that as the agent's own argument, not a verdict — if its reasoning holds against the pair in front of you, it is evidence against merging; if it compared against the wrong finding or got the root cause wrong, override it.

4. Classify each related pair into exactly one of:

   - **duplicate** — same underlying vulnerability: same root cause, same vulnerable code path, same security impact. Do not group findings that merely share a CWE, sink type, file, or helper function but have different attacker-controlled inputs, different exploit paths, or different impacts.
   - **subsumed** — different bugs, but one is only reachable through the other, and any correct fix for the parent closes the child too. Example: finding A is "unauthenticated user can reach the admin router"; finding B is "admin router path X lacks input validation". B is real on its own terms but a maintainer who fixes A has closed B's only unauthenticated path. B is subsumed by A. Do not use this when the child has an independent path the parent's fix leaves open; that is two findings.
   - **chain** — two or more findings that combine into a higher-severity attack than any of them alone. Example: finding A is a low-severity path traversal that reads arbitrary files under the app root; finding B is a medium-severity secret written to a predictable path under the app root. Separately each is what it is; together they are credential disclosure. Both stay open; the chain is what `disclose` reports.

   A pair that is none of these is unrelated; do not record it.

5. For duplicate groups, choose one canonical finding. Prefer the lowest database `id` among the open findings unless a later finding has materially better evidence. Never choose a finding with status `fixed`, `published`, `rejected`, or `duplicate` as canonical. For subsumed groups, the parent is the finding whose fix closes the others; it is not chosen by id. For chains there is no canonical; list members in exploit order when the order matters.

## Output

Write `./report.json`:

```json
{
  "duplicates": [
    {
      "canonical_id": 123,
      "duplicate_ids": [124, 125],
      "reason": "Same vulnerable parser branch and same untrusted field reaches the same allocation without a bounds check; the reports differ only by line range."
    }
  ],
  "subsumed": [
    {
      "parent_id": 130,
      "subsumed_ids": [131],
      "reason": "131 is only reachable via the unauthenticated admin route in 130; any fix that gates that route closes 131's only untrusted path."
    }
  ],
  "chains": [
    {
      "finding_ids": [140, 141],
      "reason": "140 reads arbitrary files under the app root; 141 writes a session token to a predictable path under the app root. Together: unauthenticated session takeover."
    }
  ]
}
```

Use database `id` values, not per-scan `finding_id` values like `F1`. `duplicates` is required; write `[]` when there are none. `subsumed` and `chains` are optional; omit them when empty.

Scrutineer validates that every id belongs to this repository and only touches open findings. Accepted duplicates are moved to lifecycle status `duplicate` with a note naming the canonical. Subsumed findings and chain members do not change status; each gets a note whose first line is `finding-dedup: subsumed by finding #N` or `finding-dedup: chains with finding #N[, #M...]`. `disclose` and `report-upstream` read those notes: a subsumed finding is refused (file the parent instead), and a chain member's disclosure pulls the other members' traces into a Composed section.
