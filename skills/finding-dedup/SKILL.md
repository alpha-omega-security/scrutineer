---
name: finding-dedup
description: Compare open findings in one repository and mark findings that describe the same underlying vulnerability as duplicates.
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

4. Mark a duplicate only when the findings are the same underlying vulnerability. Do not group findings that merely share a CWE, sink type, file, or helper function but have different attacker-controlled inputs, different exploit paths, or different impacts.

5. Choose one canonical finding for each duplicate group. Prefer the lowest database `id` among the open findings unless a later finding has materially better evidence. Never choose a finding with status `fixed`, `published`, `rejected`, or `duplicate` as canonical.

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
  ]
}
```

Use database `id` values, not per-scan `finding_id` values like `F1`. If there are no duplicates, write `{"duplicates":[]}`.

Scrutineer validates that every id belongs to this repository and only changes open findings. Accepted duplicate findings are moved to lifecycle status `duplicate`, and a note is appended explaining which canonical finding they duplicate.
