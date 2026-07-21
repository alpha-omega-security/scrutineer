---
name: variants
description: Starting from one confirmed finding, search this repository's current source for distinct sibling instances of the same root cause and emit only validated new findings.
license: MIT
compatibility: Finding-scoped, static, and read-only. Needs ./src plus the Scrutineer API to read the source finding and existing findings in this repository. Does not inspect dependents or use network sources.
allowed-tools: Read,Write,Bash,Grep,Glob
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: findings
  scrutineer.max_turns: 32
  scrutineer.model: high
  scrutineer.min_confidence: high
---

# variants

Starting from one confirmed finding, look for distinct, currently reachable
instances of the same root cause in this repository. This is a narrow
finding-scoped review, not a second full audit. It covers the source repository
only; dependent and downstream variants belong to a separate exposure review.

Emit only high-confidence, independently actionable siblings. An empty report
is a successful and useful result.

## Workspace and source finding

- ./src is the repository at the scan commit.
- ./context.json contains the scrutineer API details and finding_id.
- ./report.json is the required output and must conform to schema.json.

Read context.json first. If scrutineer.finding_id, api_base, or token is
missing, write {"findings":[]} and exit successfully.

Fetch the source finding:

    GET {api_base}/findings/{finding_id}
    Authorization: Bearer {token}

Then fetch the repository's existing findings:

    GET {api_base}/repositories/{repository_id}/findings
    Authorization: Bearer {token}

If either request fails, write an empty report rather than guessing. Do not
analyse a source finding that is rejected, duplicate, fixed, or published.

## Define the variant hypothesis

Turn the source finding into a precise hypothesis before searching:

1. Identify the root cause, not merely its CWE label.
2. Identify the required attacker-controlled input, data flow, and sink.
3. Identify the missing or insufficient control.
4. Identify exclusions: trusted callers, already-guarded paths, tests,
   generated code, vendored code, fixtures, unreachable helpers, and changes
   that are no longer present at HEAD.

Use rg, git grep, and focused file reads to find structural siblings: shared
helpers, equivalent parser branches, alternate protocol handlers, or other
callers that reach the same risky primitive. Use git log -S, git blame, and git
show when history is needed to distinguish a current bug from a fixed
historical pattern. Historical code is not a finding.

Do not broaden the task into an unrelated audit. A similar-looking API, a
matching CWE, or a string match alone is not a variant.

## Validate every candidate

For each candidate, establish all of the following before reporting it:

1. **Distinctness:** It is not the source location and does not duplicate an
   existing repository finding's root cause and affected location.
2. **Reachability:** Trace the relevant trust boundary through the candidate to
   the security-sensitive operation.
3. **Missing control:** Check the exact candidate path for the mitigation that
   protects the source location. Do not report a sibling protected by a
   different guard.
4. **Currentness:** Confirm the code is present in ./src and exclude
   documentation, tests, fixtures, generated code, vendored code, and dead
   branches unless production reachability is demonstrated.
5. **Impact:** Explain why the candidate has the same or a separately
   actionable security impact. Do not inherit severity without checking the
   candidate's own preconditions.

Remain static and read-only: do not build, execute, install, modify, commit,
or send data outside the local repository and the Scrutineer API reads above.
Record the searches, inspected code paths, and mitigation checks in
validation.

## Reporting

Use one finding for each independently exploitable root cause. You may use
locations only when one remediation genuinely covers every listed location.

Every emitted finding must:

- use confidence: "high" and discovered_via: "source";
- have a title beginning Variant of finding #<id>:;
- include the source finding in prior_art, for example
  Variant analysis of finding #42 (archive extraction traversal).;
- contain a concrete trace, boundary, validation record, and severity rating;
- use repository-relative locations in path:line form.

Do not report:

- the original finding;
- an existing finding describing the same affected location and root cause;
- theoretical patterns without a verified attacker-controlled path to a sink;
- low-confidence leads, generic hardening suggestions, or code-quality issues.

Write {"findings":[]} when no candidate meets every requirement. Never write
to the source finding or any other Scrutineer record.
