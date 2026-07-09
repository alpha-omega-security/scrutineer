# Diff-Based Rescans

Diff-based rescans are for repositories that have moved since the last scan.
They reuse prior scan context and focus the next run on the changes between a
baseline commit and the new commit.

Use a diff rescan when the project changed: a new release, a branch update, or
a CI-triggered scan after a merge. Use a normal full scan when Scrutineer
changed: new skills, better prompts, new runner images, or a model upgrade.
Full scans are the right way to re-check the whole repository with improved
tooling.

## Starting One

From a repository page, click **Diff rescan**. Scrutineer queues the
diff-aware threat-model, semgrep, and security-deep-dive scans as one group.
The deep-dive waits for the sibling threat-model and semgrep scans in that
group before it runs.

API callers can request diff mode when enqueueing a skill:

```json
{
  "rescan_mode": "diff"
}
```

Set `baseline_scan_id` only when you need to pin a specific baseline. Otherwise
Scrutineer chooses the latest compatible completed scan for that skill.

## What Diff Mode Does

A diff rescan compares the selected baseline scan commit with the current scan
commit, stages the diff for the skill, and asks diff-aware skills to focus on:

- changed files;
- changed entry points, trust boundaries, defaults, routes, parser surfaces, or
  build flags;
- existing findings whose attack chain may have changed;
- new findings introduced by the diff.

Diff mode does not claim full coverage over untouched code. Existing findings
are preserved, and a diff scan will not mark unrelated old findings as "not
observed" just because they were outside the diff.

## Automatic Full-Scan Fallback

Diff mode needs a stable baseline commit and a manageable diff. Scrutineer
automatically runs a full scan instead when:

- no suitable baseline scan exists;
- the baseline commit cannot be reached;
- the repository is local and has no usable git commit identity;
- the patch is too large;
- too many files changed.

The scan records why it fell back so the history still explains what happened.

## Threat Models

Diff-aware threat-model scans update the repository threat model only when the
change is material enough to plausibly alter the security contract. Small diffs
keep their threat-model scan report as evidence, but do not churn the working
model.

Material changes include security documentation, public APIs, authentication or
routing code, parser entry points, configuration defaults, build flags, and
other files that affect how untrusted input reaches security-sensitive code.

## Coverage Metadata

Diff scans record structured coverage metadata. The UI and later automation use
that metadata to explain which changed files were covered, which were skipped,
and why stale-finding updates were disabled or scoped.

Deterministic tools that cannot soundly limit themselves to the diff should say
so in their coverage metadata. They may run as a full scan or skip themselves,
depending on the tool and repository.
