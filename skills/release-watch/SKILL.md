---
name: release-watch
description: After a finding has been marked fixed, watch the upstream for a release that contains the fix. When one shows up, record the release tag, URL, and timestamp on the finding. Closes the gap between "the maintainer landed a patch" and "consumers have a shipped version they can pin to".
license: MIT
compatibility: Needs network access to the scrutineer skill API and to github.com (or whichever host the upstream lives on). Read-only.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: release_watch
  scrutineer.requires_remote: true
  scrutineer.model: mid
---

# release-watch

A finding reached `fixed` because a commit landed upstream. Consumers cannot pin to a commit; they need a tagged release. This skill answers "did the maintainer cut one yet, and what's the version".

The skill is finding-scoped. Run it after the finding has been marked `fixed` (the triage skill auto-enqueues this for every `fixed` finding on each repo run). When no release has shipped yet, the answer is just that — return `released: false` and a short note about what the latest release looks like. The next run will check again.

## Workspace

- `./src` — the upstream repository at the scanned commit
- `./context.json` — has `scrutineer.api_base`, `scrutineer.token`, `scrutineer.finding_id`, `scrutineer.repository_id`, and `repository.url` / `repository.full_name`
- `./report.json` — write your finding here
- `./schema.json` — output shape

## Inputs

1. Fetch the finding:

   ```
   GET {api_base}/findings/{finding_id}
   Authorization: Bearer {token}
   ```

   Read `fix_commit`, `fix_version`, `status`, and the existing `released_at` / `release_tag` / `release_url` on the finding. If a release is already recorded, write `{"released": true, "release_tag": "<existing tag>", ..., "notes": "already recorded; re-confirming"}` and exit — re-runs should not flap a recorded value.

   If `status` is not `fixed`, write `{"released": false, "notes": "skill only meaningful in fixed status; finding is in <status>"}` and exit.

2. List releases on the upstream. On github.com:

   ```
   gh api repos/{owner}/{repo}/releases?per_page=20
   ```

   The response gives you `tag_name`, `name`, `html_url`, `published_at`, and `target_commitish`. If `gh auth` fails, write `{"released": false, "notes": "gh auth not configured; cannot list releases"}` and exit.

   Non-GitHub hosts: skip for now and record a note. A later iteration covers GitLab, gitea, and registry-only sources.

3. Map each release back to a commit. For each release whose `target_commitish` is empty (sometimes tags are detached), resolve via:

   ```
   gh api repos/{owner}/{repo}/git/ref/tags/{tag_name}
   ```

   to get the tag's SHA, then `gh api repos/{owner}/{repo}/commits/{sha}` to confirm. Skip a release if its commit cannot be resolved; do not guess.

## Procedure

1. **Match by commit.** When the finding has a `fix_commit`, check each release for whether `fix_commit` is reachable from the release's commit. Use:

   ```
   gh api repos/{owner}/{repo}/compare/{fix_commit}...{release_commit}
   ```

   If the comparison succeeds with `status: ahead` or `identical` (the release commit is at or after the fix commit), this release contains the fix. Pick the *earliest* such release by `published_at`: consumers want the first version they can upgrade to.

2. **Fall back to fix_version.** If `fix_commit` is empty but `fix_version` is set, match by tag name: a release whose `tag_name` matches `fix_version` (with or without a leading `v`) is the one. Verify by fetching its commit, just so you have the timestamp.

3. **Neither field set.** Write `{"released": false, "notes": "finding has no fix_commit or fix_version to anchor the search"}` and exit. This is a recoverable state: the analyst can fill in either field and re-run.

4. **A release was found.** Emit:

   ```json
   {
     "released": true,
     "release_tag": "v2.3.1",
     "release_url": "https://github.com/example/lib/releases/tag/v2.3.1",
     "release_at": "2026-06-02T14:00:00Z",
     "notes": "matched by fix_commit; release contains 4 commits since the fix"
   }
   ```

   `released_at` is ISO 8601. Scrutineer writes it to `Finding.ReleasedAt` and the rest to the matching columns, with the change recorded in finding history. It also adds a `FindingReference` row with `tags=upstream-release` so the release link appears in the finding's references panel.

5. **No matching release yet.** Emit:

   ```json
   {
     "released": false,
     "notes": "latest release v2.3.0 from 2026-05-30 predates fix_commit abc1234"
   }
   ```

   The next run rechecks. Make the note specific enough that a human can tell if the maintainer is sitting on the fix.

Do not transition the finding's lifecycle status. `published` means the advisory has been published, which is a human act and a different signal from a release shipping; release-watch records the release but leaves status alone.
