# Upstream provenance

`references/unsafe-rust-review.md` is a copy of the `unsafe-rust-review` skill
from Google's `rust-skills` repository. This file is for maintainers. The
scan prompt in `SKILL.md` never points the model at it.

| | |
|---|---|
| Repository | https://github.com/google/rust-skills |
| Path | `unsafe_rust_review/SKILL.md` |
| Pinned commit | `34b87c594bf7386290a1e3698d5b8e06b6b9edd7` |
| Path last changed upstream | 2026-10-27 |
| License | Apache-2.0, Copyright Google LLC (`LICENSE.upstream.md`) |
| Authors | Developed by @joshlf; extended by @manishearth (see upstream `README.md`) |

## What is local and what is upstream

- `references/unsafe-rust-review.md`: the upstream text with only its YAML
  frontmatter (`name`, `description`) removed, plus a provenance comment at
  the top. Do not edit the body here; changes belong upstream.
- `LICENSE.upstream.md`: upstream's `LICENSE.md`, copied unchanged.
- `SKILL.md`, `schema.json` and this file are Scrutineer's own (MIT). The
  `SKILL.md` wrapper adapts the upstream method to a scan: workspace, scope,
  read-only rules, and how its review results map onto `report.json`.

Not vendored: upstream's `EVAL.yml` and `testcases/test1.rs`–`test5.rs`
(small unsound snippets with expected verdicts, useful as a manual smoke
test), and the separate `unsafe_rust_review_experimental` skill.

## Updating

```sh
tmp=$(mktemp -d)
git clone -q --depth 1 https://github.com/google/rust-skills.git "$tmp"
git -C "$tmp" rev-parse HEAD                       # the new pinned commit
git -C "$tmp" log -1 --format=%cI -- unsafe_rust_review

dst=skills/audit-unsafe-rust
# Keep the 9-line provenance header, replace everything after it with the
# upstream body (frontmatter and the blank line after it removed).
{ head -n 9 "$dst/references/unsafe-rust-review.md"
  awk 'NR==1 && /^---$/ {fm=1; next} fm && /^---$/ {fm=0; skip=1; next}
       fm {next} skip && /^$/ {skip=0; next} {skip=0; print}' \
      "$tmp/unsafe_rust_review/SKILL.md"
} > "$dst/references/unsafe-rust-review.md.new"
mv "$dst/references/unsafe-rust-review.md.new" "$dst/references/unsafe-rust-review.md"
cp "$tmp/LICENSE.md" "$dst/LICENSE.upstream.md"
```

Then:

1. Update the commit SHA and date in the provenance header of
   `references/unsafe-rust-review.md`, in the table above, and in the
   comment in `SKILL.md`'s frontmatter.
2. Check `git diff` for renamed or removed section IDs (`` `[area.slug]` ``).
   `SKILL.md` names `[fact.classify]` and the `doc`, `comment`, `rej`, `dep`,
   `ref` and `hazard` areas, and `TestBundledAuditUnsafeRustMetadata` in
   `internal/skills/unsafe_rust_audit_test.go` asserts some of them.
3. Run `go test ./internal/skills -run 'Bundled'`.
