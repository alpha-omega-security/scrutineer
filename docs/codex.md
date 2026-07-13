# Codex backend

Scrutineer can drive OpenAI's [codex](https://github.com/openai/codex) CLI
instead of claude-code, selected with `-backend codex` (or `backend: codex` in
`scrutineer.yaml`). The container, egress proxy, language profiles and
workspace layout stay the same; only the agent CLI exec'd inside the per-scan
container changes. This document records what the codex harness maps onto,
where it differs from claude, and what's still rough.

## Setup

The runner image already bundles the `codex` binary (a static musl build,
sha256-pinned in `Dockerfile.runner`), so there's nothing to install. Set the
credential and start scrutineer:

    export CODEX_API_KEY=sk-...
    go run ./cmd/scrutineer -skills ./skills -backend codex

or in `scrutineer.yaml`:

    backend: codex
    default_model: gpt-5.3-codex
    models:
      - name: GPT-5.3 Codex
        id:   gpt-5.3-codex
        tier: high
      - name: GPT-5.4
        id:   gpt-5.4
      - name: GPT-5.4 mini
        id:   gpt-5.4-mini
        tier: mid
      - name: GPT-5.5
        id:   gpt-5.5
        tier: max

The `models:` block is optional. Without it, the pick list is codex's own
built-in catalog with mid/high/max tier tags already set, so a fresh install
works with no config. Setting `models:` replaces that list; `tier:` on an
entry marks it as the default for that tier in `/settings`.

Model ids must be in the pinned codex version's built-in catalog
(`codex-rs/models-manager/models.json` at the `rust-v${CODEX_VERSION}` tag);
an id codex doesn't recognise still runs but emits a "model metadata not
found" error item into every scan log (openai/codex#12100).

Codex also supports a ChatGPT login flow (Codex Pro accounts, via
`auth0.openai.com` / `chatgpt.com`) and those hosts are on the egress
allowlist, but headless `codex exec` inside a container with a fresh per-scan
`CODEX_HOME` cannot drive the interactive browser step, so a host-side `codex
login` does not reach the scan and `CODEX_API_KEY` is the only working
credential path.

To point codex at a different endpoint, pass `-model-base-url` or set
`model_base_url:` in config; scrutineer adds the host to the allowlist and
passes the value to codex as `openai_base_url`.

The codex backend requires the containerised runner. `--no-container` with
`-backend codex` is rejected at startup: the codex binary lives in the runner
image, not on the host, and the local fallback (`LocalClaude`) is claude-only.

## How the harness maps

Everything the container runner asks of the agent CLI goes through the
`Harness` interface (`internal/worker/harness.go`). The codex values:

| Aspect | claude | codex |
| --- | --- | --- |
| Binary | `claude` | `codex` |
| Argv | `claude -p --output-format stream-json ...` | `codex exec --json --sandbox danger-full-access --skip-git-repo-check ...` |
| Skill staging | `./.claude/skills/{name}/SKILL.md` | `./skills/{name}/SKILL.md` |
| Project memory | `CLAUDE.md` | `AGENTS.md` |
| Egress hosts | `*.anthropic.com` | `api.openai.com`, `auth0.openai.com`, `chatgpt.com` |
| Credential env | `ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN` | `CODEX_API_KEY` |
| Base URL override | `ANTHROPIC_BASE_URL` env | `-c openai_base_url=...` |
| State dir env (mounted at `/harness-state`) | `CLAUDE_CONFIG_DIR` | `CODEX_HOME` |
| Account-error phrases | claude usage/plan/access messages | OpenAI `rate_limit`, `insufficient_quota`, `invalid_api_key`, `429` |

Skill staging works because codex has its own `SKILL.md` discovery
(`codex-rs/core-skills/src/loader.rs` scans `./skills/*/SKILL.md` from cwd up to
the project root and follows directory symlinks). `stageSkill` writes the same
`SKILL.md` / `schema.json` / aux files it always has; only the directory
differs. Scrutineer's extra frontmatter keys (`output_kind`, `requires_profile`,
`compatibility`) are unknown to codex and ignored.

The activation prompt differs. Claude's "Use the {name} skill" relies on its
slash-style invocation; codex discovers the skill but does not auto-invoke it
in headless `exec` mode, so the prompt says "Follow the instructions in
./skills/{name}/SKILL.md against ./src" explicitly, plus the same
schema-validation hint claude gets.

`PROFILE.md` (the per-language scanning guide) is copied into the workspace as
`AGENTS.md`, which codex reads as project memory the same way claude reads
`CLAUDE.md`. Codex concatenates every `AGENTS.md` from the project root down to
cwd (32 KiB cap), so the single workspace-root file scrutineer writes is the
whole of what it sees.

The session store (codex's thread database under `CODEX_HOME`) is bind-mounted
at `/harness-state` the same way claude's is, from
`{data}/harness-state/scan-N` on the host, so a retried scan can `codex exec
resume <thread-id>` the previous run. Each scan records which backend ran it
(`scans.backend`), and a retry after switching `-backend` starts fresh rather
than passing a codex thread id to `claude --resume` or vice versa.

## Sandbox interaction

Codex has its own sandbox modes (`read-only` / `workspace-write` /
`danger-full-access`). On Linux the first two are implemented with
`bubblewrap`, which is not in the runner image and would not work under its
`--cap-drop ALL` and default seccomp profile anyway (bwrap needs unprivileged
user namespaces). Scrutineer's container already drops all caps, runs
non-root, mounts the workspace, and gates egress through the proxy; that is
the sandbox, so scrutineer runs codex with `--sandbox danger-full-access` and
`--skip-git-repo-check`, disabling codex's own layer inside it. Under
`--hardened` the read-only rootfs and per-scan `--internal` network apply
exactly as for claude.

The threat-model T1 residual (the model-API credential is readable by
in-container code) applies the same: `CODEX_API_KEY` is passed as a container
env var.

## Known gaps

Codex has no per-turn cap in `exec` mode, so `-max-turns` and the per-skill
`max_turns` frontmatter are accepted and ignored. The `-scan-timeout`
wall-clock limit still applies.

Claude's `-effort` setting has no codex equivalent and is ignored.

The stream parser (`CodexHarness.ParseStream`) maps codex's `--json` events
onto the scan log, verified against a live codex 0.142.5 run: `thread.started`
becomes the session event (so resume works), `item.completed` agent messages
are text, `item.completed` command/tool executions are tool calls
(`item.started` for the same id is dropped so a command shows once), item-level
`error` events surface as errors, `turn.completed` becomes the result event
with token usage, and unknown shapes fall through as raw text rather than being
dropped. Reports of rough edges welcome on #211.

## Adding another harness

Opencode (and any other agent CLI) slots in the same way: a struct
implementing `Harness` in its own `internal/worker/harness_<name>.go`, an
entry in the `harnesses` registry map, the binary in `Dockerfile.runner`, and a
README/docs note. Opencode's discovery paths are
`./.opencode/skill/{name}/SKILL.md` and `AGENTS.md` (both follow symlinks), its
state dir is `OPENCODE_CONFIG_DIR` plus `OPENCODE_DB`, and its headless command
is `opencode run --format json`. Nothing in the container runner changes.

## See also

- `internal/worker/harness.go`: the `Harness` interface and `ClaudeHarness`.
- `internal/worker/harness_codex.go`: the `CodexHarness` implementation.
- `threatmodel.md`: T1 (in-container code reads the model credential), T13
  (egress proxy enforcement).
- #211: tracking issue for alternative harnesses; #239 was the original
  opencode attempt this work supersedes.
