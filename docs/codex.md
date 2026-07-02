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
    default_model: gpt-5-codex
    models:
      - name: GPT-5 Codex
        id:   gpt-5-codex

Codex Pro accounts (the ChatGPT login flow rather than an API key) authenticate
via `auth0.openai.com` and `chatgpt.com`; both are on the egress allowlist by
default. To point codex at a different endpoint, pass `-anthropic-base-url` or
set `anthropic_base_url:` in config for now; scrutineer adds the host to the
allowlist and passes the value to codex as `openai_base_url`.

The codex backend requires the containerised runner. `--no-container` with
`-backend codex` is rejected at startup: the codex binary lives in the runner
image, not on the host, and the local fallback (`LocalClaude`) is claude-only.

## How the harness maps

Everything the container runner asks of the agent CLI goes through the
`Harness` interface (`internal/worker/harness.go`). The codex values:

| Aspect | claude | codex |
| --- | --- | --- |
| Binary | `claude` | `codex` |
| Argv | `claude -p --output-format stream-json ...` | `codex exec --json --sandbox workspace-write --skip-git-repo-check ...` |
| Skill staging | `./.claude/skills/{name}/SKILL.md` | `./skills/{name}/SKILL.md` |
| Project memory | `CLAUDE.md` | `AGENTS.md` |
| Egress hosts | `*.anthropic.com` | `api.openai.com`, `auth0.openai.com`, `chatgpt.com` |
| Credential env | `ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN` | `CODEX_API_KEY` |
| Base URL override | `ANTHROPIC_BASE_URL` env / `ANTHROPIC_BASE_URL` in-container | `-c openai_base_url=...` |
| State dir env | `CLAUDE_CONFIG_DIR` | `CODEX_HOME` |
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
the same way claude's is, so a retried scan can `codex exec resume <thread-id>`
the previous run. The container mountpoint is still named `/claude-config` and
the host directory `{data}/claude-config/scan-N`; that's historical and will be
renamed once a second harness has soaked.

## Sandbox interaction

Codex has its own sandbox modes (`--sandbox workspace-write` /
`danger-full-access`). Scrutineer runs it under `workspace-write`, the lightest
mode that lets codex edit `/work`, with `--skip-git-repo-check` so the
workspace doesn't need to be a git checkout. The container already drops all
caps, runs non-root, mounts the workspace, and gates egress through the proxy;
codex's sandbox is layered inside that, not a substitute for it. Under
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
onto the scan log: `session_id` / `thread_id` become session events (so resume
works), nested `item` command/tool events show as tool calls, nested agent
message text is emitted as text, `error` events surface as errors, and unknown
shapes fall through as raw text rather than being dropped. Reports of rough
edges welcome on #211.

The `-anthropic-base-url` flag is reused as the model-API base-URL override for
whichever harness is active; under codex it becomes the `openai_base_url` config
override for `codex exec`. A harness-neutral flag name will follow.

## Adding another harness

Opencode (and any other agent CLI) slots in the same way: a struct
implementing the nine `Harness` methods in `internal/worker/harness.go`, an
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
