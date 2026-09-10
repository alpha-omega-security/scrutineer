# Codex backend

Scrutineer can drive OpenAI's [codex](https://github.com/openai/codex) CLI
instead of claude-code, selected with `-backend codex` (or `backend: codex` in
`scrutineer.yaml`). The container, egress proxy, language profiles and
workspace layout stay the same; only the agent CLI exec'd inside the per-scan
container changes. This document records what the codex harness maps onto,
where it differs from claude, and what's still rough.

## Setup

The runner image already bundles the `codex` binary (a static musl build,
sha256-pinned in `Dockerfile.runner`), so there's nothing to install. For a
Platform API-key run, set the credential and start scrutineer:

    export CODEX_API_KEY=sk-...
    go run ./cmd/scrutineer -skills ./skills -backend codex

or in `scrutineer.yaml`:

    backend: codex
    default_model: gpt-5.6-sol
    models:
      - name: GPT-5.6 Sol
        id:   gpt-5.6-sol
        tier: high
      - name: GPT-5.6 Terra
        id:   gpt-5.6-terra
      - name: GPT-5.6 Luna
        id:   gpt-5.6-luna
        tier: mid
      - name: GPT-6 Astra
        id:   gpt-6-astra
        tier: max
      - name: GPT-5.5
        id:   gpt-5.5
      - name: GPT-5.2
        id:   gpt-5.2

The `models:` block is optional. Without it, Scrutineer seeds the list above
from defaults matched to the pinned codex catalog, with mid/high/max tier tags
already set, so a fresh install works with no config. Setting `models:`
replaces that list; `tier:` on an entry marks it as the default for that tier
in `/settings`.

Model ids must be in the pinned codex version's built-in catalog
(`codex-rs/models-manager/models.json` at the release tag stored in the
`CODEX_*_LOCK` build args);
an id codex doesn't recognise still runs but emits a "model metadata not
found" error item into every scan log (openai/codex#12100).

Codex also supports a ChatGPT subscription login. Create a dedicated,
file-backed login under an isolated Codex home (the browser/device step is
interactive):

    mkdir -p ~/.config/scrutineer/codex-rubygems
    chmod 700 ~/.config/scrutineer/codex-rubygems
    CODEX_HOME=~/.config/scrutineer/codex-rubygems \
      codex -c cli_auth_credentials_store=file login --device-auth
    chmod 600 ~/.config/scrutineer/codex-rubygems/auth.json

Then select it in `scrutineer.yaml`:

    backend: codex
    codex:
      auth_file: ~/.config/scrutineer/codex-rubygems/auth.json

`codex.auth_file` is deliberately config-only. Startup requires a regular file
with mode `0600`, ChatGPT token data, and a refresh token. It also
refuses `CODEX_API_KEY` or `OPENAI_API_KEY` in the environment so an account
run cannot silently consume Platform API credits.

Each scan keeps its own session/history directory. Only the rotating
`auth.json` is bind-mounted into that private `CODEX_HOME`, read-write. The
pinned Codex release rewrites this file in place during refresh, so Scrutineer
serializes the whole Codex job stream and starts the queue at concurrency one.
The queue keeps that one-slot cap across settings changes and runner restarts;
the higher stored setting applies again if account authentication is disabled.
Immediately before each container run, Scrutineer rechecks the file's mode,
credential shape and refresh token. This follows OpenAI's rule that one
file-backed credential copy belongs to one machine and one serialized job
stream.

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
| Egress hosts | `*.anthropic.com` | `api.openai.com`, `auth0.openai.com`, `chatgpt.com`; account auth also adds `auth.openai.com` |
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
With `codex.auth_file`, the credential is a nested bind mount at
`/harness-state/auth.json`; other scans' thread databases and history remain
out of view.

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

The same applies to chat: claude holds a chat turn to
`--allowedTools Read,Grep,Glob`, codex has no equivalent switch here, so its
read-only posture is a prompt instruction and the container boundary, the
same posture every scan already runs under.

The threat-model T1 residual depends on the authentication mode. An API key is
readable from the container environment. With `codex.auth_file`, untrusted
in-container code can read the broader ChatGPT access and refresh tokens and
can overwrite the shared credential through its required read-write mount; a
valid-looking replacement would persist into later scans. Per-run validation
catches permission or structural drift, not malicious substitution, and
serialization prevents refresh races rather than isolating the credential.
Use a dedicated account login and rotate it after any suspected hostile scan.

## Known gaps

Codex has no per-turn cap in `exec` mode, so `-max-turns` and the per-skill
`max_turns` frontmatter are accepted and ignored. The `-scan-timeout`
wall-clock limit still applies.

Claude's `-effort` setting has no codex equivalent and is ignored.

The stream parser (`CodexHarness.ParseStream`) maps codex's `--json` events
onto the scan log, verified against a live codex 0.142.5 run: `thread.started`
becomes the session event (so resume works), `item.completed` agent messages
are text, `item.completed` command/tool executions are tool calls
(`item.started` for the same id is dropped so a command shows once),
item-level `error` events surface as errors, `turn.completed` becomes the
result event with token usage, and unknown shapes fall through as raw text
rather than being dropped. Reports of rough edges welcome on #211.

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
