# Opencode backend

Scrutineer can drive [opencode](https://opencode.ai) instead of claude-code,
selected with `-backend opencode` (or `backend: opencode` in
`scrutineer.yaml`). Unlike claude and codex, opencode is provider-agnostic:
the model you configure determines which API it talks to, so credential and
egress handling are looser than for the single-provider backends.

## Setup

The runner image bundles the `opencode` binary, so there's nothing to install.
opencode reads provider credentials from its auth config or from the
provider's own env var; the harness passes through `ANTHROPIC_API_KEY`,
`OPENAI_API_KEY`, `OPENCODE_CONFIG_CONTENT` and `OPENCODE_AUTH_CONTENT` from
the host so the common cases work without extra setup:

    export ANTHROPIC_API_KEY=sk-ant-...
    go run ./cmd/scrutineer -skills ./skills -backend opencode

or in `scrutineer.yaml`:

    backend: opencode
    default_model: anthropic/claude-sonnet-4-6
    models:
      - name: Sonnet (via opencode)
        id:   anthropic/claude-sonnet-4-6
      - name: GPT-5 (via opencode)
        id:   openai/gpt-5

Model ids are in opencode's `provider/model` form. For providers other than
Anthropic and OpenAI, set `OPENCODE_CONFIG_CONTENT` (an inline JSON config
opencode reads at startup) with the provider block, and add the provider's
API host to `egress_allow:` so the proxy lets it through.

The opencode backend requires the containerised runner. `--no-container` with
`-backend opencode` is rejected at startup.

## How the harness maps

| Aspect | claude | opencode |
| --- | --- | --- |
| Binary | `claude` | `opencode` |
| Argv | `claude -p --output-format stream-json ...` | `opencode run --format json --auto ...` |
| Skill staging | `./.claude/skills/{name}/SKILL.md` | `./.opencode/skill/{name}/SKILL.md` |
| Project memory | `CLAUDE.md` | `AGENTS.md` |
| Egress hosts | `*.anthropic.com` | `models.dev`, `api.openai.com`, `*.anthropic.com` |
| Credential env | `ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN` | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENCODE_CONFIG_CONTENT`, `OPENCODE_AUTH_CONTENT` |
| State dir env | `CLAUDE_CONFIG_DIR` | `OPENCODE_CONFIG_DIR`, `OPENCODE_DB` |
| Account-error phrases | claude usage/plan/access messages | union of common provider rate-limit / quota / invalid-key messages |

opencode globs `./.opencode/{skill,skills}/**/SKILL.md` with symlinks enabled,
so `stageSkill` writes the same files it always has into
`./.opencode/skill/{name}/`. The activation prompt points at that path
explicitly (opencode discovers but does not auto-invoke skills in headless
`run` mode). `PROFILE.md` lands at `AGENTS.md`, which opencode walks from cwd
up to the project root.

`--auto` and `OPENCODE_PERMISSION=allow` suppress opencode's interactive
permission prompts; the container is the sandbox. `--replay=false` on a
resumed session keeps the scan log from re-emitting the prior run's events.
`OPENCODE_DISABLE_MODELS_FETCH=1` stops opencode fetching `models.dev` at
startup (the host is still on the egress allowlist for runs that do need it).

The session store (`OPENCODE_DB`, a SQLite file) and config
(`OPENCODE_CONFIG_DIR`) are bind-mounted the same way claude's session store
is, so a retried scan continues with `--session <id>`.

## Egress

Because opencode can talk to any provider, the harness's `EgressHosts()`
returns the two common ones plus opencode's own model registry. That covers
Anthropic and OpenAI out of the box; anything else (Bedrock, Azure, Ollama on
another host, Cloudflare Workers AI) needs an `egress_allow:` entry. Under
`--hardened` only the harness's hosts plus the host skill API are permitted,
so a third-party provider under hardened mode is a deliberate widening.

The threat-model T1 residual applies the same: whichever provider credential
is set passes into the container as an env var and is readable by
in-container code.

## Known gaps

opencode has no per-turn cap in `run` mode, so `-max-turns` is ignored. The
`-scan-timeout` wall-clock limit still applies.

Claude's `-effort` setting has no opencode equivalent and is ignored.

`-anthropic-base-url` is accepted for interface symmetry but ignored: opencode
has no single base-URL override; per-provider endpoints go in
`OPENCODE_CONFIG_CONTENT`.

The stream parser (`OpencodeHarness.ParseStream`) maps `step_start`
(session id), `tool_use`, `text`/`reasoning`, and `error` events from
`opencode run --format json` onto the scan log, dropping `step_finish` noise.
Unknown event types pass through as raw text.

## See also

- `docs/codex.md`: the codex backend, including the "Adding another harness"
  section that opencode follows.
- `internal/worker/harness_opencode.go`: the `OpencodeHarness` implementation.
- #211: tracking issue for alternative harnesses.
