# Copilot backend

Scrutineer can drive [GitHub Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli)
instead of claude-code, selected with `-backend copilot` (or `backend:
copilot` in `scrutineer.yaml`). The container, egress proxy, language
profiles and workspace layout stay the same; only the agent CLI exec'd inside
the per-scan container changes.

## Setup

The runner image bundles the `copilot` binary (a glibc build, sha256-pinned
in `Dockerfile.runner`), so there's nothing to install. Authenticate with a
GitHub token that has Copilot access and start scrutineer:

    export GH_TOKEN=$(gh auth token)
    go run ./cmd/scrutineer -skills ./skills -backend copilot

or in `scrutineer.yaml`:

    backend: copilot
    default_model: claude-sonnet-4.6
    models:
      - name: Claude Sonnet 4.6
        id:   claude-sonnet-4.6
        tier: high
      - name: Claude Haiku 4.5
        id:   claude-haiku-4.5
        tier: mid
      - name: Claude Opus 4.6
        id:   claude-opus-4.6
        tier: max
      - name: GPT-5.3 Codex
        id:   gpt-5.3-codex
      - name: GPT-5.4
        id:   gpt-5.4

The `models:` block is optional; without it the pick list is the harness's
built-in default set above. Model ids are Copilot CLI's own (dotted, e.g.
`claude-sonnet-4.6`), which differ from claude-code's hyphenated ids
(`claude-sonnet-4-6`) -- don't copy ids between the claude and copilot
backends.

Any of `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, or `GITHUB_TOKEN` on the host is
passed through to the container as a credential; Copilot CLI accepts the
first one it finds. There is no separate API-key concept here: whichever
token you export is the one billed against your Copilot entitlement.

Copilot CLI rejects **classic personal access tokens** (`ghp_...`) outright
with "Classic Personal Access Tokens (ghp_) are not supported by Copilot",
before any network call. Use one of:

- the OAuth token `gh auth login` already stores -- `export GH_TOKEN=$(gh auth token)`
- a fine-grained PAT (`github_pat_...`) on an account with Copilot access

The token is validated against the GitHub API on startup, so an expired or
insufficiently scoped token fails the scan with "Authentication token found
but could not be validated" rather than hanging.

The copilot backend requires the containerised runner. `--no-container` with
`-backend copilot` is rejected at startup: the `copilot` binary is in the
runner image, not on the host, and the local fallback (`LocalClaude`) is
claude-only.

## How the harness maps

| Aspect | claude | copilot |
| --- | --- | --- |
| Binary | `claude` | `copilot` |
| Argv | `claude -p --output-format stream-json ...` | `copilot -p ... --output-format json --autopilot --max-autopilot-continues N --allow-all --no-ask-user --no-auto-update --no-color` |
| Skill staging | `./.claude/skills/{name}/SKILL.md` | `./.github/skills/{name}/SKILL.md` |
| Project memory | `CLAUDE.md` | `./.github/copilot-instructions.md` |
| Egress hosts | `*.anthropic.com` | `github.com`, `api.github.com`, `api.mcp.github.com`, `*.githubcopilot.com` |
| Credential env | `ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN` | `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN` |
| State dir env | `CLAUDE_CONFIG_DIR` | `COPILOT_HOME` |
| Account-error phrases | claude usage/plan/access messages | rate limit / quota / entitlement / auth failure messages |

`--allow-all` grants the CLI every tool it exposes without interactive
confirmation; the container is the sandbox, the same posture codex and
opencode run under. `--no-ask-user` stops copilot from blocking on an
interactive prompt (scrutineer runs it headless). `--resume=<id>` is appended
when a scan is retried, so the session store (bind-mounted at
`/harness-state`, `COPILOT_HOME`) resumes the previous attempt, the same as
the other backends.

The activation prompt points explicitly at
`./.github/skills/{name}/SKILL.md`: like codex and opencode, copilot
discovers skills but does not auto-invoke them in headless `-p` mode.

`-model-base-url` maps to `COPILOT_PROVIDER_BASE_URL`; there is no
`-effort` equivalent, and it is ignored for this backend, same as codex and
opencode.

## The package cache and the noexec /tmp

The `copilot` binary is a self-extracting bundle: on first run it unpacks a
package containing a native addon (`runtime.node`) into a cache directory and
`dlopen()`s it. Its default cache location is `$XDG_CACHE_HOME/copilot`, or
`$HOME/.cache/copilot` when that is unset.

That default does not work inside a scan container. The container runner sets
`HOME=/tmp` and mounts `/tmp` as a `noexec` tmpfs
(`--tmpfs /tmp:rw,noexec,nosuid,size=256m`, `internal/worker/container.go`),
so the extracted addon lands on a filesystem the kernel refuses to map
executable and the CLI dies before doing any work:

    Failed to load package index: /tmp/.cache/copilot/pkg/linux-x64/1.0.80/index.js
    Error: Native addon "runtime" not found for linux-x64. Tried:
      .../prebuilds/linux-x64/runtime.node: failed to map segment from shared object

`Dockerfile.runner` avoids this by unpacking the package at **build** time
into `/usr/local/lib/copilot` and setting `COPILOT_PKG_CACHE_HOME` to that
path. It is the first entry in copilot's package search order (ahead of
`COPILOT_CACHE_HOME`, `$XDG_CACHE_HOME/copilot`, `COPILOT_HOME`, and
`~/.copilot`), so the runtime lookup resolves on the exec-capable rootfs and
never touches the tmpfs. The build asserts the package actually materialised
(`test -d $COPILOT_PKG_CACHE_HOME/pkg`) so a future CLI release that changes
this layout fails the image build rather than every scan.

A read-only rootfs (`--hardened`) is compatible: the package is already
unpacked, and the harness passes `--no-auto-update` (plus
`COPILOT_AUTO_UPDATE=false`), so copilot never tries to fetch or write a
newer one. Profile images inherit both the directory and the environment
variable because they are built `FROM ${RUNNER_IMAGE}`.

Keep this in mind when bumping `COPILOT_VERSION`: the version is part of the
cache path, so the build-time unpack and the runtime lookup have to come from
the same image layer -- which they do, but a hand-copied `copilot` binary
dropped into a derived image without re-running the unpack step would fall
back to the noexec default and fail.

## Egress

Copilot CLI connects to GitHub for authentication, MCP, and the model API
itself (`githubcopilot.com`), so the default egress allowlist is entirely
GitHub infrastructure. Under `--hardened` only these hosts plus the host
skill API are permitted. The exception is `-model-base-url`: Copilot CLI
contacts that provider host directly, and scrutineer adds it to the
allowlist in both normal and `--hardened` modes.

The threat-model T1 residual applies the same: whichever GitHub token is set
passes into the container as an env var and is readable by in-container
code. Scope the token to the minimum (fine-grained PAT with only the Copilot
Requests permission) if that residual matters for your deployment.

## Known gaps

The stream parser (`CopilotHarness.ParseStream`) maps Copilot CLI's
`--output-format json` events onto the scan log:
`assistant.message` and `assistant.reasoning` become text/thinking events,
`tool.execution_start` becomes a tool call, `assistant.usage` and
`assistant.turn_end` are combined into a single result event emitted after
the stream ends (Copilot reports turns and token usage as separate records),
`result` carries the session id and a non-zero exit code as an error, and
`abort` / `session.error` / `error` surface as errors. Unknown event types
pass through as raw text so a CLI update remains visible.

## See also

- `docs/codex.md`: the codex backend, including the "Adding another harness"
  section that copilot follows.
- `docs/opencode.md`: the opencode backend.
- `internal/worker/harness.go`: the `Harness` interface aliases; the
  concrete `CopilotHarness` implementation is in the
  `github.com/alpha-omega-security/harness` module (`copilot.go`).
- #211: tracking issue for alternative harnesses.
