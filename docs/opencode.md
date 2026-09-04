# OpenCode backend

Scrutineer can run [OpenCode](https://opencode.ai) instead of claude-code. Set
`-backend opencode`, or use `backend: opencode` in `scrutineer.yaml`. Model ids
use OpenCode's `provider/model` form, and this backend requires the container
runner. Scrutineer rejects `--no-container` when it is selected.

The stock runner contains OpenCode and its common built-in providers. Existing
Anthropic and OpenAI installations can keep using host credentials without a
provider block:

    export ANTHROPIC_API_KEY=sk-ant-...
    go run ./cmd/scrutineer -skills ./skills -backend opencode

    backend: opencode
    default_model: anthropic/claude-sonnet-5
    models:
      - name: Sonnet via OpenCode
        id: anthropic/claude-sonnet-5

## Provider configuration

Add an `opencode.providers` entry when a provider needs different credentials,
egress, config, stored auth, or a derived runner image. The map key must match
the provider prefix in the model id.

    backend: opencode
    default_model: groq/llama-3.3-70b-versatile
    models:
      - name: Llama 3.3 70B via Groq
        id: groq/llama-3.3-70b-versatile

    opencode:
      providers:
        groq:
          api_key_env: GROQ_API_KEY
          egress_allow:
            - api.groq.com

`api_key_env` names a variable in Scrutineer's host environment. For each
scan, Scrutineer generates `OPENCODE_AUTH_CONTENT` containing only the selected
provider and gives the container the variable name rather than putting its
value in the runtime argv. A configured provider does not inherit
`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or a host-wide OpenCode auth document.

Use `auth_metadata` for provider auth fields that accompany an API key:

    opencode:
      providers:
        example:
          api_key_env: EXAMPLE_API_KEY
          auth_metadata:
            accountId: team-1
          egress_allow:
            - api.example.com

Some providers use several native environment variables instead of an
OpenCode API-key record. Name each one under `pass_env`; Scrutineer refuses the
scan if any named value is absent. Variables such as `GITHUB_TOKEN` are never
forwarded unless they appear here, which avoids confusing a repository token
with a Copilot credential. Proxy, state, config, update, model-fetch, and share
controls owned by Scrutineer cannot be named under `pass_env`.

    opencode:
      providers:
        amazon-bedrock:
          pass_env:
            - AWS_ACCESS_KEY_ID
            - AWS_SECRET_ACCESS_KEY
            - AWS_REGION
          egress_allow:
            - bedrock-runtime.us-east-1.amazonaws.com

Credential files are not mounted automatically. Bedrock, Vertex, and similar
providers need narrowly scoped mounts before file-based host credential chains
can be supported.

Whichever of `api_key_env`, `pass_env`, or `state_dir` supplies the credential,
its value passes into the scan container so opencode can authenticate and is
readable by any code the scanned repository causes to run there (the T1
residual in `threatmodel.md`). `pass_env` extends that to whatever native
chain the provider requires, and the `state_dir` auth file described below is
mounted read-write so refreshed tokens persist, which also lets in-container
code overwrite it. Prefer short-lived or narrowly scoped credentials (an
`AWS_SECRET_ACCESS_KEY` limited to Bedrock model invocation, a per-install
OAuth app for Copilot) so an exfiltrated value has bounded reach; under
`--hardened` the provider's `egress_allow` hosts, its `host_port` when set,
and the skill API are the only destinations it can be sent to.

Every configured provider needs at least one `egress_allow` hostname or a
`host_port`. `egress_allow` hosts are added only to scans using that provider,
including under `--hardened`. The top-level `egress_allow` remains ignored in
hardened mode. Use hostnames without a scheme, path, or port. Region- and
resource-specific providers should list the endpoints for the configured region
or resource.

A model whose provider prefix is neither `anthropic`, `openai`, nor a key under
`opencode.providers` is refused before the container starts.

## Host-local providers

For a model server running on the host machine's loopback (Ollama, LM Studio,
llama.cpp, or another OpenAI-compatible endpoint), set `host_port` instead of
`egress_allow`. The egress proxy opens exactly that port on
`host.docker.internal` and rewrites it to the host loopback, alongside the
skill API port every scan already reaches; no other host loopback service is
reachable. The `config_file` must point OpenCode's `options.baseURL` at
`http://host.docker.internal:<port>`, not `127.0.0.1`, because the request
originates inside the container. Scrutineer refuses a `host_port` provider at
startup when the loaded `config_file` does not name that address.

    opencode:
      providers:
        ollama:
          config_file: ./opencode/ollama.json
          host_port: 11434

    # ./opencode/ollama.json
    {
      "provider": {
        "ollama": {
          "npm": "@ai-sdk/openai-compatible",
          "options": { "baseURL": "http://host.docker.internal:11434/v1" },
          "models": { "llama3.3": {} }
        }
      }
    }

The readiness check probes `http://host.docker.internal:<port>/` from inside
the container before the skill runs, so a stopped model server or a wrong port
fails the scan with a clear error rather than an OpenCode server exception.
`host_port` and `egress_allow` may be combined when a provider needs both a
host-local endpoint and external hostnames.

Under the sidecar egress path (Docker Desktop or rootless podman with `--hardened`) the request
goes container → sidecar → host gateway → host loopback. Rootless podman needs
its network backend to forward the host gateway to the host loopback. The
sidecar refuses to start when the skill API port is unavailable on the default
`-addr 127.0.0.1:8080`; the same check applies here. A non-loopback `-addr`
makes the sidecar's startup gate reach the API without host-loopback forwarding,
so that check no longer proves a loopback-bound model server is reachable.

## Provider images and config

`runner_image` selects a provider base image before Scrutineer resolves the
repository language profile:

    Scrutineer runner -> OpenCode provider image -> language profile

Build provider images from the Scrutineer runner. They must retain `opencode`,
`brief`, and the `scrutineer` binary, then add any pinned plugin, adapter,
provider package, or supporting executable. Pin the configured image by digest
when practical. Scrutineer records both the configured image reference and its
locally resolved digest or image id on the scan. Readiness checks `brief` and
`scrutineer` automatically when `runner_image` is set.

List supporting executables under `required_binaries`. The readiness check
looks them up inside the selected image and names a missing executable in the
scan error.

`config_file` points to an OpenCode JSON or JSONC config on the host. Relative
paths are resolved from `scrutineer.yaml`; the file is read at startup and sent
as `OPENCODE_CONFIG_CONTENT`. Restart Scrutineer after changing it. Keep the
file limited to the selected provider and do not store credentials in it; code
inside the scan container can read the resulting environment variable.

    opencode:
      providers:
        kiro:
          runner_image: registry.example/scrutineer-opencode-kiro@sha256:...
          config_file: ./opencode/kiro.json
          pass_env:
            - KIRO_API_KEY
          required_binaries:
            - kiro-cli
          egress_allow:
            - q.us-east-1.amazonaws.com
            - runtime.us-east-1.kiro.dev
            - management.us-east-1.kiro.dev
            - prod.us-east-1.auth.desktop.kiro.dev

Kiro is an operator-managed image case. The stock OpenCode catalog no longer
contains `kiro/auto`, so the image and config must supply a pinned adapter and
`kiro-cli`. The exact config and host list must match the adapter version in
that image.

Before running the skill, Scrutineer checks each concrete provider egress host,
then runs `opencode models <provider>` from `/tmp` in the selected
language-profile image. This keeps repository OpenCode files out of the check.
The selected `provider/model` must appear exactly in the output. Missing
OpenCode binaries, adapter packages, supporting binaries, egress, and catalog
models produce separate errors. OpenCode errors from the skill run are also
kept in the scan error instead of being replaced by the container exit status.

## Stored auth

OAuth providers can use `state_dir` instead of `api_key_env`. Scrutineer mounts
only its `auth.json` into the scan's OpenCode data directory, allowing refreshed
auth to survive separate scans without exposing logs or repository data from a
previous scan.

    opencode:
      providers:
        github-copilot:
          state_dir: ~/.local/share/scrutineer/opencode/github-copilot
          egress_allow:
            - github.com
            - api.github.com
            - "*.githubcopilot.com"

The corresponding auth file is
`<state_dir>/opencode/auth.json`. It may contain only the provider named by the
configuration block. Scrutineer checks this before mounting it and refuses to
expose a file containing another provider's credential. On Unix the state
directory must have owner-only permissions such as `0700`; Windows has no
POSIX mode bits so the check does not apply there. When `state_dir` is the only
credential source, its auth file must already contain the selected provider. A
provider using `pass_env` may initialise the file on first use.
`state_dir` and `api_key_env` cannot be combined because
`OPENCODE_AUTH_CONTENT` would override the rotating file. Scans that share a
`state_dir` run one at a time so a token refresh from one scan is never
overwritten by another; use `api_key_env` or `pass_env` for providers where
concurrent scans matter more than persisted OAuth.

Without `state_dir`, OpenCode's auth data stays with the scan's retry state and
is deleted after that scan lineage completes. Logs, repository data, and
session data remain under the ordinary per-scan harness-state mount in both
cases.

## Harness behaviour

OpenCode receives `opencode run --format json --auto --model
provider/model`. Skills are staged at `./.opencode/skill/{name}/SKILL.md`, and a
language profile's project guide is written as `AGENTS.md`. `--auto` suppresses
interactive permission prompts; the container remains the security boundary.

OpenCode has no `run` option matching Scrutineer's `-max-turns`, and Claude's
`-effort` setting has no OpenCode equivalent. The wall-clock `-scan-timeout`
still applies. `-model-base-url` is also ignored because OpenCode endpoints are
configured per provider.

The stream parser maps OpenCode session, tool, text, reasoning, error, cost,
and usage events into the scan log and metrics. Unknown event types remain
visible as raw text.

## See also

- [Runner setup](../README.md#setup)
- [Hardened egress](egress-sidecar.md)
- [Codex backend](codex.md)
