# Configuration

Every flag below except `-config` can be set in a YAML config file, loaded from `./scrutineer.yaml` by default. Use `-config path/to/file` to select another file; command-line flags always take precedence. See [scrutineer.sample.yaml](../scrutineer.sample.yaml) for the full shape.

`scrutineer.yaml` may contain long-lived credentials such as `skills_repo_token`, the VINCE API key and federation salt. Keep it out of source control and backups, and set owner-only permissions with `chmod 600 scrutineer.yaml`. A private `skills_repo` must use a credential-free HTTPS URL; Scrutineer passes `skills_repo_token` to Git through `GIT_ASKPASS`, and intentionally provides no token command-line flag.

For identity files and age identity plugins, see [encrypted-sharing.md](encrypted-sharing.md#age-identity-plugins).

## Models and tiers

The config file can also replace the model pick list and pin the fallback default model used by the high tier:

    default_model: claude-sonnet-5
    models:
      - name: Sonnet 5.0
        id:   claude-sonnet-5
      - name: Opus
        id:   claude-opus-5

Skills resolve to a model through a tier: `high` by default, unless the skill's `SKILL.md` metadata pins `scrutineer.model` to another tier or an exact model id (bundled lightweight skills such as `metadata` use `mid`, `security-deep-dive` uses `max`). The Settings page maps each tier to any configured model.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | `./scrutineer.yaml` if present | Path to YAML config file |
| `-addr` | `127.0.0.1:8080` | Listen address |
| `-data` | `./data` | Data directory for the database and workspaces |
| `-effort` | `high` | Reasoning effort level, applied by the `claude` and `copilot` backends and ignored by `codex` and `opencode`. Copilot CLI stops at `xhigh`, so `max` is capped to it there |
| `-skills` | - | Additional local directory to load SKILL.md files from; same-named skills override the bundled copies (repeatable) |
| `-skills-repo` | - | `owner/repo[@ref]` or credential-free git HTTPS URL `https://host/path[@ref]` to clone skills from on startup; `@ref` pins a branch, tag or commit and the resolved SHA is recorded on every scan; private repositories use config-file-only `skills_repo_token` |
| `-backend` | `claude` | Agent CLI the container runner execs: `claude`, `codex`, `opencode`, or `copilot`. Non-claude backends require the containerised runner |
| `--runtime` | `docker` | Container runtime: `docker`, `podman` (rootless podman supported), or `apple` (Apple, experimental) |
| `--selinux` | `auto` | Bind-mount SELinux relabeling: `auto` (relabel when SELinux is detected), `on`, or `off` |
| `--no-container` | false | Disable the containerised runner; run claude directly on the host (no isolation). Deprecated alias: `--no-docker` |
| `--hardened` | false | Strict sandbox: container runtime required, egress restricted to the backend's model API hosts + host skill API, read-only rootfs, internal network |
| `--hardened-runtime-only` | false | The non-network half of `--hardened` (read-only rootfs + `no-new-privileges` + 2 GiB workspace cap) **without** the per-scan `--internal` network; the rootless fallback for hosts where the `--hardened` egress sidecar can't run (implied by `--hardened`). Deprecated alias: `--hardened-rootless-runtime` |
| `--runner-image` | release-matched digest (`ghcr.io/alpha-omega-security/scrutineer-runner:latest` in development builds) | Container image for per-scan containers |
| `-concurrency` | `4` | Number of scans to run in parallel. Chat turns run from a separate pool sized at half this value, so a busy host can reach 1.5x this many agent containers. With `codex.auth_file`, scans and chat turns share one execution slot |
| `-clone` | `shallow` | Clone depth: `shallow` (`--depth 1`) or `full` |
| `-scan-timeout` | `1h` | Wall-clock limit per scan; exceeded scans fail |
| `-backend-preflight-ttl` | `0` | Opt-in live backend probe cache lifetime, e.g. `1h`; probes consume model tokens. YAML: `backend_preflight_ttl`. |
| `-max-turns` | `0` | Per-scan turn cap (0 = unlimited); claude and copilot backends only, codex and opencode have no turn cap |
| `-schema-strict` | `false` | Fail a scan when its `report.json` does not validate against the skill's `schema.json` (default: warn in the scan log and parse anyway) |
| `-model-base-url` | - | Custom model API base URL for the active backend (env fallback: `ANTHROPIC_BASE_URL` for claude). `-anthropic-base-url` is a deprecated alias. |
| `-model-proxy` | false | Keep `ANTHROPIC_API_KEY` off scan containers: each scan gets a per-scan token for a host-side Anthropic API proxy. Claude backend with API-key auth only, requires the containerised runner. See [docs/model-proxy.md](model-proxy.md). |
| `-ecosystems-enrichment` | `true` | Enrich repositories from ecosyste.ms: the per-repository cache, the warm on repo add, and the PURL-to-repository resolution behind SBOM and dependency import. `=false` stops every lookup scrutineer's own process makes, leaves `egress_allow` untouched (the bundled skills still fetch ecosyste.ms themselves), and leaves the Dependents tab and dependent-exposure analysis with no data |
| `-recipients-file` | - | Age recipients file (public keys) for encrypted export |
| `-identity-file` | - | Age identity file or SSH private key for decrypting imports and encrypted federation feeds |
| `-identity-plugin` | - | Data-less age identity plugin name (`age -j`) for decrypting imports and encrypted federation feeds (repeatable; replaces `identity_plugins` from config when set) |

See [running.md](running.md#container-runner) for runner images, profiles and hardening, and [egress-policies.md](egress-policies.md) for per-skill egress policies. Backend-specific setup is in [codex.md](codex.md), [opencode.md](opencode.md), and [copilot.md](copilot.md).
