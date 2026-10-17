# Running Scrutineer as an OSS-CRS auditing CRS

[OSS-CRS](https://github.com/ossf/oss-crs) runs cyber reasoning systems (CRSs) against a target in a campaign. Scrutineer ships an `oss-crs/` directory that makes it an `auditing` CRS for source-only campaigns: it scans the target source with the default triage pipeline and submits the findings back as bug candidates plus a report. To go the other way and feed an existing Scrutineer export into a campaign, see [sarif-export.md](sarif-export.md).

## How it runs

`oss-crs/crs.yaml` declares one run module, `auditor`, with `target_dependent: false`, so no target build is needed and the campaign only supplies source.

- `oss-crs prepare` builds the runner image from `Dockerfile.runner` through `oss-crs/build.hcl` (tag `scrutineer-oss-crs-base:1.0.0`), then builds the auditor module on top of it (tag `oss-crs-runner:scrutineer-auditor`). The runner image already carries `claude`, the analysis tools and the `scrutineer` binary. The module adds libCRS and the entrypoint `oss-crs/run-auditor.sh`.
- `oss-crs run` starts the auditor container with the target source mounted read-only at `OSS_CRS_TARGET_SOURCE`. The entrypoint runs `scrutineer audit -no-container` against it with the claude backend, as the non-root `runner` user. No Docker socket is mounted: the CRS container is the isolation boundary, so scans run `claude` directly inside it.
- The audit is the usual triage pipeline. Triage fans out the audit skills and hooks chain the follow-ups (revalidate, dedup, reflect). The source is a local repository, so skills that require a remote forge are skipped.
- When the audit ends the entrypoint submits the bug-candidate SARIF and the report directory through libCRS.

## Example campaign

`crs-compose.yaml`:

```yaml
scrutineer:
  source:
    local_path: /path/to/scrutineer
  cpuset: "0-3"
  memory: 16G
  additional_env:
    SCRUTINEER_MODEL: claude-opus-4-6
    SCRUTINEER_AUDIT_TIMEOUT: 50m

llm_config:
  litellm:
    mode: internal
    internal:
      config_path: ./litellm-config.yaml
```

`litellm-config.yaml` must list every model Scrutineer asks for. The default model is `claude-opus-4-6`. A different `SCRUTINEER_MODEL` must be in this list too. Claude Code also uses a background model, which the entrypoint defaults to `SCRUTINEER_MODEL`, so that name has to resolve as well.

```yaml
model_list:
  - model_name: claude-opus-4-6
    litellm_params:
      model: anthropic/claude-opus-4-6
      api_key: os.environ/ANTHROPIC_API_KEY
```

Then, from an OSS-CRS checkout:

```sh
uv run oss-crs prepare --compose-file ./crs-compose.yaml
uv run oss-crs run --compose-file ./crs-compose.yaml --target-source-path ./target --timeout 3600
uv run oss-crs artifacts --compose-file ./crs-compose.yaml --target-source-path ./target
```

The entrypoint points `ANTHROPIC_BASE_URL` at `OSS_CRS_LLM_API_URL`, reads the per-CRS key from `OSS_CRS_LLM_API_KEY_FILE` into `ANTHROPIC_API_KEY` then passes the proxy hostname as `-trusted-model-host` because LiteLLM listens on a private container network over plain http.

## Environment variables

| Variable | Default | Effect |
|---|---|---|
| `SCRUTINEER_MODEL` | Scrutineer's default | Model for the audit's scans. Also the default for `ANTHROPIC_DEFAULT_HAIKU_MODEL` |
| `SCRUTINEER_AUDIT_TIMEOUT` | none | Wall-clock limit for the whole audit (`-audit-timeout`), for example `50m` |
| `SCRUTINEER_CONCURRENCY` | Scrutineer's default | Scans run in parallel (`-concurrency`) |
| `SCRUTINEER_AUDIT_USER` | `runner` | User the audit drops to when the container starts as root |
| `SCRUTINEER_AUDIT_WORK` | `/tmp/scrutineer-audit` | Work directory holding `out`, `data` and `logs` |

## Outputs

- `bug-candidates/scrutineer.sarif` is submitted with `libCRS submit bug-candidate`. It holds every finding except those a reviewer or the dedup pass suppressed, so rejected and duplicate findings are left out. It is written only when at least one finding remains.
- `scrutineer-audit/` is submitted with `libCRS submit report` and arrives as `scrutineer-audit.tar.gz`. It holds `audit.json` (the manifest), `scrutineer.sarif` (the full export including suppressed results), `findings.jsonl` and `scans.jsonl`.

`audit.json` carries `tool`, `version`, `status`, `reason`, `source`, `revision` (the `git rev-parse HEAD` of the source, empty when it is not a git checkout), `repository_id`, `started_at`, `finished_at`, `scans` (id, skill, status and error per scan), `findings` and `bug_candidates`.

`status` is one of:

- `complete`: every scan finished as done or skipped.
- `incomplete`: some scan failed, was cancelled or paused, never ran, or no scan ran at all. `reason` counts them, for example `2 scans failed, 1 scan paused`.
- `interrupted`: the audit timeout was reached or the process got SIGINT or SIGTERM. Running scans are cancelled and whatever finished is still exported.

The command exits 0 for `complete` and 3 for `incomplete` or `interrupted`. The entrypoint submits results for both then exits 0, because OSS-CRS aborts a campaign as failed when a module exits non-zero, so check `status` in `audit.json`. Any other exit code from the command means setup or export failed: nothing is submitted and the entrypoint exits with that code.

## Limits and cancellation

Spend is capped by the LiteLLM `llm_budget` in the compose file. Per-scan cost caps inside Scrutineer are tracked in [issue 774](https://github.com/alpha-omega-security/scrutineer/issues/774).

Set `SCRUTINEER_AUDIT_TIMEOUT` below the campaign `--timeout`. The audit then stops and submits before the framework kills the container. A SIGTERM from the framework has the same effect and produces an `interrupted` manifest.

## Rebuilding after code changes

`oss-crs prepare` skips a module image whose tag already exists, so remove both images first:

```sh
docker image rm oss-crs-runner:scrutineer-auditor scrutineer-oss-crs-base:1.0.0
```

## The audit command

`scrutineer audit` also works outside OSS-CRS. It runs the triage pipeline against one local directory in a throwaway instance, then writes the outputs described above under `-out`.

```sh
scrutineer audit -source ./widget -out ./audit-out -audit-timeout 1h
```

It accepts every server flag plus:

| Flag | Default | Description |
|---|---|---|
| `-source` | required | Directory to audit. Copied per scan, so it can be read-only |
| `-out` | required | Directory the results are written to |
| `-audit-timeout` | `0` | Wall-clock limit for the whole audit, `0` for none |
| `-model` | server default | Default model for the audit's scans, overriding the config file |
| `-trusted-model-host` | none | Hostname of a model proxy on a private container network that may be reached over plain http, such as OSS-CRS's LiteLLM |

`-trusted-model-host` relaxes the https requirement for that one hostname only. Every other model URL still has to use https unless it is loopback.

The audit never touches an operator instance. Without `-data` it uses a fresh temporary directory and removes it at the end. With `-data` it refuses a directory that already holds `scrutineer.db`. Any `data` or database setting in the config file is ignored: the audit always uses sqlite in its own data directory and listens on an ephemeral loopback port. It does not start the scheduler, federation, the ecosystems lookups or the CNA sync.
