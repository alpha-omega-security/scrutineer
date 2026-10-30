# Anthropic OSS Scanner

[Anthropic's OSS Scanner registry](https://github.com/anthropics/oss-scanner) is a git repository where each enrolled project has a `projects/<name>/` directory holding `project.yaml` and optionally a `Dockerfile` and `threat_model.md`. Scrutineer reads those maintainer files and hands them to the threat-model and verify skills as reference data.

## Lookup order

1. Find the registry project whose `repo` matches the scanned repository URL. A `#branch` fragment, a trailing `/` or `.git`, http versus https and case are ignored. If several projects match, the lexically first directory name wins. Entries with an unparseable `project.yaml` are skipped.
2. For the Dockerfile and the threat model separately, the registry copy (`projects/<name>/Dockerfile`, `projects/<name>/threat_model.md`) wins when present. Otherwise the in-repo path from the `dockerfile` or `threat_model` key in `project.yaml` is used if it names a regular file inside the checkout.
3. When the repository is not enrolled, `.oss-scanner/Dockerfile` and `.oss-scanner/threat_model.md` in the checkout are used if present.

## What gets staged

For `threat-model` and `verify` scans, the files found are copied to `./oss_scanner/threat_model.md` and `./oss_scanner/Dockerfile` in the scan workspace. No other skill sees them. `context.json` gains `scrutineer.oss_scanner`:

| Field | Meaning |
|---|---|
| `project` | Registry project name. Absent when not enrolled. |
| `registry` | True when the repository matched a registry project. |
| `registry_url` | The registry that was consulted. Set only when `registry` is true. |
| `disabled` | The project's `disabled` flag. |
| `threat_model` / `dockerfile` | Where each file came from: `origin` (`registry` or `repository`) and `path`. |
| `threat_model_file` / `dockerfile_file` | Workspace path of the staged copy. Set only when the copy succeeded. |

The block is omitted when nothing applies. The threat-model skill treats the threat model as a documented maintainer source. The verify skill uses the Dockerfile as build guidance and the threat model as severity context.

## Configuration

```yaml
oss_scanner: true    # false turns the lookup off
oss_scanner_registry: https://github.com/anthropics/oss-scanner
```

`oss_scanner: false` turns off the registry fetch and the repository's own `.oss-scanner/` files, so nothing is staged. `oss_scanner_registry` must be an https URL with a host and no credentials. The registry is cloned into its own directory in the repository cache, apart from the clone a repository scan of the same URL uses. It is fetched again at most once an hour. The cache lock is held while the files are read and copied.

## Safety

- Files are read through `os.Root`, so symlinks in the registry or the scanned repository cannot escape it. Symlinks and other non-regular files are rejected.
- Each staged file is capped at 256 KiB.
- The content is maintainer-supplied data. The skills treat it as untrusted and never as instructions.
- The registry fetch is best-effort. A failure is logged and shown in the scan log and the scan continues without it.
- Local (`file://`) repositories skip the registry but still use `.oss-scanner/` files from the checkout.
- Nothing builds or runs the Dockerfile. The verify skill reads it as build guidance only.
