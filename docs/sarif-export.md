# Exporting findings as SARIF

`GET /api/v1/repositories/{id}/findings?format=sarif` returns the repository's findings as one SARIF 2.1.0 log, built and validated with [`github.com/git-pkgs/sarif`](https://github.com/git-pkgs/sarif). It is meant for handing findings to other security tooling, including [OSS-CRS](https://github.com/ossf/oss-crs) as bug candidates. The endpoint takes the same operator token as the rest of `/api/v1` (see [HTTP API](api.md#operator-api-apiv1)).

```sh
curl -H "Authorization: Bearer $(cat data/operator-token)" -o scrutineer.sarif 'http://127.0.0.1:8080/api/v1/repositories/1/findings?format=sarif&scope=findings'
```

The `severity`, `status`, `sub_path` and `scope` filters apply as they do for JSONL. `encrypt` and `include` are bundle-only and get a 400.

## What the log carries

Each distinct revision gets its own run, because SARIF records version control provenance per run. A finding's revision is the commit it was last observed at, falling back to the commit it was first seen at, since its location is refreshed on every re-observation. `versionControlProvenance` names the repository by the same portable URL a [sharing bundle](encrypted-sharing.md) uses, so a local checkout is exported under its HTTPS origin when it has one. Without one it is named by its `file:///` URI, with a Windows drive in the path (`file:///C:/src/widget`). A repository with no matching findings still yields one run with an empty `results` array.

| SARIF field | Source |
|---|---|
| `ruleId` and `tool.driver.rules` | First CWE of the finding (`CWE-79`, tagged `external/cwe/cwe-79`), or `scrutineer/finding` when the finding has none |
| `level` | Severity: Critical and High are `error`, Medium is `warning`, Low is `note` |
| `message.text` | Finding title |
| `locations` | Primary location, rebased onto the repository root with the finding's `sub_path`. `:line`, `:line:column` and `:start-end` suffixes become the region |
| `relatedLocations` | The other hits of a grouped finding |
| `fingerprints["scrutineer/v1"]` | The dedup fingerprint |
| `suppressions` | One `external` suppression for a `rejected` or `duplicate` finding, with the status as justification |
| `properties.scrutineer` | Finding id, report id, first-seen commit, sub-path, VID, model, importer, status, severity, confidence, the full CWE list, reachability and quality tier |
| `properties.scrutineer.evidence` | The audit's own reasoning: trace, boundary, validation, prior art, reach, rating |
| `properties.scrutineer.verification` | Status, score and scan id (`verify_scan_id`) of the latest `verify` run, or `unverified` when none has run |

The audit evidence is the candidate's own argument, so a consumer that needs an independent check reads `verification.status`, which only a `verify` run sets. Disclosure drafts, suggested recipients, federation claim contacts, notes and communications are never selected from the database for this export.

## Handing findings to OSS-CRS

OSS-CRS reads bug candidates through `libCRS`, whose [SARIF parser](https://github.com/ossf/oss-crs/blob/main/libCRS/libCRS/sarif.py) keeps each result's `ruleId`, `level`, `message.text` and the `uri` and `startLine`/`endLine` of each entry in `locations`. Its directory reader picks up only `*.sarif` and `*.sarif.json` files, so keep the extension.

Location URIs are relative to the repository root, so the source tree handed to OSS-CRS must be a checkout of the repository at a run's `versionControlProvenance[0].revisionId`. The `jq` line lists each run's revision with its result count, so pick the revision that carries the candidates you want. A source-only campaign with an `auditing` CRS then takes the export as a bug candidate:

```sh
jq -r '.runs[] | "\(.versionControlProvenance[0].revisionId // "no revision") \(.results | length)"' scrutineer.sarif
git -C ./widget checkout <revision>
uv run oss-crs prepare --compose-file ./crs-compose.yaml
uv run oss-crs run --compose-file ./crs-compose.yaml --target-source-path ./widget --bug-candidate ./scrutineer.sarif
```

`--bug-candidate` (or `--bug-candidate-dir` for a directory of exports) stages the file into `FETCH_DIR/bug-candidates/`, where a CRS reads it with `libCRS fetch bug-candidate <dir>` and parses it with `libCRS.sarif.parse_sarif_dir`. `oss-crs build-target` takes the same flags for directed builds. See [fetching data](https://github.com/ossf/oss-crs/blob/main/docs/crs-development-guide.md#fetching-data) in the CRS development guide. This was run end to end against OSS-CRS `674fd2a` with a source-only `auditing` CRS that fetched the export, parsed it with `libCRS` and resolved every location against `OSS_CRS_TARGET_SOURCE`.

OSS-CRS ignores `versionControlProvenance`, so an export spanning several revisions mixes locations from commits other than the one checked out, and a run whose revision differs from the checkout may point at lines that have moved. The parser also ignores `suppressions`, `relatedLocations` and the property bag, so a rejected finding reaches a campaign as an ordinary candidate and only its primary location is used. Filter with `status=` when the export should carry a single lifecycle state. The OSS-CRS guide still lists the bug-candidate format as unstandardised, so this mapping was checked against that parser rather than against a published contract.
