# Scan usage and cost

Scrutineer records model usage on each scan and aggregates completed and failed skill runs on the `/usage` page. The **By skill** view is the instance's observed cost range: min, median, p90, max, total, token totals and turn-count percentiles are calculated from the scans stored in that instance. These corpus measurements are more useful than a fixed price estimate because model, effort, repository content and provider pricing all affect cost.

## Cost drivers

The **Cost drivers** view compares scan cost with three inexpensive workload proxies:

- **SLOC** is `lines.total_lines` from the latest successful `repo-overview` report for the repository.
- **Dependency manifests** is the current number of distinct non-empty `Dependency.ManifestPath` values stored for the repository.
- **Phase 1 sinks** is the number of entries in the latest positive-cost completed `security-deep-dive` report for the repository.

Repository-wide SLOC and manifest measurements are not attached to subpath or focus-area scans because the full-repository value would overstate their scope. They are deliberately coarse, inexpensive current-corpus proxies rather than historical commit snapshots: SLOC can lag until `repo-overview` runs again, and dependency rows reflect the latest successful inventory. Phase 1 sink counts are attached only to the selected deep-dive scan, which avoids loading and parsing the repository's complete deep-dive history on every page view.

Correlations are calculated independently per skill over positive-cost runs. A row appears once at least three matched observations exist and both cost and the driver vary. The reported value is Pearson's correlation coefficient (`r`): values near `1` indicate that cost tends to rise with the proxy, values near `-1` indicate an inverse relationship and values near `0` indicate little linear relationship. Correlation describes the stored corpus and does not prove that a proxy caused the cost.

## Outliers

The outlier table lists every positive-cost scan whose cost is at least ten times the positive-cost median for that skill. Each row links to the scan and repository and includes model, runner profile, turns and any matched driver measurements. Inspect the linked scan's transcript, report and runtime settings before assigning a cause; common explanations include a larger-than-usual analysis surface, a large sink inventory, repeated tool work, retries or a different model configuration.

Zero-cost rows are retained in the normal usage totals but excluded from correlation and outlier baselines. This prevents historical rows without captured billing data and genuinely free runs from forcing the outlier median to zero.

## Pausing on subscription overage

Set `pause_on_overage: true` in `scrutineer.yaml` or pass `-pause-on-overage` to stop model work when a Claude subscription reports paid overage. The option defaults to false and takes precedence over `downgrade_on_overage`. An explicit CLI boolean overrides the YAML setting, including `-pause-on-overage=false`.

An overage signal stops active scan jobs through the existing cancellation mechanism but records them as paused, preserving their session IDs, partial reports, and workspace state. Queued skill and exposure scans are paused, and a dispatch gate prevents newly queued or manually resumed jobs from starting while the hold is active. The Jobs and Usage pages display the policy state. Manual cancellations and maintainer opt-outs remain cancellations; manually paused scans are not included in overage auto-resume.

The worker waits for the latest applicable reset across observed overage windows, using the existing auto-resume buffer. Missing or implausibly distant reset times leave the work paused for operator action rather than guessing. Persisted overage pauses also gate new dispatch after a restart; a hold without a reliable reset remains until operator action. To deliberately permit overage, disable the option, restart Scrutineer, and resume the paused scans. This policy does not disable the existing handling of actual account errors.

The policy depends on provider-reported overage events, so it is not a hard monetary budget and cannot guarantee zero overage charges before detection or while cancellation takes effect. An API-key account that reports no subscription-overage signal does not activate it.
