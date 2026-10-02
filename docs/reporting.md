# Reporting exports

The **Reporting** page (`/reporting`) shows corpus-wide activity over a rolling window -- repositories scanned, runs started and completed, findings, per-day and per-model breakdowns, and per-scan cost and token averages beside their all-time figures -- and exports the same snapshot as CSV or JSON:

    curl -sSfOJ 'http://127.0.0.1:8080/reporting/report.json?interval=week'
    curl -sSfOJ 'http://127.0.0.1:8080/reporting/report.csv?interval=month&severity=high'

`interval` is `day`, `week`, `month` or `all` (the default). `severity` is a minimum floor on the findings count -- `low`, `medium` (or `moderate`), `high`, `critical`, any case -- and never touches the scan counts. The JSON shape is `reporting.Export` in `internal/reporting/export.go`: `filters.minimum_severity` is `null` for an unfiltered export and `period.starts_at` is `null` for `interval=all`.

## Merging exports from several instances

Discrete instances that each scan their own repositories can be rolled up into one report in the same shape, as if a single instance had scanned the whole corpus:

    go run ./scripts/merge-reports a/report.json b/report.json > merged.json
    go run ./scripts/merge-reports -o merged.json reports/*/report.json

Counts are summed, averages are pooled by `scans_averaged`, per-day and per-model rows are combined by date and model, and the period is the union of the inputs' windows. The merged file has `period.key: "merged"`, a `sources` array naming each original export with its window and severity floor, and a note appended to `activity_in_period.measured_by` that `repositories_scanned` sums per-instance distinct counts -- exact only when the instances share no repositories.

Options:

- `-severity LEVEL` -- require every input to have been exported with that floor (`-severity all`: with none). The export carries only aggregated counts, so a floor cannot be re-applied while merging; an input with a different floor is refused by name.
- `-allow-mixed-periods` -- merge inputs exported over different windows (a `week` beside an `all`), which is otherwise refused because the in-period figures would pool two windows. The merged `starts_at` is `null` if any input was unbounded.
- `-o FILE` -- write there instead of stdout.

Warnings go to stderr for inputs whose `filters` differ and for inputs that share their all-time cost averages, which two exports of the *same* instance do -- merging those would double every figure. When inputs disagree on their severity floor, the merged `filters.minimum_severity` is `"mixed"` and each input's own floor is in `sources`.

Inputs must come from instances running the same scrutineer version as the tool: a file whose fields differ from the tool's `report.json` is refused rather than merged with a field dropped or zeroed. A merged file is itself a valid input, and merging is associative -- `merge(merge(a, b), c)` equals `merge(a, b, c)`, `sources` included.
