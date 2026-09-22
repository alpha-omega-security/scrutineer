#!/usr/bin/env python3
"""Merge /reporting JSON exports from multiple discrete scanner instances.

Each input is the JSON export of one scrutineer instance's reporting page:

    curl -sSfOJ 'http://127.0.0.1:8080/reporting/report.json?interval=week'

Combining the exports of several instances that each scan their own set of
repositories yields one report in the same shape, as if a single instance
had scanned the whole corpus.

Usage (Python 3.9+, so macOS's stock python3 works):
    scripts/merge-reports.py report1.json report2.json ... [-o merged.json]
    scripts/merge-reports.py --severity medium reports/*.json > merged.json

Merge rules:
  - activity_by_day / activity_by_model: rows keyed by `date` / `model`.
    Rows present in only one source are copied unchanged. Rows present in
    several sources have their count fields summed and their `avg_*` fields
    weighted by `scans_averaged`.
  - activity_in_period: counts summed across all sources.
  - cost_averages_per_scan: `all_time` and `in_period` are weighted by
    `scans_averaged` across all sources.
  - filters: taken from the first file (a warning is printed if they differ).
  - generated_at / period: latest generated_at, earliest start, latest end;
    one unbounded source (interval=all, null starts_at) makes the merged
    start null.
  - sources: one entry per input file recording its original period.

A severity floor is applied at export time (?severity=medium on the URL)
and recorded in filters.minimum_severity; the export carries only
aggregated counts, so the floor cannot be re-applied here. --severity
medium asserts every input was exported with exactly that floor
(--severity all: with none), refusing an input whose laxer or stricter
floor would skew the merged findings counts.

The sums are only meaningful because the sources are DISCRETE instances
with disjoint corpora. Do not merge two exports of the same instance:
overlapping windows double-count scans, `repositories_scanned` (a distinct
count per source) double-counts repositories active in both, and the pooled
`all_time` averages double-count the older export's population, which the
newer one already contains. Inputs that look identical are warned about.
"""

# Lazy annotations keep the PEP 604 spellings below (`str | None`) from
# being evaluated on Python 3.9, where the union operator does not exist.
from __future__ import annotations

import argparse
import json
import sys
from collections import OrderedDict
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from typing import Any

WEIGHT_KEY = "scans_averaged"


def is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def zip_strict(*seqs: Sequence[Any]) -> Iterator[tuple[Any, ...]]:
    """zip(strict=True), which Python 3.9's zip does not accept yet.

    The zipped lists are built in lockstep, so unequal lengths mean a bug
    upstream that silent truncation would mask.
    """
    if len({len(s) for s in seqs}) > 1:
        raise ValueError("zip_strict: sequences differ in length")
    return zip(*seqs)


def merge_group(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    """Merge rows that share the same key value (e.g. same model)."""
    if len(rows) == 1:
        return rows[0]

    merged: dict[str, Any] = {key: rows[0][key]}

    # Union of fields in first-seen order, so a field that only newer
    # sources carry survives a merge with older exports.
    for field in dict.fromkeys(f for r in rows for f in r):
        if field == key:
            continue
        present = [r for r in rows if field in r]
        values = [r[field] for r in present]
        if not all(is_number(v) for v in values):
            merged[field] = values[0]
        elif field.startswith("avg_"):
            # Weight only over the rows that carry the field, so a source
            # predating it does not drag the average toward zero.
            weight = sum(r.get(WEIGHT_KEY, 0) for r in present)
            merged[field] = (
                sum(r[field] * r.get(WEIGHT_KEY, 0) for r in present) / weight
                if weight
                else 0
            )
        else:
            merged[field] = sum(values)

    return dict(sorted(merged.items()))


def merge_rows(rows: Iterable[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    groups: OrderedDict[Any, list[dict[str, Any]]] = OrderedDict()
    for row in rows:
        groups.setdefault(row[key], []).append(row)
    return [merge_group(group, key) for group in groups.values()]


def weighted_average(blocks: list[dict[str, Any]]) -> dict[str, Any]:
    """Weight every avg_* field by scans_averaged and sum the weights."""
    blocks = [b for b in blocks if b]
    if not blocks:
        return {}
    result: dict[str, Any] = {}
    for field in dict.fromkeys(f for b in blocks for f in b):
        if not field.startswith("avg_"):
            continue
        present = [b for b in blocks if field in b]
        weight = sum(b.get(WEIGHT_KEY, 0) for b in present)
        result[field] = (
            sum(b[field] * b.get(WEIGHT_KEY, 0) for b in present) / weight
            if weight
            else 0
        )
    result[WEIGHT_KEY] = sum(b.get(WEIGHT_KEY, 0) for b in blocks)
    return dict(sorted(result.items()))


def severity_error(
    reports: list[dict[str, Any]], names: list[str], floor: str
) -> str | None:
    """Explain why the inputs cannot honour the requested severity floor.

    The reporting endpoint applies the floor server-side (?severity=medium)
    and records it in filters.minimum_severity; the export carries only
    aggregated counts, so a floor cannot be re-applied here. A laxer input
    would overstate the merged findings counts and a stricter one would
    understate them, so anything but an exact match is refused.
    """
    want = floor.lower()
    if want != "all":
        # Validate the level against the first input that names the levels,
        # so a typo fails as "unknown" rather than as a per-file mismatch.
        for report in reports:
            ordering = (report.get("filters") or {}).get("severity_ordering") or []
            if ordering:
                if want not in (str(level).lower() for level in ordering):
                    levels = ", ".join(ordering)
                    return f"unknown severity {floor!r} (one of: {levels}, or all)"
                break
    for name, report in zip_strict(names, reports):
        recorded = (report.get("filters") or {}).get("minimum_severity")
        if want == "all":
            if recorded is None:
                continue
            return (
                f"{name} was exported with a minimum severity of {recorded!r}; "
                "--severity all requires unfiltered inputs"
            )
        if isinstance(recorded, str) and recorded.lower() == want:
            continue
        have = "no severity floor" if recorded is None else f"a {recorded!r} floor"
        return (
            f"{name} was exported with {have}; a merged {floor} report needs "
            f"every input exported with ?severity={want}"
        )
    return None


def merge_reports(reports: list[dict[str, Any]], names: list[str]) -> dict[str, Any]:
    first = reports[0]

    # Warn on metadata that is expected to be identical across sources.
    for path, report in zip_strict(names[1:], reports[1:]):
        if report.get("filters") != first.get("filters"):
            print(f"warning: filters in {path} differ from {names[0]}", file=sys.stderr)

    # Two inputs that agree on all three of these are almost certainly the
    # same export passed twice, and every figure would count double.
    fingerprints: dict[str, str] = {}
    for name, r in zip_strict(names, reports):
        fp = json.dumps(
            [r.get("generated_at"), r.get("period"), r.get("activity_in_period")],
            sort_keys=True,
        )
        if fp in fingerprints:
            print(
                f"warning: {name} and {fingerprints[fp]} have identical "
                "generated_at, period and totals -- duplicate input?",
                file=sys.stderr,
            )
        else:
            fingerprints[fp] = name

    by_day = merge_rows(
        (row for r in reports for row in r.get("activity_by_day", [])), "date"
    )
    by_day.sort(key=lambda row: row["date"], reverse=True)

    by_model = merge_rows(
        (row for r in reports for row in r.get("activity_by_model", [])), "model"
    )
    # Same order the reporting page uses: findings, then cost, then name.
    by_model.sort(
        key=lambda row: (
            -row.get("findings", 0),
            -row.get("cost_usd", 0),
            row["model"] or "",
        )
    )

    in_period: dict[str, Any] = {}
    for r in reports:
        for field, value in r.get("activity_in_period", {}).items():
            if is_number(value):
                in_period[field] = in_period.get(field, 0) + value
            else:
                in_period.setdefault(field, value)
    in_period = dict(sorted(in_period.items()))
    # A distinct count cannot be re-derived from aggregates, so the merged
    # figure is the per-source sum -- exact only for disjoint corpora.
    note = "repositories_scanned sums per-source distinct counts"
    measured_by = in_period.get("measured_by")
    if isinstance(measured_by, str) and note not in measured_by:
        in_period["measured_by"] = measured_by + "; " + note

    cost_blocks = [r.get("cost_averages_per_scan", {}) for r in reports]
    cost = {
        "all_time": weighted_average([c.get("all_time", {}) for c in cost_blocks]),
        "in_period": weighted_average([c.get("in_period", {}) for c in cost_blocks]),
    }
    population = next((c["population"] for c in cost_blocks if "population" in c), None)
    if population is not None:
        cost["population"] = population

    periods = [r.get("period", {}) for r in reports]
    period_keys = ", ".join(sorted({p.get("key", "?") for p in periods}))
    starts = [p.get("starts_at") for p in periods]

    return {
        "activity_by_day": by_day,
        "activity_by_model": by_model,
        "activity_in_period": in_period,
        "cost_averages_per_scan": cost,
        "filters": first.get("filters"),
        "generated_at": max(r["generated_at"] for r in reports),
        "period": {
            "ends_at": max(p["ends_at"] for p in periods),
            "key": "merged",
            "label": "Merged",
            "meaning": (
                f"union of {len(reports)} source reports (period keys: {period_keys}) "
                "assumed to come from discrete scanner instances with disjoint "
                "corpora; totals summed; rows present in more than one source "
                f"have averages weighted by {WEIGHT_KEY}; all_time averages "
                "pooled across sources"
            ),
            # interval=all exports carry a null starts_at; one unbounded
            # source makes the union unbounded.
            "starts_at": None if any(s is None for s in starts) else min(starts),
        },
        "sources": [
            {
                "file": name,
                "generated_at": r.get("generated_at"),
                "period_key": p.get("key"),
                "starts_at": p.get("starts_at"),
                "ends_at": p.get("ends_at"),
            }
            for name, r, p in zip_strict(names, reports, periods)
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Merge /reporting JSON exports from multiple discrete "
        "scanner instances."
    )
    parser.add_argument("files", nargs="+", type=Path, help="input JSON report files")
    parser.add_argument(
        "-o", "--output", type=Path, help="write result here (default: stdout)"
    )
    parser.add_argument(
        "--indent", type=int, default=2, help="JSON indent (default: 2)"
    )
    parser.add_argument(
        "--severity",
        metavar="LEVEL",
        help="require every input to carry this minimum-severity floor, e.g. medium "
        "(the ?severity= parameter the export was generated with), or 'all' to "
        "require unfiltered inputs; merged counts cannot be re-filtered, so a "
        "mismatching input is refused",
    )
    args = parser.parse_args()

    reports, names = [], []
    for path in args.files:
        try:
            with path.open() as fh:
                report = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: could not read {path}: {exc}", file=sys.stderr)
            return 1
        if (
            not isinstance(report, dict)
            or "generated_at" not in report
            or not isinstance(report.get("period"), dict)
            or "ends_at" not in report["period"]
        ):
            print(
                f"error: {path} does not look like a /reporting JSON export "
                "(expected an object with generated_at and period.ends_at)",
                file=sys.stderr,
            )
            return 1
        reports.append(report)
        # The path as given, not the basename: curl -OJ names every
        # instance's export identically, distinguished only by directory.
        names.append(str(path))

    if args.severity:
        problem = severity_error(reports, names, args.severity)
        if problem:
            print(f"error: {problem}", file=sys.stderr)
            return 1

    merged = merge_reports(reports, names)
    text = json.dumps(merged, indent=args.indent)

    if args.output:
        try:
            args.output.write_text(text + "\n")
        except OSError as exc:
            print(f"error: could not write {args.output}: {exc}", file=sys.stderr)
            return 1
    else:
        print(text)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
