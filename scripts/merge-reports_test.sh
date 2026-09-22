#!/usr/bin/env bash

set -euo pipefail

tests=0

fail() {
  printf 'not ok %s - %s\n' "$tests" "$1" >&2
  exit 1
}

assert_eq() {
  local expected=$1
  local actual=$2
  local label=$3
  tests=$((tests + 1))
  if [ "$actual" != "$expected" ]; then
    printf 'expected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
    fail "$label"
  fi
  printf 'ok %s - %s\n' "$tests" "$label"
}

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM

# Fixtures: two overlapping week exports from discrete instances (week_b
# carries a field week_a predates, plus a second model), an all-time export
# (null starts_at), and Medium-floor variants. Weights and averages are
# chosen so every weighted mean is an exact binary float, keeping the
# JSON-rendered expectations byte-stable.
python3 - "$TEST_DIR" <<'EOF'
import copy, json, os, sys

out = sys.argv[1]

base = {
    "generated_at": "2026-09-14T14:00:00Z",
    "period": {
        "key": "week",
        "label": "Week",
        "meaning": "rolling 7 days ending at generated_at",
        "starts_at": "2026-09-07T14:00:00Z",
        "ends_at": "2026-09-14T14:00:00Z",
    },
    "filters": {
        "minimum_severity": None,
        "applies_to": ["findings"],
        "severity_ordering": ["Low", "Medium", "High", "Critical"],
    },
    "activity_in_period": {
        "repositories_scanned": 3,
        "scans_started": 10,
        "scans_completed": 8,
        "findings": 5,
        "measured_by": "scans_started at started_at",
    },
    "cost_averages_per_scan": {
        "population": "completed scans with a recorded cost",
        "in_period": {"scans_averaged": 6, "avg_cost_usd": 2.0, "avg_total_tokens": 18.0},
        "all_time": {"scans_averaged": 100, "avg_cost_usd": 3.0, "avg_total_tokens": 18.0},
    },
    "activity_by_model": [
        {
            "model": "model-x",
            "scans_started": 10, "scans_completed": 8, "findings": 5,
            "cost_usd": 16.0, "total_tokens": 140,
            "scans_averaged": 6, "avg_cost_usd": 2.0, "avg_total_tokens": 18.0,
        }
    ],
    "activity_by_day": [
        {
            "date": "2026-09-14",
            "repositories_scanned": 2, "scans_started": 10, "scans_completed": 8,
            "findings": 5, "cost_usd": 16.0, "total_tokens": 140,
            "scans_averaged": 6, "avg_cost_usd": 2.0, "avg_total_tokens": 18.0,
        },
        {
            "date": "2026-09-12",
            "repositories_scanned": 1, "scans_started": 1, "scans_completed": 1,
            "findings": 0, "cost_usd": 1.0, "total_tokens": 10,
            "scans_averaged": 1, "avg_cost_usd": 1.0, "avg_total_tokens": 10.0,
        },
    ],
}

def write(name, report):
    with open(os.path.join(out, name), "w") as fh:
        json.dump(report, fh)

write("week_a.json", base)

b = copy.deepcopy(base)
b["generated_at"] = "2026-09-14T15:00:00Z"
b["period"].update(starts_at="2026-09-07T15:00:00Z", ends_at="2026-09-14T15:00:00Z")
b["activity_in_period"].update(
    repositories_scanned=1, scans_started=4, scans_completed=4, findings=20
)
b["cost_averages_per_scan"]["in_period"] = {
    "scans_averaged": 2, "avg_cost_usd": 4.0, "avg_total_tokens": 22.0,
}
b["cost_averages_per_scan"]["all_time"] = {
    "scans_averaged": 50, "avg_cost_usd": 6.0, "avg_total_tokens": 24.0,
}
b["activity_by_model"] = [
    {
        "model": "model-x",
        "scans_started": 4, "scans_completed": 4, "findings": 7,
        "cost_usd": 16.0, "total_tokens": 60,
        "scans_averaged": 2, "avg_cost_usd": 4.0, "avg_total_tokens": 22.0,
    },
    {
        "model": "model-y",
        "scans_started": 1, "scans_completed": 1, "findings": 13,
        "cost_usd": 0.5, "total_tokens": 5,
        "scans_averaged": 1, "avg_cost_usd": 0.5, "avg_total_tokens": 5.0,
    },
]
b["activity_by_day"] = [
    {
        "date": "2026-09-14",
        "repositories_scanned": 1, "scans_started": 4, "scans_completed": 4,
        "findings": 7, "cost_usd": 8.0, "total_tokens": 60,
        "scans_averaged": 2, "avg_cost_usd": 4.0, "avg_total_tokens": 22.0,
        "new_field": 42,
    },
    {
        "date": "2026-09-13",
        "repositories_scanned": 1, "scans_started": 1, "scans_completed": 1,
        "findings": 13, "cost_usd": 0.5, "total_tokens": 5,
        "scans_averaged": 1, "avg_cost_usd": 0.5, "avg_total_tokens": 5.0,
    },
]
write("week_b.json", b)

c = copy.deepcopy(base)
c["generated_at"] = "2026-09-21T09:00:00Z"
c["period"] = {
    "key": "all",
    "label": "All time",
    "meaning": "every scan and finding on record",
    "starts_at": None,
    "ends_at": "2026-09-21T09:00:00Z",
}
write("all_c.json", c)

for name, stamp in [
    ("medium_a.json", "2026-09-14T14:00:00Z"),
    ("medium_b.json", "2026-09-14T15:00:00Z"),
]:
    m = copy.deepcopy(base)
    m["generated_at"] = stamp
    m["filters"]["minimum_severity"] = "Medium"
    write(name, m)
EOF

# merge OUT EXPECTED_STATUS ARGS... runs the script, capturing stdout to
# $TEST_DIR/OUT and stderr to $TEST_DIR/stderr for the probes below.
merge() {
  local out=$1 expected=$2
  shift 2
  local status=0
  python3 "$root/scripts/merge-reports.py" "$@" \
    > "$TEST_DIR/$out" 2> "$TEST_DIR/stderr" || status=$?
  assert_eq "$expected" "$status" "$out: exit status"
}

# probe FILE PATH prints the JSON value at a dotted path (list indexes as
# name[0]), rendered with json.dumps so null/strings compare exactly.
probe() {
  python3 - "$TEST_DIR/$1" "$2" <<'EOF'
import json, sys
value = json.load(open(sys.argv[1]))
for part in sys.argv[2].split("."):
    name, bracket, index = part.partition("[")
    if name:
        value = value[name]
    if bracket:
        value = value[int(index.rstrip("]"))]
print(json.dumps(value))
EOF
}

stderr_hits() {
  grep -c -- "$1" "$TEST_DIR/stderr" || true
}

# Two overlapping week reports from discrete instances.
merge merged.json 0 "$TEST_DIR/week_a.json" "$TEST_DIR/week_b.json"
assert_eq 0 "$(stderr_hits 'warning:')" 'clean merge: no warnings'
assert_eq 14 "$(probe merged.json activity_in_period.scans_started)" 'period scans summed'
assert_eq 25 "$(probe merged.json activity_in_period.findings)" 'period findings summed'
assert_eq 4 "$(probe merged.json activity_in_period.repositories_scanned)" 'period repos summed'
assert_eq '"scans_started at started_at; repositories_scanned sums per-source distinct counts"' \
  "$(probe merged.json activity_in_period.measured_by)" 'distinct-count caveat appended'
assert_eq 14 "$(probe merged.json 'activity_by_day[0].scans_started')" 'shared day counts summed'
assert_eq 2.5 "$(probe merged.json 'activity_by_day[0].avg_cost_usd')" 'shared day avg cost weighted'
assert_eq 19.0 "$(probe merged.json 'activity_by_day[0].avg_total_tokens')" 'shared day avg tokens weighted'
assert_eq 42 "$(probe merged.json 'activity_by_day[0].new_field')" 'field known only to newer source survives'
assert_eq '"2026-09-13"' "$(probe merged.json 'activity_by_day[1].date')" 'day rows ordered newest first'
assert_eq '"2026-09-12"' "$(probe merged.json 'activity_by_day[2].date')" 'single-source day row kept'
assert_eq '"model-y"' "$(probe merged.json 'activity_by_model[0].model')" 'models ordered by findings before cost'
assert_eq 12 "$(probe merged.json 'activity_by_model[1].findings')" 'model findings summed'
assert_eq 2.5 "$(probe merged.json 'activity_by_model[1].avg_cost_usd')" 'model avg cost weighted'
assert_eq 2.5 "$(probe merged.json cost_averages_per_scan.in_period.avg_cost_usd)" 'in-period averages weighted'
assert_eq 8 "$(probe merged.json cost_averages_per_scan.in_period.scans_averaged)" 'in-period weights summed'
assert_eq 4.0 "$(probe merged.json cost_averages_per_scan.all_time.avg_cost_usd)" 'all-time averages pooled'
assert_eq 150 "$(probe merged.json cost_averages_per_scan.all_time.scans_averaged)" 'all-time weights summed'
assert_eq '"2026-09-07T14:00:00Z"' "$(probe merged.json period.starts_at)" 'earliest start kept'
assert_eq '"2026-09-14T15:00:00Z"' "$(probe merged.json period.ends_at)" 'latest end kept'
assert_eq '"2026-09-14T15:00:00Z"' "$(probe merged.json generated_at)" 'latest generated_at kept'
assert_eq '"merged"' "$(probe merged.json period.key)" 'merged period key'

# An interval=all source has a null starts_at; the union is unbounded.
merge all_merged.json 0 "$TEST_DIR/week_a.json" "$TEST_DIR/all_c.json"
assert_eq null "$(probe all_merged.json period.starts_at)" 'unbounded source makes merged start null'

# The same export twice would double every figure.
merge dup.json 0 "$TEST_DIR/week_a.json" "$TEST_DIR/week_a.json"
assert_eq 1 "$(stderr_hits 'duplicate input')" 'identical inputs warned about'

# Differing filters are merged (first file wins) but warned about.
merge mixed.json 0 "$TEST_DIR/week_a.json" "$TEST_DIR/medium_a.json"
assert_eq 1 "$(stderr_hits 'filters in')" 'differing filters warned about'

# Re-merging merged output stays associative and does not stack the caveat.
merge remerged.json 0 "$TEST_DIR/merged.json" "$TEST_DIR/all_merged.json"
assert_eq '"scans_started at started_at; repositories_scanned sums per-source distinct counts"' \
  "$(probe remerged.json activity_in_period.measured_by)" 're-merge keeps a single caveat'

# Inputs that are not reports fail cleanly, naming the file.
printf '[]' > "$TEST_DIR/junk.json"
merge junk_out.json 1 "$TEST_DIR/junk.json"
assert_eq 1 "$(stderr_hits 'does not look like')" 'non-report input rejected'
merge missing_out.json 1 "$TEST_DIR/nope.json"
assert_eq 1 "$(stderr_hits 'could not read')" 'missing input rejected'

# --severity requires every input to carry exactly the requested floor.
merge sev_ok.json 0 --severity medium "$TEST_DIR/medium_a.json" "$TEST_DIR/medium_b.json"
merge sev_case.json 0 --severity MEDIUM "$TEST_DIR/medium_a.json" "$TEST_DIR/medium_b.json"
merge sev_bad.json 1 --severity medium "$TEST_DIR/medium_a.json" "$TEST_DIR/week_a.json"
assert_eq 1 "$(stderr_hits 'week_a.json was exported with no severity floor')" 'laxer input refused by name'
merge sev_all_ok.json 0 --severity all "$TEST_DIR/week_a.json" "$TEST_DIR/week_b.json"
merge sev_all_bad.json 1 --severity all "$TEST_DIR/medium_a.json"
assert_eq 1 "$(stderr_hits 'requires unfiltered inputs')" 'filtered input refused for --severity all'
merge sev_unknown.json 1 --severity bananas "$TEST_DIR/week_a.json"
assert_eq 1 "$(stderr_hits 'unknown severity')" 'unknown level rejected'

# -o writes the file instead of stdout and is otherwise silent on success.
merge o_stdout.json 0 "$TEST_DIR/week_a.json" "$TEST_DIR/week_b.json" -o "$TEST_DIR/out.json"
assert_eq '"merged"' "$(probe out.json period.key)" '-o writes a parseable report'
assert_eq '' "$(cat "$TEST_DIR/o_stdout.json")" '-o leaves stdout empty'
assert_eq '' "$(cat "$TEST_DIR/stderr")" '-o prints nothing on success'

printf '1..%s\n' "$tests"
