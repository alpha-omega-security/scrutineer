package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/reporting"
)

// The merge rules themselves are covered in internal/reporting, and the
// real-export test in internal/web holds them to the server's output. This
// file covers the command around them: arguments, files, exit statuses
// and what reaches stdout and stderr.

func ptr(s string) *string { return &s }

// weekExport is one instance's rolling-week export, with the figures
// scaled by n so two instances' files differ in every number.
func weekExport(n int, stamp string, floor *string) reporting.Export {
	start := strings.Replace(stamp, "-14T", "-07T", 1)
	return reporting.Export{
		GeneratedAt: stamp,
		Period:      reporting.Period{Key: "week", Label: "Week", Meaning: "rolling 7 days ending at generated_at", StartsAt: &start, EndsAt: stamp},
		Filters: reporting.Filters{
			MinimumSeverity:  floor,
			AppliesTo:        []string{"findings"},
			SeverityOrdering: []string{"Low", "Medium", "High", "Critical"},
		},
		Activity: reporting.Activity{ReposScanned: n, ScansStarted: 10 * n, ScansCompleted: 8 * n, Findings: 5 * n, MeasuredBy: "scans_started at started_at"},
		CostAverages: reporting.CostAverages{
			Population: "completed scans with a recorded cost",
			InPeriod:   reporting.Averages{ScansAveraged: 6 * n, AvgCostUSD: 2, AvgTotalTokens: 18},
			AllTime:    reporting.Averages{ScansAveraged: 100 * n, AvgCostUSD: 3, AvgTotalTokens: 18},
		},
		ByModel: []reporting.ModelRow{{Model: "model-x", ScansStarted: 10 * n, ScansCompleted: 8 * n, Findings: 5 * n,
			CostUSD: 16, TotalTokens: 140, ScansAveraged: 6 * n, AvgCostUSD: 2, AvgTotalTokens: 18}},
		ByDay: []reporting.DayRow{{Date: "2026-09-14", ReposScanned: n, ScansStarted: 10 * n, ScansCompleted: 8 * n, Findings: 5 * n,
			CostUSD: 16, TotalTokens: 140, ScansAveraged: 6 * n, AvgCostUSD: 2, AvgTotalTokens: 18}},
	}
}

func allTimeExport() reporting.Export {
	e := weekExport(3, "2026-09-21T09:00:00Z", nil)
	e.Period = reporting.Period{Key: "all", Label: "All time", Meaning: "every scan and finding on record", EndsAt: e.GeneratedAt}
	return e
}

func writeJSON(t *testing.T, dir, name string, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type fixtures struct {
	weekA, weekB, all, mediumA, mediumB, junk string
}

func writeFixtures(t *testing.T) fixtures {
	t.Helper()
	dir := t.TempDir()
	return fixtures{
		weekA:   writeJSON(t, dir, "week_a.json", weekExport(1, "2026-09-14T14:00:00Z", nil)),
		weekB:   writeJSON(t, dir, "week_b.json", weekExport(2, "2026-09-14T15:00:00Z", nil)),
		all:     writeJSON(t, dir, "all_c.json", allTimeExport()),
		mediumA: writeJSON(t, dir, "medium_a.json", weekExport(4, "2026-09-14T14:00:00Z", ptr("Medium"))),
		mediumB: writeJSON(t, dir, "medium_b.json", weekExport(5, "2026-09-14T15:00:00Z", ptr("Medium"))),
		junk:    writeJSON(t, dir, "junk.json", []int{}),
	}
}

// merge runs the command and decodes a successful merge from stdout.
func merge(t *testing.T, args ...string) (merged reporting.Export, stdout, stderr string, status int) {
	t.Helper()
	var out, errOut bytes.Buffer
	status = run(args, &out, &errOut)
	if status == exitOK && out.Len() > 0 {
		var err error
		if merged, err = reporting.Decode(bytes.NewReader(out.Bytes())); err != nil {
			t.Fatalf("stdout is not a decodable export: %v\n%s", err, out.String())
		}
	}
	return merged, out.String(), errOut.String(), status
}

func TestMergeCommand(t *testing.T) {
	f := writeFixtures(t)

	merged, stdout, stderr, status := merge(t, f.weekA, f.weekB)
	if status != exitOK || stderr != "" {
		t.Fatalf("status %d, stderr %q", status, stderr)
	}
	if merged.Period.Key != "merged" || merged.Activity.ScansStarted != 30 || merged.CostAverages.InPeriod.ScansAveraged != 18 {
		t.Errorf("merged = %+v", merged)
	}
	if len(merged.Sources) != 2 || merged.Sources[0].File != f.weekA || merged.Sources[1].File != f.weekB {
		t.Errorf("sources name the paths as given: %+v", merged.Sources)
	}
	if !strings.HasSuffix(stdout, "}\n") || !strings.Contains(stdout, "\n  \"generated_at\"") {
		t.Errorf("stdout should be indented JSON ending in a newline: %q", stdout)
	}
}

func TestMergeCommandWritesOutputFile(t *testing.T) {
	f := writeFixtures(t)
	out := filepath.Join(t.TempDir(), "merged.json")

	_, stdout, stderr, status := merge(t, "-o", out, f.weekA, f.weekB)
	if status != exitOK || stdout != "" || stderr != "" {
		t.Fatalf("status %d, stdout %q, stderr %q; -o should leave both empty on success", status, stdout, stderr)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	written, err := reporting.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("output file: %v", err)
	}
	if written.Period.Key != "merged" || !bytes.HasSuffix(raw, []byte("\n")) {
		t.Errorf("output file = %q", raw)
	}

	// Re-merging the written file works and keeps the original sources.
	remerged, _, _, status := merge(t, out, f.mediumB)
	if status != exitOK || len(remerged.Sources) != 3 || remerged.Sources[0].File != f.weekA {
		t.Errorf("status %d, sources %+v", status, remerged.Sources)
	}
}

func TestMergeCommandFailures(t *testing.T) {
	f := writeFixtures(t)
	for _, tc := range []struct {
		name       string
		args       []string
		wantStatus int
		wantErr    string
	}{
		{"no inputs", nil, exitUsage, "no input files"},
		{"unknown flag", []string{"-bogus", f.weekA}, exitUsage, "flag provided but not defined: -bogus"},
		{"missing file", []string{filepath.Join(t.TempDir(), "nope.json")}, exitError, "nope.json"},
		{"not a report", []string{f.junk}, exitError, "junk.json: not a /reporting JSON export"},
		{"laxer input under a floor", []string{"-severity", "medium", f.mediumA, f.weekA}, exitError,
			"week_a.json was exported with no severity floor"},
		{"filtered input under all", []string{"-severity", "all", f.mediumA}, exitError, "unfiltered merge needs unfiltered inputs"},
		{"unknown level", []string{"-severity", "bananas", f.weekA}, exitError, `unknown severity "bananas"`},
		{"mixed periods", []string{f.weekA, f.all}, exitError, "pass -allow-mixed-periods to merge them anyway"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, stdout, stderr, status := merge(t, tc.args...)
			if status != tc.wantStatus {
				t.Errorf("status = %d, want %d; stderr %q", status, tc.wantStatus, stderr)
			}
			if !strings.Contains(stderr, tc.wantErr) {
				t.Errorf("stderr = %q, want it to mention %q", stderr, tc.wantErr)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want nothing on failure", stdout)
			}
		})
	}
}

func TestMergeCommandOptions(t *testing.T) {
	f := writeFixtures(t)

	t.Run("severity accepts what the export URL accepts", func(t *testing.T) {
		for _, level := range []string{"medium", "MEDIUM", "moderate"} {
			merged, _, stderr, status := merge(t, "-severity", level, f.mediumA, f.mediumB)
			if status != exitOK || stderr != "" {
				t.Errorf("-severity %s: status %d, stderr %q", level, status, stderr)
			}
			if merged.Filters.MinimumSeverity == nil || *merged.Filters.MinimumSeverity != "Medium" {
				t.Errorf("-severity %s: minimum_severity = %v, want Medium kept", level, merged.Filters.MinimumSeverity)
			}
		}
		if _, _, stderr, status := merge(t, "-severity", "all", f.weekA, f.weekB); status != exitOK || stderr != "" {
			t.Errorf("-severity all on unfiltered inputs: status %d, stderr %q", status, stderr)
		}
	})

	t.Run("allow mixed periods", func(t *testing.T) {
		merged, _, stderr, status := merge(t, "-allow-mixed-periods", f.weekA, f.all)
		if status != exitOK || !strings.Contains(stderr, "warning: inputs cover different windows") {
			t.Fatalf("status %d, stderr %q", status, stderr)
		}
		if merged.Period.StartsAt != nil {
			t.Errorf("starts_at = %q, want null with an unbounded input", *merged.Period.StartsAt)
		}
	})

	t.Run("disagreeing floors warn and are marked", func(t *testing.T) {
		merged, _, stderr, status := merge(t, f.mediumA, f.weekA)
		if status != exitOK || !strings.Contains(stderr, "warning: filters in") {
			t.Fatalf("status %d, stderr %q", status, stderr)
		}
		if merged.Filters.MinimumSeverity == nil || *merged.Filters.MinimumSeverity != reporting.MixedSeverity {
			t.Errorf("minimum_severity = %v, want %q", merged.Filters.MinimumSeverity, reporting.MixedSeverity)
		}
	})

	t.Run("duplicate input warns", func(t *testing.T) {
		if _, _, stderr, status := merge(t, f.weekA, f.weekA); status != exitOK || !strings.Contains(stderr, "two exports of the same instance?") {
			t.Errorf("status %d, stderr %q", status, stderr)
		}
	})

	t.Run("help", func(t *testing.T) {
		if _, _, stderr, status := merge(t, "-h"); status != exitOK || !strings.Contains(stderr, "usage: go run ./scripts/merge-reports") {
			t.Errorf("status %d, stderr %q", status, stderr)
		}
	})
}
