// Command merge-reports combines /reporting JSON exports from several
// discrete scanner instances into one corpus-wide report.
//
// Each input is the JSON export of one scrutineer instance's reporting
// page:
//
//	curl -sSfOJ 'http://127.0.0.1:8080/reporting/report.json?interval=week'
//
// Combining the exports of several instances that each scan their own set
// of repositories yields one report in the same shape, as if a single
// instance had scanned the whole corpus:
//
//	go run ./scripts/merge-reports a/report.json b/report.json > merged.json
//	go run ./scripts/merge-reports -severity medium -o merged.json reports/*/report.json
//
// The shape and the merge rules live in internal/reporting, which the
// server's export is marshalled from, so the two cannot drift apart:
//
//   - activity_in_period: counts summed.
//   - activity_by_day / activity_by_model: rows keyed by date / model. Rows
//     present in one input only are copied unchanged; rows present in
//     several have their counts summed and their averages weighted by
//     scans_averaged.
//   - cost_averages_per_scan: in_period and all_time weighted by
//     scans_averaged across all inputs.
//   - filters: the first input's. minimum_severity becomes "mixed" when the
//     inputs' floors disagree, and each input's own floor is recorded under
//     sources.
//   - generated_at / period: latest generated_at, earliest start, latest
//     end; one unbounded input (interval=all) makes the merged start null.
//   - sources: one entry per original export, through any number of merges.
//
// Inputs exported over different windows (a week beside a month) are
// refused, since their in_period figures would pool two windows into one
// number true of neither; -allow-mixed-periods merges them with a warning.
// Inputs whose fields differ from this tool's report.json (an export from
// another scrutineer version) are refused before anything is merged.
//
// A severity floor is applied at export time (?severity=medium on the URL)
// and recorded in filters.minimum_severity; the export carries only
// aggregated counts, so the floor cannot be re-applied here. -severity
// medium asserts every input was exported with exactly that floor
// (-severity all: with none), refusing an input whose laxer or stricter
// floor would skew the merged findings counts. Levels are matched the way
// the export URL matches them, so moderate is accepted for medium.
//
// The sums are only meaningful because the sources are discrete instances
// with disjoint corpora. Do not merge two exports of the same instance:
// overlapping windows double-count scans, repositories_scanned (a distinct
// count per source) double-counts repositories active in both, and the
// pooled all_time averages double-count the older export's population,
// which the newer one already contains. Inputs that share their all-time
// averages, as two exports of one instance do, are warned about.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"scrutineer/internal/reporting"
)

const (
	exitOK    = 0
	exitError = 1
	// exitUsage matches flag.ExitOnError's usage-error exit code.
	exitUsage = 2

	outputPerm = 0o644
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main without the process: arguments in, exit status out, so the
// tests drive it in-process.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("merge-reports", flag.ContinueOnError)
	fs.SetOutput(stderr)
	output := fs.String("o", "", "write the merged report to this `file` instead of stdout")
	severity := fs.String("severity", "", "require every input to carry this minimum-severity `level`, "+
		"the ?severity= value it was exported with, or all for unfiltered inputs")
	allowMixed := fs.Bool("allow-mixed-periods", false, "merge inputs exported over different windows, with a warning")
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, "usage: go run ./scripts/merge-reports [-o merged.json] [-severity LEVEL] [-allow-mixed-periods] report.json...\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() == 0 {
		_, _ = fmt.Fprintln(stderr, "error: no input files")
		fs.Usage()
		return exitUsage
	}

	inputs := make([]reporting.Input, 0, fs.NArg())
	for _, path := range fs.Args() {
		export, err := readExport(path)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return exitError
		}
		// The path as given, not the basename: curl -OJ names every
		// instance's export identically, distinguished only by directory.
		inputs = append(inputs, reporting.Input{Name: path, Export: export})
	}

	merged, warnings, err := reporting.Merge(inputs, reporting.Options{Severity: *severity, AllowMixedPeriods: *allowMixed})
	for _, warning := range warnings {
		_, _ = fmt.Fprintf(stderr, "warning: %s\n", warning)
	}
	if err != nil {
		hint := ""
		if errors.Is(err, reporting.ErrMixedPeriods) {
			hint = "; pass -allow-mixed-periods to merge them anyway"
		}
		_, _ = fmt.Fprintf(stderr, "error: %v%s\n", err, hint)
		return exitError
	}

	text, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}
	text = append(text, '\n')
	if *output != "" {
		err = os.WriteFile(*output, text, outputPerm)
	} else {
		_, err = stdout.Write(text)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}
	return exitOK
}

// readExport decodes one input, naming it in any error: the OS already
// names the file in a read error, and Decode's messages are about the
// document, so the name is added to those.
func readExport(path string) (reporting.Export, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return reporting.Export{}, err
	}
	export, err := reporting.Decode(bytes.NewReader(raw))
	if err != nil {
		return reporting.Export{}, fmt.Errorf("%s: %w", path, err)
	}
	return export, nil
}
