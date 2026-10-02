// Package reporting is the contract of the /reporting JSON export: the
// shape of one instance's report.json, and the rules for folding several
// instances' exports into one.
//
// internal/web/reporting.go marshals Export, so the document a scrutineer
// serves and the document scripts/merge-reports reads are the same Go type.
// Each merged field carries a `merge` tag naming its rule beside the json
// tag naming it, and Merge refuses a field without one, so a figure added
// to the export later (a median, a rate) has to say how it merges before
// any merged report can carry it. Nothing here imports the database or the
// web server: the merge tool is a plain `go run` and stays stdlib-only.
package reporting

// Export is one /reporting/report.json document. A merged document has the
// same shape plus Sources, which names the exports it was folded from.
type Export struct {
	GeneratedAt string  `json:"generated_at"`
	Period      Period  `json:"period"`
	Filters     Filters `json:"filters"`
	// Activity is the running-total panel for the period.
	Activity Activity `json:"activity_in_period"`
	// CostAverages pairs the period's per-scan averages with the all-time
	// ones so the two can be read side by side.
	CostAverages CostAverages `json:"cost_averages_per_scan"`
	// ByModel slices the period total by model. Scan figures group by the
	// scan row's model on the same clocks as the totals; findings group by
	// the model that first produced each finding, which for bundle-imported
	// findings is the exporting instance's model. A "" model groups activity
	// with no model attribution recorded: deterministic imports and
	// pre-model rows.
	ByModel []ModelRow `json:"activity_by_model"`
	// ByDay slices the period total by UTC calendar day, newest first.
	ByDay []DayRow `json:"activity_by_day"`
	// Sources is present only on a merged export: one entry per original
	// export, however many merges deep it arrived through.
	Sources []Source `json:"sources,omitempty"`
}

// Period is the window a report covers. Timestamps are RFC 3339 strings
// rather than time.Time so the wire format stays exactly what the server
// wrote (second precision, UTC) through a decode and re-encode.
type Period struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	// Meaning spells the window out, where a bare "week" leaves a reader
	// guessing between a rolling 7 days and an ISO week.
	Meaning string `json:"meaning"`
	// StartsAt is null for an unbounded (interval=all) report.
	StartsAt *string `json:"starts_at"`
	EndsAt   string  `json:"ends_at"`
}

// Filters records the severity floor the report was exported under.
type Filters struct {
	// MinimumSeverity is null for an unfiltered export. A merged export
	// whose inputs disagreed carries MixedSeverity instead, so it can never
	// pass for an unfiltered one.
	MinimumSeverity *string `json:"minimum_severity"`
	// AppliesTo names the figures the floor filters: findings only. The
	// scan counts are never filtered by severity, which belongs to findings
	// alone.
	AppliesTo        []string `json:"applies_to"`
	SeverityOrdering []string `json:"severity_ordering"`
}

// MixedSeverity is the minimum_severity a merged export records when its
// inputs were exported under different floors. The counts then mix inputs
// filtered at different levels, so no single floor is true of them, and a
// distinct marker (rather than null, which means unfiltered) keeps a later
// merge from mistaking the file for an unfiltered one. Each input's own
// floor is recorded in its Source entry.
const MixedSeverity = "mixed"

// Activity is the period's running totals. ReposScanned counts distinct
// repositories with at least one run that began or ended in the window, so
// a repo rescanned ten times still counts once. ScansStarted and
// ScansCompleted are read on their own clocks (a start where started_at
// falls, a completion where finished_at falls), so they are not a total and
// a subset of it; MeasuredBy says so for the reader of an archived file.
type Activity struct {
	// ReposScanned is a distinct count, which cannot be re-derived from
	// aggregates: the merged figure is the per-source sum, exact only for
	// disjoint corpora. Merge says so in MeasuredBy.
	ReposScanned   int    `json:"repositories_scanned" merge:"sum"`
	ScansStarted   int    `json:"scans_started" merge:"sum"`
	ScansCompleted int    `json:"scans_completed" merge:"sum"`
	Findings       int    `json:"findings" merge:"sum"`
	MeasuredBy     string `json:"measured_by" merge:"first"`
}

// CostAverages is the cost-averages table: the per-scan means for the
// period beside the same means over all time.
type CostAverages struct {
	// Population names the denominator both columns share: completed
	// scans with a recorded cost, so queued, running, failed and cancelled
	// rows don't drag the figures toward zero.
	Population string   `json:"population"`
	InPeriod   Averages `json:"in_period"`
	AllTime    Averages `json:"all_time"`
}

// Averages is one column of the cost-averages table. ScansAveraged is the
// denominator, exposed so a small-sample average is recognisable as one,
// and the weight every Avg* field is pooled by when columns are merged:
// Σ(avg × scans_averaged) / Σ scans_averaged is exactly the mean a single
// instance would have computed over the union of the populations.
type Averages struct {
	ScansAveraged       int     `json:"scans_averaged" merge:"weight"`
	AvgCostUSD          float64 `json:"avg_cost_usd" merge:"mean"`
	AvgInputTokens      float64 `json:"avg_input_tokens" merge:"mean"`
	AvgOutputTokens     float64 `json:"avg_output_tokens" merge:"mean"`
	AvgCacheReadTokens  float64 `json:"avg_cache_read_tokens" merge:"mean"`
	AvgCacheWriteTokens float64 `json:"avg_cache_write_tokens" merge:"mean"`
	AvgTotalTokens      float64 `json:"avg_total_tokens" merge:"mean"`
}

// DayRow is one UTC calendar day of the period. ScansAveraged is the day's
// completed-and-costed scan count: the denominator behind the day's
// averages, and the same population the period averages use. A day's
// average is over a narrower population than the same row's CostUSD (the
// completed-and-costed runs, not every run that spent), so the two must not
// be read as a total and its mean.
type DayRow struct {
	Date           string  `json:"date" merge:"key"`
	ReposScanned   int     `json:"repositories_scanned" merge:"sum"`
	ScansStarted   int     `json:"scans_started" merge:"sum"`
	ScansCompleted int     `json:"scans_completed" merge:"sum"`
	Findings       int     `json:"findings" merge:"sum"`
	CostUSD        float64 `json:"cost_usd" merge:"sum"`
	TotalTokens    int     `json:"total_tokens" merge:"sum"`
	ScansAveraged  int     `json:"scans_averaged" merge:"weight"`
	AvgCostUSD     float64 `json:"avg_cost_usd" merge:"mean"`
	AvgTotalTokens float64 `json:"avg_total_tokens" merge:"mean"`
}

// ModelRow is one model's share of the period: the same figures as a
// DayRow attributed to a model instead of a date, minus the repository
// count, which would double-count a repository scanned under two models.
type ModelRow struct {
	Model          string  `json:"model" merge:"key"`
	ScansStarted   int     `json:"scans_started" merge:"sum"`
	ScansCompleted int     `json:"scans_completed" merge:"sum"`
	Findings       int     `json:"findings" merge:"sum"`
	CostUSD        float64 `json:"cost_usd" merge:"sum"`
	TotalTokens    int     `json:"total_tokens" merge:"sum"`
	ScansAveraged  int     `json:"scans_averaged" merge:"weight"`
	AvgCostUSD     float64 `json:"avg_cost_usd" merge:"mean"`
	AvgTotalTokens float64 `json:"avg_total_tokens" merge:"mean"`
}

// Source records one original export inside a merged one: the file it was
// read from (the path as given, since curl -OJ names every instance's
// export identically and only the directory tells them apart), and the
// window and severity floor it was exported under, which the merged
// period and filters can no longer state individually.
type Source struct {
	File            string  `json:"file"`
	GeneratedAt     string  `json:"generated_at"`
	MinimumSeverity *string `json:"minimum_severity"`
	PeriodKey       string  `json:"period_key"`
	StartsAt        *string `json:"starts_at"`
	EndsAt          string  `json:"ends_at"`
}
