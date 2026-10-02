package web

// /reporting is the corpus-wide reporting page: a running total of scan
// activity over a rolling window, alongside the cost and token averages
// that docs/cost_averages.sql computes from the command line.
//
// It deliberately overlaps /usage only on the averages. /usage answers
// "which skill costs what" by slicing cost per skill and per day; this
// page answers "what has the corpus done lately" and pairs that with the
// single-number averages, so the two can be read side by side. Both draw
// on the same cost_usd/*_tokens columns the worker writes.
//
// The cost averages are computed SQL-side so the GORM query maps clause
// for clause onto docs/cost_averages.sql, and so a growing corpus is not
// read into memory to be averaged. AVG/COUNT are standard SQL and survive
// the PostgreSQL driver swap internal/db documents.
//
// The day bucketing is the one thing done in Go: grouping by calendar day
// needs date()/strftime()/date_trunc, which differ per dialect and would
// pin this file to SQLite. /usage bins its days in Go for the same reason.

import (
	"encoding/csv"
	"fmt"
	"maps"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/reporting"
)

// reportDateLayout is the calendar-day key for the per-day breakdown. Days
// are UTC so a report generated in two timezones bucket-aligns.
const reportDateLayout = "2006-01-02"

// findingsField is the "findings" column name, shared by the CSV header
// and the JSON export's filters.applies_to and measured_by text. Named
// rather than repeated so the spellings cannot drift apart, and so this
// package's count of the bare literal stays under goconst's threshold. The
// JSON rows spell it in reporting.DayRow's and reporting.ModelRow's tags;
// TestReportingJSONMatchesCSVColumns holds those to the CSV header.
const findingsField = "findings"

// reportInterval is one selectable rolling window. Dur of 0 means all
// time. Rolling rather than calendar: the totals are a running figure, so
// they should not collapse to near-zero at midnight or on the 1st.
type reportInterval struct {
	Key   string
	Label string
	// Meaning spells the window out for the exports, where a bare "week"
	// leaves a reader guessing between a rolling 7 days and an ISO week.
	Meaning string
	Dur     time.Duration
}

const (
	reportDay   = 24 * time.Hour
	reportWeek  = 7 * reportDay
	reportMonth = 30 * reportDay
)

var reportIntervals = []reportInterval{
	{Key: "all", Label: "All time", Meaning: "every scan and finding on record"},
	{Key: "month", Label: "Month", Meaning: "rolling 30 days ending at generated_at", Dur: reportMonth},
	{Key: "week", Label: "Week", Meaning: "rolling 7 days ending at generated_at", Dur: reportWeek},
	{Key: "day", Label: "Day", Meaning: "rolling 24 hours ending at generated_at", Dur: reportDay},
}

// resolveReportInterval maps the ?interval query value to a window,
// defaulting to all time for anything unrecognised.
func resolveReportInterval(key string) reportInterval {
	for _, iv := range reportIntervals {
		if iv.Key == key {
			return iv
		}
	}
	return reportIntervals[0]
}

// reportSeverities lists the selectable minimum-severity thresholds, least
// severe first so the UI reads as a widening filter. Derived from
// db.SeverityLevels so a new level appears here automatically.
var reportSeverities = db.SeverityLevels

// resolveMinSeverity canonicalises the ?severity query value, returning ""
// (no filter) for anything unrecognised. displaySeverity folds the casing
// variants the corpus carries, so ?severity=critical works.
func resolveMinSeverity(v string) string {
	if v == "" {
		return ""
	}
	// displaySeverity folds the "CRITICAL"/"MODERATE" spellings the corpus
	// carries but not lowercase ones, and a query parameter is usually
	// typed lowercase, so upcase before asking.
	canonical := displaySeverity(strings.ToUpper(v))
	for _, level := range db.SeverityLevels {
		if level == canonical {
			return canonical
		}
	}
	return ""
}

// reportTotals is the running-total panel. ReposScanned counts distinct
// repositories with at least one run that began or ended in the window, so
// a repo rescanned ten times still counts once. ScansStarted and
// ScansCompleted are read on their own clocks (see reportActivitySQL), so
// they are not a total and a subset of it. Findings honours the severity
// filter; the scan counts do not, since severity is a property of findings
// only.
type reportTotals struct {
	ReposScanned   int
	ScansStarted   int
	ScansCompleted int
	Findings       int
}

// ScansPerRepo is the mean number of runs each repository with activity
// accounted for. Display-only: a reader seeing 510 runs against 49
// repositories needs the ratio to know the figure is a fan-out, not an
// inflated count. One repository scan enqueues a run per skill (see
// enqueueDiffRescanGroup), so this is normally well above 1. It can dip
// below 1 in a narrow window whose only activity for some repository was a
// run that had already started before the window opened, which is why the
// page renders it to one decimal rather than rounding to a bare "0".
//
// Deliberately a method rather than a field: it is derived presentation,
// and the exports build their payloads from the fields explicitly, so
// keeping it off the struct stops it leaking into the CSV or JSON.
func (t reportTotals) ScansPerRepo() float64 {
	if t.ReposScanned == 0 {
		return 0
	}
	return float64(t.ScansStarted) / float64(t.ReposScanned)
}

// CompletionRate is the completions in the window over the starts in it, as
// a 0..1 fraction for the pct template helper. Over all time that is the
// success rate, since every run that finished also started. Over a rolling
// window it is a throughput ratio and may exceed 1: the two figures are on
// different clocks, so a batch that began just before the window and
// finished inside it counts as completions with no matching starts.
func (t reportTotals) CompletionRate() float64 {
	if t.ScansStarted == 0 {
		return 0
	}
	return float64(t.ScansCompleted) / float64(t.ScansStarted)
}

// reportAverages is one column of the cost-averages table: the per-scan
// means from docs/cost_averages.sql. Runs is the denominator, exposed so a
// small-sample average is recognisable as one.
//
// The population matches that SQL exactly — completed scans with a
// recorded cost — so queued, running, failed and cancelled rows don't drag
// the figures toward zero. The severity filter does not apply: these
// average scans, not findings.
type reportAverages struct {
	Runs             int     `gorm:"column:runs"`
	CostUSD          float64 `gorm:"column:cost_usd"`
	InputTokens      float64 `gorm:"column:input_tokens"`
	OutputTokens     float64 `gorm:"column:output_tokens"`
	CacheReadTokens  float64 `gorm:"column:cache_read_tokens"`
	CacheWriteTokens float64 `gorm:"column:cache_write_tokens"`
	TotalTokens      float64 `gorm:"column:total_tokens"`
}

// reportDayRow is one row of the per-day breakdown. ScansAveraged is the
// day's completed-and-costed scan count — the denominator behind that
// day's averages, and the same population the period averages use.
type reportDayRow struct {
	Date           string
	ReposScanned   int
	ScansStarted   int
	ScansCompleted int
	Findings       int
	CostUSD        float64
	TotalTokens    int
	ScansAveraged  int
	AvgCostUSD     float64
	AvgTotalTokens float64
}

// reportModelRow is one row of the per-model breakdown: the same activity
// figures as a day row, attributed to a model instead of a date. Scan
// figures group by the scan row's model on the same clocks the totals use;
// findings group by Finding.Model — the model of the scan that *first
// produced* each finding, denormalized at create time — under the same
// created-at window and severity filter as the findings total. The two
// dimensions can legitimately disagree: a finding imported from another
// instance's sharing bundle carries the exporting instance's producing
// model, which may never have run a scan here, so its row shows findings
// against little or no local scan activity. Models sort by findings, then
// cost, so the page reads as "who is finding what" before "who is
// spending what". An empty Model groups the rows with no model
// attribution recorded: rows predating model recording, and findings
// from the deterministic importers (SARIF/CSV/markdown), whose
// synchronous import scan records no model — unlike the queued LLM
// ingest fallback, which does. The page labels it, the exports carry
// it as "".
type reportModelRow struct {
	Model          string
	ScansStarted   int
	ScansCompleted int
	Findings       int
	CostUSD        float64
	TotalTokens    int
	ScansAveraged  int
	AvgCostUSD     float64
	AvgTotalTokens float64
}

// reportData is the whole snapshot. The page render and both exports read
// from this one value, so no figure in a download can disagree with the
// screen it came from — a weaker promise than carrying the same columns,
// and the one that matters.
//
// The exports do carry more: each day's averages (scans_averaged,
// avg_cost_usd, avg_total_tokens) have no column in the daily table. The
// page shows the averages for the period as a whole instead, and a day's
// average is over a narrower population than the same row's Cost column —
// the completed-and-costed runs, not every run that spent — so putting the
// two side by side invites reading one as the other's mean. The daily table
// says so under its heading rather than leaving the difference to be found
// on download.
type reportData struct {
	Interval    reportInterval
	MinSeverity string
	Since       *time.Time
	Generated   time.Time
	Totals      reportTotals
	Period      reportAverages
	AllTime     reportAverages
	Days        []reportDayRow
	Models      []reportModelRow
}

// A scan row carries two nullable timestamps this report reads: started_at,
// stamped when the worker claims the job and the run begins, and finished_at,
// stamped when the run reaches a terminal state. Each figure is counted on
// the clock that recorded it — a start where started_at falls, a completion
// where finished_at falls.
//
// Neither is derived from created_at, which is only the enqueue time. A row
// that has sat in the queue since Tuesday has started nothing, and counting
// it as a start reports work that never ran.
//
// One consequence: a run spanning a window boundary contributes a start to
// one period and a completion to the next, so starts and completions are not
// a total and a subset of it and need not reconcile.
const (
	// reportActivitySQL keeps the rows that have begun or ended. A row still
	// queued has neither timestamp and nothing to attribute to a day.
	reportActivitySQL = "(started_at IS NOT NULL OR finished_at IS NOT NULL)"
	// reportWindowSQL bounds those rows to a rolling window. Either end
	// being inside is enough, so a run that began before the window and
	// finished within it is still read — inWindow then admits its
	// completion and rejects its start. Parenthesised so the disjunction
	// cannot bind loosely against the clauses ANDed alongside it.
	reportWindowSQL = "(started_at >= ? OR finished_at >= ?)"
)

// reportAveragesFor loads one column of the cost-averages table.
//
// The WHERE clause and the averaged expressions are a direct transcription
// of docs/cost_averages.sql: completed scans carrying a recorded cost, so
// queued, running, failed and cancelled rows don't drag the figures toward
// zero. since bounds the population to a rolling window; nil averages the
// whole corpus.
//
// The bound is on finished_at, the same clock the completion counts use, so
// the denominator here is exactly the completed runs the report attributes
// to the window. A done row without a finish timestamp cannot be placed on
// the timeline and so falls out of every bounded window.
//
// AVG over an empty set is NULL, which will not scan into a float64, so
// each average is coalesced to zero — matching the zeroed struct an empty
// corpus should produce. Rounding is left to the display layer: the SQL
// file's ROUND(AVG(cost_usd), 2) has no round(double precision, integer)
// overload on PostgreSQL and would not survive the driver swap.
func (s *Server) reportAveragesFor(since *time.Time) (reportAverages, error) {
	var out reportAverages
	q := s.DB.Model(&db.Scan{}).
		Select(`COUNT(*) AS runs,
			COALESCE(AVG(cost_usd), 0)            AS cost_usd,
			COALESCE(AVG(input_tokens), 0)        AS input_tokens,
			COALESCE(AVG(output_tokens), 0)       AS output_tokens,
			COALESCE(AVG(cache_read_tokens), 0)   AS cache_read_tokens,
			COALESCE(AVG(cache_write_tokens), 0)  AS cache_write_tokens,
			COALESCE(AVG(input_tokens + output_tokens + cache_read_tokens + cache_write_tokens), 0) AS total_tokens`).
		Where("status = ?", db.ScanDone).
		Where("cost_usd > 0")
	if since != nil {
		q = q.Where("finished_at >= ?", *since)
	}
	return out, q.Scan(&out).Error
}

// dayAccumulator gathers one calendar day's figures while the scan rows
// stream past, so the day breakdown costs one pass rather than a query
// per day.
type dayAccumulator struct {
	repos         map[uint]struct{}
	started       int
	completed     int
	findings      int
	cost          float64
	tokens        int
	averagedScans int
	averagedCost  float64
	averagedToken int
}

// modelAccumulator gathers one model's figures in the same streaming passes
// the day breakdown uses, so the per-model table costs no extra query. It
// carries no repos set: a per-model repository count would double-count a
// repository scanned under two models and the row has no column for it.
type modelAccumulator struct {
	started       int
	completed     int
	findings      int
	cost          float64
	tokens        int
	averagedScans int
	averagedCost  float64
	averagedToken int
}

// inWindow reports whether one of a scan's two timestamps falls inside the
// selected window. A nil timestamp is inside no window at all: a run that
// has not started, or not finished, has not reached that milestone yet and
// there is no day to put it on. The comparison mirrors reportWindowSQL's
// `>=`, so a row the query returned is attributed on exactly the same
// boundary the query used to select it.
func (d reportData) inWindow(t *time.Time) bool {
	if t == nil {
		return false
	}
	return d.Since == nil || !t.Before(*d.Since)
}

// buildReport assembles the snapshot for one interval and severity floor.
//
// Every read is checked. A failed query would otherwise leave this returning
// a report of zeros that is indistinguishable from a quiet week, and the
// exports would hand an operator that report as a file to archive.
//
// Both averages columns are aggregated in the database. Only the totals
// and the day breakdown need individual rows, and that read is bounded to
// the selected window and to the columns the report reads, so picking a
// narrower interval genuinely costs less rather than filtering a full
// table scan in memory.
func (s *Server) buildReport(iv reportInterval, minSeverity string) (reportData, error) {
	now := time.Now().UTC()
	data := reportData{Interval: iv, MinSeverity: minSeverity, Generated: now}
	if iv.Dur > 0 {
		since := now.Add(-iv.Dur)
		data.Since = &since
	}

	var err error
	if data.AllTime, err = s.reportAveragesFor(nil); err != nil {
		return data, fmt.Errorf("all-time cost averages: %w", err)
	}
	if data.Period, err = s.reportAveragesFor(data.Since); err != nil {
		return data, fmt.Errorf("cost averages for %s: %w", iv.Key, err)
	}

	days := map[string]*dayAccumulator{}
	at := func(day string) *dayAccumulator {
		acc := days[day]
		if acc == nil {
			acc = &dayAccumulator{repos: map[uint]struct{}{}}
			days[day] = acc
		}
		return acc
	}

	// A failed or still-running row is activity too, so unlike the averages
	// this read is not narrowed to completed scans — only to rows that have
	// begun or ended, which is every row that has anything to attribute.
	var scans []db.Scan
	sq := s.DB.Model(&db.Scan{}).
		Select("repository_id", "status", "model", "cost_usd", "input_tokens", "output_tokens",
			"cache_read_tokens", "cache_write_tokens", "started_at", "finished_at").
		Where(reportActivitySQL)
	if data.Since != nil {
		sq = sq.Where(reportWindowSQL, *data.Since, *data.Since)
	}
	if err := sq.Find(&scans).Error; err != nil {
		return data, fmt.Errorf("scan activity: %w", err)
	}

	models := map[string]*modelAccumulator{}
	mat := func(model string) *modelAccumulator {
		acc := models[model]
		if acc == nil {
			acc = &modelAccumulator{}
			models[model] = acc
		}
		return acc
	}

	repos := map[uint]struct{}{}
	// active marks a repository as having had scan activity on this day and
	// in the period overall. A repository counts once however many of its
	// runs touched the window.
	active := func(acc *dayAccumulator, repoID uint) {
		repos[repoID] = struct{}{}
		acc.repos[repoID] = struct{}{}
	}
	for _, sc := range scans {
		if data.inWindow(sc.StartedAt) {
			acc := at(sc.StartedAt.UTC().Format(reportDateLayout))
			data.Totals.ScansStarted++
			acc.started++
			mat(sc.Model).started++
			active(acc, sc.RepositoryID)
		}
		if !data.inWindow(sc.FinishedAt) {
			continue
		}
		acc := at(sc.FinishedAt.UTC().Format(reportDateLayout))
		macc := mat(sc.Model)
		active(acc, sc.RepositoryID)
		// A completion is a run that reached done. Failed, cancelled and
		// skipped runs stop here too, and their spend is counted below, but
		// counting them as completions would make the tile's success rate
		// read ~100% however many runs were failing, and would put this
		// figure at odds with the cost averages on the same page, whose
		// population is the completed-and-costed scans docs/cost_averages.sql
		// defines.
		if sc.Status == db.ScanDone {
			data.Totals.ScansCompleted++
			acc.completed++
			macc.completed++
		}
		// Spend lands on the finish day for any terminal status: the worker
		// writes the cost and token columns when a run finalises, so an
		// in-flight run has nothing to attribute yet and a failed one still
		// spent what it spent. Keeping it on this clock also means a day's
		// cost_usd and its avg_cost_usd count the same runs.
		tokens := sc.InputTokens + sc.OutputTokens + sc.CacheReadTokens + sc.CacheWriteTokens
		acc.cost += sc.CostUSD
		acc.tokens += tokens
		macc.cost += sc.CostUSD
		macc.tokens += tokens
		// Same population as reportAveragesFor, so a day's average and the
		// period average are the same measurement at two resolutions.
		if sc.Status == db.ScanDone && sc.CostUSD > 0 {
			acc.averagedScans++
			acc.averagedCost += sc.CostUSD
			acc.averagedToken += tokens
			macc.averagedScans++
			macc.averagedCost += sc.CostUSD
			macc.averagedToken += tokens
		}
	}
	data.Totals.ReposScanned = len(repos)

	// Findings are counted by creation time: a finding belongs to the
	// window it was first reported in, not to a later re-observation.
	type findingRow struct {
		CreatedAt time.Time
		Model     string
	}
	var found []findingRow
	fq := s.DB.Model(&db.Finding{}).Select("created_at", "model")
	if data.Since != nil {
		fq = fq.Where("created_at >= ?", *data.Since)
	}
	// severityOrder ranks the most severe lowest, so "at or above this
	// severity" is `<=`. Reusing that shared CASE keeps this filter from
	// ever disagreeing with the finding lists' ordering.
	if rank, ok := db.SeverityRank(minSeverity); ok {
		fq = fq.Where("("+severityOrder+") <= ?", rank)
	}
	if err := fq.Scan(&found).Error; err != nil {
		return data, fmt.Errorf("findings: %w", err)
	}
	for _, f := range found {
		data.Totals.Findings++
		at(f.CreatedAt.UTC().Format(reportDateLayout)).findings++
		mat(f.Model).findings++
	}

	data.Days = make([]reportDayRow, 0, len(days))
	for day, acc := range days {
		row := reportDayRow{
			Date:           day,
			ReposScanned:   len(acc.repos),
			ScansStarted:   acc.started,
			ScansCompleted: acc.completed,
			Findings:       acc.findings,
			CostUSD:        acc.cost,
			TotalTokens:    acc.tokens,
			ScansAveraged:  acc.averagedScans,
		}
		if acc.averagedScans > 0 {
			n := float64(acc.averagedScans)
			row.AvgCostUSD = acc.averagedCost / n
			row.AvgTotalTokens = float64(acc.averagedToken) / n
		}
		data.Days = append(data.Days, row)
	}
	sort.Slice(data.Days, func(i, j int) bool { return data.Days[i].Date > data.Days[j].Date })
	data.Models = modelRows(models)
	return data, nil
}

// modelRows assembles and orders the per-model breakdown from the streamed
// accumulators. Findings first, then cost, then name, so the table reads
// as "who is finding what" before "who is spending what".
func modelRows(models map[string]*modelAccumulator) []reportModelRow {
	rows := make([]reportModelRow, 0, len(models))
	for model, acc := range models {
		row := reportModelRow{
			Model:          model,
			ScansStarted:   acc.started,
			ScansCompleted: acc.completed,
			Findings:       acc.findings,
			CostUSD:        acc.cost,
			TotalTokens:    acc.tokens,
			ScansAveraged:  acc.averagedScans,
		}
		if acc.averagedScans > 0 {
			n := float64(acc.averagedScans)
			row.AvgCostUSD = acc.averagedCost / n
			row.AvgTotalTokens = float64(acc.averagedToken) / n
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Findings != b.Findings {
			return a.Findings > b.Findings
		}
		if a.CostUSD != b.CostUSD {
			return a.CostUSD > b.CostUSD
		}
		return a.Model < b.Model
	})
	return rows
}

// reportFromRequest builds the snapshot the request asks for. Shared by the
// page and both exports so a download can never disagree with the screen.
func (s *Server) reportFromRequest(r *http.Request) (reportData, error) {
	q := r.URL.Query()
	return s.buildReport(resolveReportInterval(q.Get("interval")), resolveMinSeverity(q.Get("severity")))
}

// reportOrError builds the snapshot or fails the request. Every caller has to
// answer before writing a byte of the response, so a broken read shows as a
// 500 rather than as a page or a download full of zeros.
func (s *Server) reportOrError(w http.ResponseWriter, r *http.Request) (reportData, bool) {
	data, err := s.reportFromRequest(r)
	if err != nil {
		s.Log.Error("build report", "err", err)
		http.Error(w, "report unavailable", http.StatusInternalServerError)
		return data, false
	}
	return data, true
}

func (s *Server) reporting(w http.ResponseWriter, r *http.Request) {
	data, ok := s.reportOrError(w, r)
	if !ok {
		return
	}
	s.render(w, r, "reporting.html", map[string]any{
		"Report":     data,
		"Intervals":  reportIntervals,
		"Severities": reportSeverities,
	})
}

// reportFilename names a download after the window it covers, so reports
// pulled on different days don't overwrite each other in a downloads dir.
func reportFilename(data reportData, ext string) string {
	return fmt.Sprintf("scrutineer-report-%s-%s.%s",
		data.Interval.Key, data.Generated.Format(reportDateLayout), ext)
}

func reportTimestamp(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

// severityFilterLabel names the active filter for the exports, where an
// empty string would read as "the filter is broken" rather than "off".
func severityFilterLabel(minSeverity string) string {
	if minSeverity == "" {
		return "all"
	}
	return minSeverity
}

// reportCSVHeader is the single header row of the CSV export.
//
// The export is one rectangular table with a uniform column count so that
// Excel, Numbers and pandas all open it as a single sheet. An earlier
// version emitted a summary block, a blank line and then the daily table;
// that is two tables in one file and spreadsheets render it as a ragged
// sheet. row_type instead distinguishes the summary rows from the daily
// ones, which also makes the file filterable and pivotable in place.
//
// period and minimum_severity repeat on every row so several exports can
// be concatenated into one sheet and still be told apart.
//
// model sits last so a consumer that still reads the original columns by
// position keeps getting them; it is filled only on row_type=model rows,
// where date and repositories_scanned stay empty (a model is not a day,
// and a per-model repository count would double-count repositories
// scanned under two models).
var reportCSVHeader = []string{
	"period", "minimum_severity", "row_type", "date",
	"repositories_scanned", "scans_started", "scans_completed", findingsField,
	"cost_usd", "total_tokens", "scans_averaged", "avg_cost_usd", "avg_total_tokens",
	"model",
}

func (s *Server) reportingCSV(w http.ResponseWriter, r *http.Request) {
	data, ok := s.reportOrError(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+reportFilename(data, "csv")+`"`)

	cw := csv.NewWriter(w)
	defer cw.Flush()

	period, severity := data.Interval.Key, severityFilterLabel(data.MinSeverity)
	num := func(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }
	// Columns are addressed by name, never by position. A partially filled
	// row (the all-time averages fill three of thirteen) would otherwise be
	// a run of anonymous "" literals that nobody — human or tool — can
	// recount safely, and dropping one silently shifts every later value
	// into its neighbour's column.
	row := func(rowType, date string, cells map[string]string) []string {
		values := map[string]string{
			"period":           period,
			"minimum_severity": severity,
			"row_type":         rowType,
			"date":             date,
		}
		maps.Copy(values, cells)
		return csvRecord(values)
	}

	_ = cw.Write(reportCSVHeader)
	// The period total leads: opened in a spreadsheet, the headline numbers
	// are the first thing under the header rather than below the daily rows.
	_ = cw.Write(row("period_total", "", map[string]string{
		"repositories_scanned": strconv.Itoa(data.Totals.ReposScanned),
		"scans_started":        strconv.Itoa(data.Totals.ScansStarted),
		"scans_completed":      strconv.Itoa(data.Totals.ScansCompleted),
		findingsField:          strconv.Itoa(data.Totals.Findings),
		"cost_usd":             num(sumDayCost(data.Days)),
		"total_tokens":         strconv.Itoa(sumDayTokens(data.Days)),
		"scans_averaged":       strconv.Itoa(data.Period.Runs),
		"avg_cost_usd":         num(data.Period.CostUSD),
		"avg_total_tokens":     num(data.Period.TotalTokens),
	}))
	// All-time averages are a different population from the selected
	// period, so only the average columns are filled: the activity columns
	// would otherwise imply an all-time total this report never computed.
	_ = cw.Write(row("all_time_average", "", map[string]string{
		"scans_averaged":   strconv.Itoa(data.AllTime.Runs),
		"avg_cost_usd":     num(data.AllTime.CostUSD),
		"avg_total_tokens": num(data.AllTime.TotalTokens),
	}))
	// The per-model rows sit with the summary rows, above the daily table:
	// they slice the same period total by model, not by day. An empty model
	// cell on a model row is real data — activity with no model attribution
	// recorded (deterministic imports, pre-model rows) — not an unfilled
	// column.
	for _, m := range data.Models {
		_ = cw.Write(row("model", "", map[string]string{
			"model":            csvGuardCell(m.Model),
			"scans_started":    strconv.Itoa(m.ScansStarted),
			"scans_completed":  strconv.Itoa(m.ScansCompleted),
			findingsField:      strconv.Itoa(m.Findings),
			"cost_usd":         num(m.CostUSD),
			"total_tokens":     strconv.Itoa(m.TotalTokens),
			"scans_averaged":   strconv.Itoa(m.ScansAveraged),
			"avg_cost_usd":     num(m.AvgCostUSD),
			"avg_total_tokens": num(m.AvgTotalTokens),
		}))
	}
	for _, d := range data.Days {
		_ = cw.Write(row("day", d.Date, map[string]string{
			"repositories_scanned": strconv.Itoa(d.ReposScanned),
			"scans_started":        strconv.Itoa(d.ScansStarted),
			"scans_completed":      strconv.Itoa(d.ScansCompleted),
			findingsField:          strconv.Itoa(d.Findings),
			"cost_usd":             num(d.CostUSD),
			"total_tokens":         strconv.Itoa(d.TotalTokens),
			"scans_averaged":       strconv.Itoa(d.ScansAveraged),
			"avg_cost_usd":         num(d.AvgCostUSD),
			"avg_total_tokens":     num(d.AvgTotalTokens),
		}))
	}
}

// csvGuardCell neutralises spreadsheet formula interpretation (CWE-1236)
// for a free-text CSV cell: a value starting with `=`, `+`, `-`, `@`, tab,
// or CR is evaluated by Excel/LibreOffice/Sheets even when quoted, so it
// gets a leading apostrophe, which spreadsheets render as a text marker.
// Every free-text column in a CSV export MUST pass through this — today
// that is only the model cell, whose value can arrive from an externally
// supplied sharing bundle (the ingest boundary also drops non-model-id
// values, but this sink defends itself). The numeric and enumerated
// columns are machine-formatted and deliberately not guarded: an
// apostrophe on a future negative number would corrupt real data.
func csvGuardCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// csvRecord renders one record in reportCSVHeader order. The result is
// always exactly as wide as the header, so no caller can make the sheet
// ragged; columns the caller did not set stay empty.
func csvRecord(values map[string]string) []string {
	rec := make([]string, len(reportCSVHeader))
	for i, column := range reportCSVHeader {
		rec[i] = values[column]
	}
	return rec
}

func sumDayCost(days []reportDayRow) float64 {
	var total float64
	for _, d := range days {
		total += d.CostUSD
	}
	return total
}

func sumDayTokens(days []reportDayRow) int {
	var total int
	for _, d := range days {
		total += d.TotalTokens
	}
	return total
}

// reportingJSON serves the snapshot as a reporting.Export. The shape is a
// Go type rather than a hand-built map so the merge tool under
// scripts/merge-reports reads exactly what this writes: a figure added to
// the export has to be added to the struct, and the struct makes it say how
// it merges.
func (s *Server) reportingJSON(w http.ResponseWriter, r *http.Request) {
	data, ok := s.reportOrError(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+reportFilename(data, "json")+`"`)
	writeJSON(w, http.StatusOK, reportExport(data))
}

// reportExport maps the snapshot onto the export contract. The slices are
// built non-nil so an empty breakdown exports as [] rather than null.
func reportExport(data reportData) reporting.Export {
	days := make([]reporting.DayRow, 0, len(data.Days))
	for _, d := range data.Days {
		days = append(days, reporting.DayRow{
			Date:           d.Date,
			ReposScanned:   d.ReposScanned,
			ScansStarted:   d.ScansStarted,
			ScansCompleted: d.ScansCompleted,
			Findings:       d.Findings,
			CostUSD:        d.CostUSD,
			TotalTokens:    d.TotalTokens,
			ScansAveraged:  d.ScansAveraged,
			AvgCostUSD:     d.AvgCostUSD,
			AvgTotalTokens: d.AvgTotalTokens,
		})
	}
	byModel := make([]reporting.ModelRow, 0, len(data.Models))
	for _, m := range data.Models {
		byModel = append(byModel, reporting.ModelRow{
			Model:          m.Model,
			ScansStarted:   m.ScansStarted,
			ScansCompleted: m.ScansCompleted,
			Findings:       m.Findings,
			CostUSD:        m.CostUSD,
			TotalTokens:    m.TotalTokens,
			ScansAveraged:  m.ScansAveraged,
			AvgCostUSD:     m.AvgCostUSD,
			AvgTotalTokens: m.AvgTotalTokens,
		})
	}
	period := reporting.Period{
		Key:     data.Interval.Key,
		Label:   data.Interval.Label,
		Meaning: data.Interval.Meaning,
		EndsAt:  data.Generated.Format(time.RFC3339),
	}
	if data.Since != nil {
		start := reportTimestamp(data.Since)
		period.StartsAt = &start
	}
	// null means unfiltered; the scan counts are never filtered by
	// severity, which belongs to findings alone.
	var minSeverity *string
	if data.MinSeverity != "" {
		minSeverity = &data.MinSeverity
	}
	return reporting.Export{
		GeneratedAt: data.Generated.Format(time.RFC3339),
		Period:      period,
		Filters: reporting.Filters{
			MinimumSeverity:  minSeverity,
			AppliesTo:        []string{findingsField},
			SeverityOrdering: db.SeverityLevels,
		},
		Activity: reporting.Activity{
			ReposScanned:   data.Totals.ReposScanned,
			ScansStarted:   data.Totals.ScansStarted,
			ScansCompleted: data.Totals.ScansCompleted,
			Findings:       data.Totals.Findings,
			// Starts and completions are read on different columns, so a run
			// spanning the boundary lands in one period as a start and the
			// next as a completion. Spelled out here because the two figures
			// look like a total and a subset of it and are not.
			MeasuredBy: "scans_started at started_at, scans_completed at finished_at on runs that reached done, " +
				findingsField + " at first report; queued runs are counted nowhere",
		},
		CostAverages: reporting.CostAverages{
			Population: "completed scans with a recorded cost",
			InPeriod:   exportAverages(data.Period),
			AllTime:    exportAverages(data.AllTime),
		},
		ByModel: byModel,
		ByDay:   days,
	}
}

func exportAverages(a reportAverages) reporting.Averages {
	return reporting.Averages{
		ScansAveraged:       a.Runs,
		AvgCostUSD:          a.CostUSD,
		AvgInputTokens:      a.InputTokens,
		AvgOutputTokens:     a.OutputTokens,
		AvgCacheReadTokens:  a.CacheReadTokens,
		AvgCacheWriteTokens: a.CacheWriteTokens,
		AvgTotalTokens:      a.TotalTokens,
	}
}
