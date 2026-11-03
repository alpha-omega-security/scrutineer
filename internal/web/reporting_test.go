package web

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
)

// seedReportCorpus lays down scans and findings either side of the rolling
// window boundaries so each interval selects a known subset:
//
//	repo 1: one costed scan 2h ago, one costed scan 3 days ago
//	repo 2: one costed scan 10 days ago
//	repo 3: one costed scan 100 days ago, plus a failed and a queued scan
//
// Day sees repo 1 only; week sees repos 1-2; month adds nothing further;
// all time adds repo 3. Findings carry three different severities so the
// minimum-severity filter has something to bite on.
// mustBuildReport fails the test rather than letting a query error return a
// zeroed report that would then be asserted against as though it were data.
func mustBuildReport(t *testing.T, s *Server, iv reportInterval, minSeverity string) reportData {
	t.Helper()
	data, err := s.buildReport(iv, minSeverity)
	if err != nil {
		t.Fatalf("buildReport(%s, %q): %v", iv.Key, minSeverity, err)
	}
	return data
}

func seedReportCorpus(t *testing.T, s *Server) {
	t.Helper()
	now := time.Now().UTC()
	mkRepo := func(name string) db.Repository {
		repo := db.Repository{URL: "https://example.test/" + name, Name: name, FullName: "acme/" + name}
		if err := s.DB.Create(&repo).Error; err != nil {
			t.Fatal(err)
		}
		return repo
	}
	r1, r2, r3 := mkRepo("one"), mkRepo("two"), mkRepo("three")

	// mkScan seeds a terminal run that finished `ago` before now, having
	// started a few minutes earlier so both ends land in the same window.
	// created_at sits before the start, as an enqueue always does, so any
	// code reaching for it instead of started_at buckets the row wrong.
	const ranFor = 5 * time.Minute
	mkScan := func(repo db.Repository, status db.ScanStatus, cost float64, in, out, cr, cw int, ago time.Duration) db.Scan {
		finished := now.Add(-ago)
		started := finished.Add(-ranFor)
		sc := db.Scan{
			RepositoryID: repo.ID, Kind: "skill", Status: status, SkillName: "vuln-scan",
			Model:   "model-a",
			CostUSD: cost, InputTokens: in, OutputTokens: out,
			CacheReadTokens: cr, CacheWriteTokens: cw,
			StartedAt: &started, FinishedAt: &finished, CreatedAt: started.Add(-time.Minute),
		}
		if err := s.DB.Create(&sc).Error; err != nil {
			t.Fatal(err)
		}
		return sc
	}

	inWindow := mkScan(r1, db.ScanDone, 2.00, 100, 10, 1000, 50, 2*time.Hour)
	mkScan(r1, db.ScanDone, 4.00, 300, 30, 3000, 150, 3*reportDay)
	mkScan(r2, db.ScanDone, 6.00, 200, 20, 2000, 100, 10*reportDay)
	mkScan(r3, db.ScanDone, 8.00, 400, 40, 4000, 200, 100*reportDay)
	// A failed run is a start and a spend but never a completion, so it
	// moves the scan totals without touching the averages.
	mkScan(r3, db.ScanFailed, 1.00, 10, 1, 10, 1, time.Hour)

	// A queued run has neither timestamp: it is enqueued work, not scan
	// activity, and must be counted in no window. A running one has only a
	// start, and is counted as one.
	mkPending := func(repo db.Repository, status db.ScanStatus, startedAgo time.Duration) {
		// A second model, so the by-model breakdown has something to group:
		// the running row contributes one start under model-b and nothing
		// else, while every terminal row above is model-a.
		sc := db.Scan{
			RepositoryID: repo.ID, Kind: "skill", Status: status, SkillName: "vuln-scan",
			Model:     "model-b",
			CreatedAt: now.Add(-time.Hour),
		}
		if startedAgo > 0 {
			started := now.Add(-startedAgo)
			sc.StartedAt = &started
		}
		if err := s.DB.Create(&sc).Error; err != nil {
			t.Fatal(err)
		}
	}
	mkPending(r3, db.ScanQueued, 0)
	mkPending(r2, db.ScanRunning, 30*time.Minute)

	recent := now.Add(-2 * time.Hour)
	old := now.Add(-100 * reportDay)
	for _, f := range []struct {
		severity string
		at       time.Time
	}{
		{"Critical", recent},
		{"Low", recent},
		{"High", old},
	} {
		row := db.Finding{
			RepositoryID: r1.ID, ScanID: inWindow.ID, Title: "x",
			Model:    "model-a",
			Severity: f.severity, CreatedAt: f.at,
		}
		if err := s.DB.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func TestResolveReportInterval(t *testing.T) {
	for _, tc := range []struct {
		key  string
		want string
		dur  time.Duration
	}{
		{"day", "day", reportDay},
		{"week", "week", reportWeek},
		{"month", "month", reportMonth},
		{"all", "all", 0},
		{"", "all", 0},
		{"fortnight", "all", 0},
	} {
		got := resolveReportInterval(tc.key)
		if got.Key != tc.want || got.Dur != tc.dur {
			t.Errorf("resolveReportInterval(%q) = %q/%v, want %q/%v", tc.key, got.Key, got.Dur, tc.want, tc.dur)
		}
	}
}

func TestResolveMinSeverity(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Critical", "Critical"},
		{"critical", "Critical"},
		{"CRITICAL", "Critical"},
		{"MODERATE", "Medium"},
		{"Low", "Low"},
		{"", ""},
		{"catastrophic", ""},
		// Not a severity: must not leak through as a filter value.
		{"'; DROP TABLE findings; --", ""},
	} {
		if got := resolveMinSeverity(tc.in); got != tc.want {
			t.Errorf("resolveMinSeverity(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// minSeverityRank must agree with severityOrder, which ranks the most
// severe lowest. If these drift, the filter silently selects the wrong end
// of the scale.
func TestBuildReportIntervalTotals(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	for _, tc := range []struct {
		interval                                       string
		repos, started, done, findings, costedInWindow int
	}{
		// Day: repo 1's 2h run, repo 3's failed run and repo 2's running
		// one all started inside it; only repo 1's reached done. The queued
		// row is not activity and is counted nowhere.
		{"day", 3, 3, 1, 2, 1},
		// Week: adds repo 1's 3-day run; repo 2's 10-day one is out.
		{"week", 3, 4, 2, 2, 2},
		// Month: adds repo 2's 10-day run.
		{"month", 3, 5, 3, 2, 3},
		// All time: adds repo 3's 100-day run and the old finding.
		{"all", 3, 6, 4, 3, 4},
	} {
		t.Run(tc.interval, func(t *testing.T) {
			got := mustBuildReport(t, s, resolveReportInterval(tc.interval), "")
			if got.Totals.ReposScanned != tc.repos {
				t.Errorf("ReposScanned = %d, want %d", got.Totals.ReposScanned, tc.repos)
			}
			if got.Totals.ScansStarted != tc.started {
				t.Errorf("ScansStarted = %d, want %d", got.Totals.ScansStarted, tc.started)
			}
			if got.Totals.ScansCompleted != tc.done {
				t.Errorf("ScansCompleted = %d, want %d", got.Totals.ScansCompleted, tc.done)
			}
			if got.Totals.Findings != tc.findings {
				t.Errorf("Findings = %d, want %d", got.Totals.Findings, tc.findings)
			}
			if got.Period.Runs != tc.costedInWindow {
				t.Errorf("Period.Runs = %d, want %d", got.Period.Runs, tc.costedInWindow)
			}
			// The all-time column never moves with the selector.
			if got.AllTime.Runs != 4 {
				t.Errorf("AllTime.Runs = %d, want 4", got.AllTime.Runs)
			}
		})
	}
}

// A start is read from started_at and a completion from finished_at, so a
// run spanning a window boundary belongs to two different periods and a run
// still on the queue belongs to none. created_at is only the enqueue time
// and must not stand in for either.
func TestBuildReportCountsRunsOnTheirOwnClock(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	now := time.Now().UTC()

	mkRepo := func(name string) db.Repository {
		repo := db.Repository{URL: "https://example.test/" + name, Name: name, FullName: "acme/" + name}
		if err := s.DB.Create(&repo).Error; err != nil {
			t.Fatal(err)
		}
		return repo
	}
	mkScan := func(repo db.Repository, status db.ScanStatus, cost float64, started, finished *time.Time) {
		sc := db.Scan{
			RepositoryID: repo.ID, Kind: "skill", Status: status, SkillName: "vuln-scan",
			CostUSD: cost, StartedAt: started, FinishedAt: finished,
			// Enqueued 40 hours ago: outside the day window but inside the
			// week, so counting rows by created_at would show up here.
			CreatedAt: now.Add(-40 * time.Hour),
		}
		if err := s.DB.Create(&sc).Error; err != nil {
			t.Fatal(err)
		}
	}
	began, ended, running := now.Add(-30*time.Hour), now.Add(-2*time.Hour), now.Add(-30*time.Minute)
	// Began before the day window and finished inside it.
	mkScan(mkRepo("straddler"), db.ScanDone, 3.00, &began, &ended)
	// Began inside the day window and has not finished.
	mkScan(mkRepo("inflight"), db.ScanRunning, 0, &running, nil)
	// Enqueued and never claimed: no timestamps, no activity.
	mkScan(mkRepo("queued"), db.ScanQueued, 0, nil, nil)

	day := mustBuildReport(t, s, resolveReportInterval("day"), "")
	if day.Totals.ScansStarted != 1 {
		t.Errorf("day ScansStarted = %d, want 1 (the running run only)", day.Totals.ScansStarted)
	}
	if day.Totals.ScansCompleted != 1 {
		t.Errorf("day ScansCompleted = %d, want 1 (the straddler only)", day.Totals.ScansCompleted)
	}
	// Both repositories saw activity in the window even though neither had a
	// whole run inside it; the queued repository saw none.
	if day.Totals.ReposScanned != 2 {
		t.Errorf("day ReposScanned = %d, want 2", day.Totals.ReposScanned)
	}
	// Starts can trail the repository count once completions bring their own
	// repositories in, so the fan-out ratio is allowed below one.
	if got := day.Totals.ScansPerRepo(); got != 0.5 {
		t.Errorf("day ScansPerRepo() = %v, want 0.5", got)
	}
	// The averages window is bounded on finished_at, the same clock the
	// completion count uses, so the straddler is inside it.
	if day.Period.Runs != 1 || day.Period.CostUSD != 3 {
		t.Errorf("day averages = %d runs at %v, want 1 at 3", day.Period.Runs, day.Period.CostUSD)
	}
	// Its spend lands on the day it finished, not the day it began.
	for _, d := range day.Days {
		if d.Date == ended.Format(reportDateLayout) && d.CostUSD != 3 {
			t.Errorf("finish day %s cost = %v, want 3", d.Date, d.CostUSD)
		}
	}

	// Widening the window brings the straddler's start in. The queued run
	// was enqueued inside this window and must still be counted nowhere.
	week := mustBuildReport(t, s, resolveReportInterval("week"), "")
	if week.Totals.ScansStarted != 2 {
		t.Errorf("week ScansStarted = %d, want 2", week.Totals.ScansStarted)
	}
	if week.Totals.ScansCompleted != 1 {
		t.Errorf("week ScansCompleted = %d, want 1", week.Totals.ScansCompleted)
	}
	if week.Totals.ReposScanned != 2 {
		t.Errorf("week ReposScanned = %d, want 2; the queued repository has no activity", week.Totals.ReposScanned)
	}
}

// Every state below stamps finished_at, so reaching the completion count is
// not the same as belonging in it. The guard on db.ScanDone is what tells
// them apart, and it reads as redundant next to the finished_at check that
// selects the row — it is not, and this test says so out loud rather than
// leaving a reviewer to infer it from an arithmetic shift elsewhere.
//
// The paused row is the clearest case: it has not finished at all. Counting
// it would report a completion now and another when the run actually
// finishes after resuming.
func TestBuildReportCountsOnlyDoneRunsAsCompleted(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	now := time.Now().UTC()

	repo := db.Repository{URL: "https://example.test/stopped", Name: "stopped", FullName: "acme/stopped"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	started, stopped := now.Add(-2*time.Hour), now.Add(-time.Hour)
	stoppedRuns := []struct {
		status db.ScanStatus
		cost   float64
	}{
		{db.ScanDone, 2.00},
		{db.ScanFailed, 1.00},
		{db.ScanCancelled, 3.00},
		{db.ScanSkipped, 4.00},
		{db.ScanPaused, 5.00},
	}
	for _, run := range stoppedRuns {
		sc := db.Scan{
			RepositoryID: repo.ID, Kind: "skill", Status: run.status, SkillName: "vuln-scan",
			CostUSD: run.cost, InputTokens: 100,
			StartedAt: &started, FinishedAt: &stopped, CreatedAt: started,
		}
		if err := s.DB.Create(&sc).Error; err != nil {
			t.Fatal(err)
		}
	}

	got := mustBuildReport(t, s, resolveReportInterval("day"), "")
	if got.Totals.ScansStarted != len(stoppedRuns) {
		t.Errorf("ScansStarted = %d, want %d", got.Totals.ScansStarted, len(stoppedRuns))
	}
	if got.Totals.ScansCompleted != 1 {
		t.Errorf("ScansCompleted = %d, want 1: only the done run completed, but every row here "+
			"carries a finished_at and so reaches the count", got.Totals.ScansCompleted)
	}

	// Spend is accumulated after the completion guard, so the full total
	// proves all five rows passed the finished_at check and arrived at it.
	// Without that guard every one of them would have been a completion.
	var spend float64
	for _, d := range got.Days {
		spend += d.CostUSD
	}
	if want := 15.00; spend != want {
		t.Errorf("attributed spend = %v, want %v; every stopped run should reach the guard", spend, want)
	}

	// And the averages population stays the completed-and-costed scans
	// docs/cost_averages.sql defines, so the two figures on the page agree
	// on what "completed" means.
	if got.Period.Runs != 1 || got.Period.CostUSD != 2 {
		t.Errorf("averages = %d runs at %v, want 1 at 2", got.Period.Runs, got.Period.CostUSD)
	}
}

// The severity floor must filter findings and leave scan activity alone.
func TestBuildReportMinSeverityFiltersFindingsOnly(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	all := reportIntervals[0]
	for _, tc := range []struct {
		severity string
		findings int
	}{
		{"", 3},         // Critical + Low + High
		{"Low", 3},      // the floor admits everything
		{"Medium", 2},   // drops Low
		{"High", 2},     // Critical + High
		{"Critical", 1}, // Critical only
	} {
		got := mustBuildReport(t, s, all, tc.severity)
		if got.Totals.Findings != tc.findings {
			t.Errorf("severity %q: findings = %d, want %d", tc.severity, got.Totals.Findings, tc.findings)
		}
		// Scan-side numbers are a property of scans, not findings.
		if got.Totals.ScansStarted != 6 || got.Totals.ScansCompleted != 4 || got.AllTime.Runs != 4 {
			t.Errorf("severity %q moved scan totals: %+v", tc.severity, got.Totals)
		}
	}
}

func TestBuildReportMinSeverityAppliesToDayRows(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	unfiltered := mustBuildReport(t, s, reportIntervals[0], "")
	filtered := mustBuildReport(t, s, reportIntervals[0], "Critical")
	sum := func(days []reportDayRow) int {
		var n int
		for _, d := range days {
			n += d.Findings
		}
		return n
	}
	if got := sum(unfiltered.Days); got != 3 {
		t.Errorf("unfiltered day findings = %d, want 3", got)
	}
	if got := sum(filtered.Days); got != 1 {
		t.Errorf("Critical-only day findings = %d, want 1", got)
	}
}

// The averages must reproduce docs/cost_averages.sql: mean over completed
// scans with a positive cost, so the failed and queued rows stay out.
func TestBuildReportAveragesMatchCostAveragesSQL(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	got := mustBuildReport(t, s, reportIntervals[0], "").AllTime
	// (2+4+6+8)/4
	if got.CostUSD != 5 {
		t.Errorf("avg cost = %v, want 5", got.CostUSD)
	}
	// (100+300+200+400)/4
	if got.InputTokens != 250 {
		t.Errorf("avg input = %v, want 250", got.InputTokens)
	}
	if got.OutputTokens != 25 {
		t.Errorf("avg output = %v, want 25", got.OutputTokens)
	}
	if got.CacheReadTokens != 2500 {
		t.Errorf("avg cache read = %v, want 2500", got.CacheReadTokens)
	}
	if got.CacheWriteTokens != 125 {
		t.Errorf("avg cache write = %v, want 125", got.CacheWriteTokens)
	}
	if got.TotalTokens != 2900 {
		t.Errorf("avg total = %v, want 2900", got.TotalTokens)
	}
}

// A day's averages and the period averages must be the same measurement at
// two resolutions, so the per-day denominators have to add up to the
// period denominator the SQL aggregate returned.
func TestBuildReportDayAveragesShareThePeriodPopulation(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	got := mustBuildReport(t, s, reportIntervals[0], "")
	var averaged int
	var cost float64
	for _, d := range got.Days {
		averaged += d.ScansAveraged
		cost += d.AvgCostUSD * float64(d.ScansAveraged)
	}
	if averaged != got.AllTime.Runs {
		t.Errorf("day denominators sum to %d, period says %d", averaged, got.AllTime.Runs)
	}
	if want := got.AllTime.CostUSD * float64(got.AllTime.Runs); cost != want {
		t.Errorf("day costs sum to %v, period implies %v", cost, want)
	}
}

func TestBuildReportEmptyCorpus(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	got := mustBuildReport(t, s, resolveReportInterval("week"), "")
	if got.Totals.ScansStarted != 0 || got.AllTime.Runs != 0 || len(got.Days) != 0 {
		t.Fatalf("empty corpus report = %+v, want zeroed", got)
	}
	// A zero denominator must not produce NaN in the rendered averages.
	if got.AllTime.CostUSD != 0 || got.AllTime.TotalTokens != 0 {
		t.Errorf("averages over no runs = %+v, want zeros", got.AllTime)
	}
}

func TestReportingPageRenders(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/reporting?interval=week"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{
		"Reporting",
		"Repositories scanned",
		"Cost averages",
		"Daily breakdown",
		"Minimum severity",
		// The scan tiles name their unit and show why the count outruns
		// the repository count, and each names the clock it is read on.
		"Scan runs started",
		"Scan runs completed",
		"per repository",
		"of runs started",
		"/reporting/report.csv?interval=week",
		"/reporting/report.json?interval=week",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	// The orphaned right-aligned caption is gone; the wording now lives in
	// the paragraph under the heading.
	if strings.Contains(body, `<span class="text-xs text-muted-foreground">per completed scan with a recorded cost</span>`) {
		t.Error("floating cost-averages caption is still present")
	}
	if !strings.Contains(body, "Averaged per completed scan with a recorded cost.") {
		t.Error("cost-averages population is not explained in the prose")
	}
	if !strings.Contains(body, `href="/reporting" aria-current="page"`) {
		t.Error("sidebar Reporting entry not marked current")
	}
	// The page must invoke the shared foot: it closes the <main> wrapper
	// "head" opened and carries the dialogs and the #toaster that flash
	// messages and htmx OOB toasts land in.
	for _, want := range []string{`id="toaster"`, "</main>", "</body>", "</html>"} {
		if !strings.Contains(body, want) {
			t.Errorf("page never reaches the shared foot: missing %q", want)
		}
	}
}

// Selecting a severity must survive into the period links and both export
// links, or switching period silently drops the filter.
func TestReportingPagePreservesSeverityInLinks(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/reporting?interval=week&severity=High"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{
		"/reporting?interval=day&amp;severity=High",
		"/reporting/report.csv?interval=week&amp;severity=High",
		"/reporting/report.json?interval=week&amp;severity=High",
		"Findings (High+)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestReportingNavKey(t *testing.T) {
	if got := navKey("/reporting"); got != "reporting" {
		t.Errorf("navKey(/reporting) = %q, want reporting", got)
	}
	// The neighbouring repository routes must not be captured by the new prefix.
	if got := navKey("/repositories/1"); got != "repos" {
		t.Errorf("navKey(/repositories/1) = %q, want repos", got)
	}
}

// The CSV must be one rectangular table: a single header, a uniform column
// count and no blank separator line. Anything else opens as a ragged sheet
// in Excel and breaks strict parsers.
func TestReportingCSVIsOneRectangularTable(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/reporting/report.csv?interval=week"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") ||
		!strings.Contains(cd, "scrutineer-report-week-") || !strings.Contains(cd, ".csv") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if strings.Contains(w.Body.String(), "\n\n") {
		t.Error("CSV contains a blank line; it is no longer a single table")
	}

	// FieldsPerRecord defaults to the first record's count and errors on
	// any row that disagrees, so a successful ReadAll proves rectangularity.
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("not a rectangular CSV: %v", err)
	}
	if strings.Join(rows[0], ",") != strings.Join(reportCSVHeader, ",") {
		t.Fatalf("header = %v, want %v", rows[0], reportCSVHeader)
	}
	if len(rows) < 3 {
		t.Fatalf("expected a period_total, an all_time_average and day rows, got %d", len(rows)-1)
	}

	byType := map[string][]string{}
	for _, row := range rows[1:] {
		if len(row) != len(reportCSVHeader) {
			t.Fatalf("row %v has %d cells, want %d", row, len(row), len(reportCSVHeader))
		}
		if row[0] != "week" {
			t.Errorf("period column = %q, want week", row[0])
		}
		if row[1] != "all" {
			t.Errorf("minimum_severity column = %q, want all", row[1])
		}
		byType[row[2]] = row
	}
	total, ok := byType["period_total"]
	if !ok {
		t.Fatal("no period_total row")
	}
	// repositories_scanned, scans_started, scans_completed, findings
	if total[4] != "3" || total[5] != "4" || total[6] != "2" || total[7] != "2" {
		t.Errorf("period_total activity = %v", total[4:8])
	}
	if total[11] != "3.00" {
		t.Errorf("period avg_cost_usd = %q, want 3.00", total[11])
	}
	allTime, ok := byType["all_time_average"]
	if !ok {
		t.Fatal("no all_time_average row")
	}
	if allTime[11] != "5.00" {
		t.Errorf("all-time avg_cost_usd = %q, want 5.00", allTime[11])
	}
	// The all-time row must not imply activity totals it never computed.
	if allTime[4] != "" || allTime[7] != "" {
		t.Errorf("all_time_average leaked activity figures: %v", allTime)
	}
	if _, ok := byType["day"]; !ok {
		t.Fatal("no day rows")
	}
}

func TestReportingCSVCarriesSeverityFilter(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/reporting/report.csv?interval=all&severity=Critical"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows[1:] {
		if row[1] != "Critical" {
			t.Fatalf("minimum_severity column = %q, want Critical", row[1])
		}
		if row[2] == "period_total" && row[7] != "1" {
			t.Errorf("filtered findings total = %q, want 1", row[7])
		}
	}
}

func TestReportingJSONExport(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/reporting/report.json?interval=all"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "scrutineer-report-all-") {
		t.Errorf("Content-Disposition = %q", cd)
	}

	var out struct {
		GeneratedAt string `json:"generated_at"`
		Period      struct {
			Key      string  `json:"key"`
			Label    string  `json:"label"`
			Meaning  string  `json:"meaning"`
			StartsAt *string `json:"starts_at"`
			EndsAt   string  `json:"ends_at"`
		} `json:"period"`
		Filters struct {
			MinimumSeverity *string  `json:"minimum_severity"`
			AppliesTo       []string `json:"applies_to"`
		} `json:"filters"`
		Activity struct {
			RepositoriesScanned int     `json:"repositories_scanned"`
			ScansStarted        int     `json:"scans_started"`
			ScansCompleted      int     `json:"scans_completed"`
			Findings            int     `json:"findings"`
			CostUSD             float64 `json:"cost_usd"`
			TotalTokens         int     `json:"total_tokens"`
		} `json:"activity_in_period"`
		Averages struct {
			Population string             `json:"population"`
			InPeriod   map[string]float64 `json:"in_period"`
			AllTime    map[string]float64 `json:"all_time"`
		} `json:"cost_averages_per_scan"`
		ByDay []struct {
			Date           string  `json:"date"`
			ScansStarted   int     `json:"scans_started"`
			ScansCompleted int     `json:"scans_completed"`
			Findings       int     `json:"findings"`
			CostUSD        float64 `json:"cost_usd"`
		} `json:"activity_by_day"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v\n%s", err, w.Body)
	}

	// The old ambiguous key names must be gone.
	var raw map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &raw)
	for _, gone := range []string{"totals", "days", "averages", "window_start", "interval"} {
		if _, ok := raw[gone]; ok {
			t.Errorf("ambiguous key %q is still present at the top level", gone)
		}
	}
	if _, ok := out.Averages.InPeriod["avg_cost_usd"]; !ok {
		t.Error("cost_averages_per_scan.in_period missing avg_cost_usd")
	}

	if out.Period.Key != "all" || out.Period.Label != "All time" || out.Period.Meaning == "" {
		t.Errorf("period = %+v", out.Period)
	}
	if out.Period.StartsAt != nil {
		t.Errorf("starts_at = %v, want null for all time", *out.Period.StartsAt)
	}
	if out.Period.EndsAt == "" || out.GeneratedAt == "" {
		t.Error("generated_at/ends_at should always be set")
	}
	if out.Filters.MinimumSeverity != nil {
		t.Errorf("minimum_severity = %v, want null", *out.Filters.MinimumSeverity)
	}
	if len(out.Filters.AppliesTo) != 1 || out.Filters.AppliesTo[0] != "findings" {
		t.Errorf("applies_to = %v, want [findings]", out.Filters.AppliesTo)
	}
	// The failed run's spend (1.00, 22 tokens) is part of the period totals.
	if out.Activity.RepositoriesScanned != 3 || out.Activity.ScansStarted != 6 ||
		out.Activity.ScansCompleted != 4 || out.Activity.Findings != 3 ||
		out.Activity.CostUSD != 21 || out.Activity.TotalTokens != 11622 {
		t.Errorf("activity_in_period = %+v", out.Activity)
	}
	if out.Averages.Population == "" {
		t.Error("cost_averages_per_scan.population should explain the denominator")
	}
	if out.Averages.AllTime["avg_cost_usd"] != 5 {
		t.Errorf("all_time avg_cost_usd = %v, want 5", out.Averages.AllTime["avg_cost_usd"])
	}
	// All time makes both columns the same population.
	if out.Averages.InPeriod["avg_total_tokens"] != out.Averages.AllTime["avg_total_tokens"] {
		t.Errorf("in_period and all_time should agree over the all-time period: %v vs %v",
			out.Averages.InPeriod["avg_total_tokens"], out.Averages.AllTime["avg_total_tokens"])
	}
	if len(out.ByDay) == 0 {
		t.Fatal("activity_by_day is empty")
	}
	for i := 1; i < len(out.ByDay); i++ {
		if out.ByDay[i-1].Date < out.ByDay[i].Date {
			t.Fatalf("activity_by_day not newest first: %q then %q", out.ByDay[i-1].Date, out.ByDay[i].Date)
		}
	}
}

func TestReportingJSONCarriesSeverityFilter(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/reporting/report.json?interval=all&severity=high"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var out struct {
		Filters struct {
			MinimumSeverity *string `json:"minimum_severity"`
		} `json:"filters"`
		Activity struct {
			Findings       int `json:"findings"`
			ScansCompleted int `json:"scans_completed"`
		} `json:"activity_in_period"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	// Lowercase input is canonicalised on the way in.
	if out.Filters.MinimumSeverity == nil || *out.Filters.MinimumSeverity != "High" {
		t.Errorf("minimum_severity = %v, want High", out.Filters.MinimumSeverity)
	}
	if out.Activity.Findings != 2 {
		t.Errorf("findings = %d, want 2 (Critical + High)", out.Activity.Findings)
	}
	if out.Activity.ScansCompleted != 4 {
		t.Errorf("scans_completed = %d, want 4; severity must not touch scan counts", out.Activity.ScansCompleted)
	}
}

// The tile captions are derived presentation, so they must be safe on an
// empty corpus and must not appear in either export.
func TestReportTotalsDerivedRatios(t *testing.T) {
	t.Run("zero corpus does not divide by zero", func(t *testing.T) {
		var empty reportTotals
		if got := empty.ScansPerRepo(); got != 0 {
			t.Errorf("ScansPerRepo() = %v, want 0", got)
		}
		if got := empty.CompletionRate(); got != 0 {
			t.Errorf("CompletionRate() = %v, want 0", got)
		}
	})

	t.Run("fan-out ratio", func(t *testing.T) {
		totals := reportTotals{ReposScanned: 49, ScansStarted: 510, ScansCompleted: 321}
		if got := totals.ScansPerRepo(); got < 10.4 || got > 10.5 {
			t.Errorf("ScansPerRepo() = %v, want ~10.41", got)
		}
		if got := totals.CompletionRate(); got < 0.62 || got > 0.63 {
			t.Errorf("CompletionRate() = %v, want ~0.629", got)
		}
	})

	// Over all time the corpus\'s six started runs span three repositories.
	// The ratio can fall below one in a narrow window — see
	// TestBuildReportCountsRunsOnTheirOwnClock — which is why the tile
	// renders it to one decimal.
	t.Run("fan-out over the seeded corpus", func(t *testing.T) {
		s, cleanup := newTestServer(t)
		defer cleanup()
		seedReportCorpus(t, s)
		got := mustBuildReport(t, s, reportIntervals[0], "").Totals
		if want := 2.0; got.ScansPerRepo() != want {
			t.Errorf("ScansPerRepo() = %v, want %v", got.ScansPerRepo(), want)
		}
	})
}

// The rename was a UI decision; the export contract stays as published.
func TestReportingExportsKeepScanFieldNames(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	csvRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(csvRec, localReq("GET", "/reporting/report.csv?interval=all"))
	header := strings.SplitN(csvRec.Body.String(), "\n", 2)[0]
	for _, want := range []string{"scans_started", "scans_completed"} {
		if !strings.Contains(header, want) {
			t.Errorf("CSV header lost %q: %s", want, header)
		}
	}
	if strings.Contains(header, "scan_runs") {
		t.Error("CSV header picked up the UI-only rename")
	}

	jsonRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(jsonRec, localReq("GET", "/reporting/report.json?interval=all"))
	body := jsonRec.Body.String()
	for _, want := range []string{`"scans_started"`, `"scans_completed"`} {
		if !strings.Contains(body, want) {
			t.Errorf("JSON lost %q", want)
		}
	}
	for _, gone := range []string{`"scan_runs"`, `"scans_per_repo"`, `"completion_rate"`} {
		if strings.Contains(body, gone) {
			t.Errorf("JSON leaked display-only value %q", gone)
		}
	}
}

// Columns are addressed by name, so a mistyped key renders an empty cell
// instead of failing to compile. Assert which columns each row type is
// meant to fill, so a typo shows up as a test failure rather than a blank
// column in someone's spreadsheet.
func TestReportingCSVRowsFillTheirColumns(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/reporting/report.csv?interval=all"))
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	index := map[string]int{}
	for i, col := range rows[0] {
		index[col] = i
	}

	// The all-time row deliberately leaves the activity columns blank, the
	// model column is filled only on model rows, and a model row has no
	// date or repository count; every other column of every other row
	// carries a value.
	blankForAllTime := map[string]bool{
		"date": true, "repositories_scanned": true, "scans_started": true,
		"scans_completed": true, findingsField: true, "cost_usd": true,
		"total_tokens": true, "model": true,
	}
	seen := map[string]bool{}
	for _, row := range rows[1:] {
		rowType := row[index["row_type"]]
		seen[rowType] = true
		for col, i := range index {
			// period_total covers the whole window, so it has no single date.
			wantBlank := (rowType == "period_total" && (col == "date" || col == "model")) ||
				(rowType == "all_time_average" && blankForAllTime[col]) ||
				(rowType == "day" && col == "model") ||
				(rowType == "model" && (col == "date" || col == "repositories_scanned"))
			if wantBlank {
				if row[i] != "" {
					t.Errorf("%s: column %q = %q, want empty", rowType, col, row[i])
				}
				continue
			}
			if row[i] == "" {
				t.Errorf("%s: column %q is empty; check the key spelling", rowType, col)
			}
		}
	}
	for _, want := range []string{"period_total", "all_time_average", "model", "day"} {
		if !seen[want] {
			t.Errorf("no %s row emitted", want)
		}
	}
}

func TestReportingJSONModelBreakdown(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/reporting/report.json?interval=all"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var out struct {
		ByModel []struct {
			Model          string  `json:"model"`
			ScansStarted   int     `json:"scans_started"`
			ScansCompleted int     `json:"scans_completed"`
			Findings       int     `json:"findings"`
			CostUSD        float64 `json:"cost_usd"`
		} `json:"activity_by_model"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.ByModel) != 2 {
		t.Fatalf("got %d model rows, want 2: %+v", len(out.ByModel), out.ByModel)
	}
	// model-a leads: rows sort by findings first. It owns every terminal
	// run (4 done + 1 failed = 5 starts, 4 completions, all the spend) and
	// all three findings; model-b's only activity is the running scan's
	// start, so its other figures hold zero rather than going blank.
	a, b := out.ByModel[0], out.ByModel[1]
	if a.Model != "model-a" || a.ScansStarted != 5 || a.ScansCompleted != 4 || a.Findings != 3 || a.CostUSD != 21.00 {
		t.Errorf("model-a row = %+v, want started 5, completed 4, findings 3, cost 21.00", a)
	}
	if b.Model != "model-b" || b.ScansStarted != 1 || b.ScansCompleted != 0 || b.Findings != 0 {
		t.Errorf("model-b row = %+v, want started 1, completed 0, findings 0", b)
	}
}

func TestCSVGuardCell(t *testing.T) {
	cases := []struct{ in, want string }{
		{"claude-opus-4-1", "claude-opus-4-1"},
		{"", ""},
		{"=1+1", "'=1+1"},
		{"+cmd", "'+cmd"},
		{"-2+3", "'-2+3"},
		{"@SUM(A1)", "'@SUM(A1)"},
		{"\tx", "'\tx"},
		{"\rx", "'\rx"},
	}
	for _, tc := range cases {
		if got := csvGuardCell(tc.in); got != tc.want {
			t.Errorf("csvGuardCell(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestReportingCSVGuardsHostileModel proves the CSV sink defends itself:
// the hostile model is seeded directly in the database, bypassing the
// ingest normalisation that would normally drop it, and must still come
// out neutralised. Weakening either layer alone keeps a test failing.
func TestReportingCSVGuardsHostileModel(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	repo := db.Repository{URL: "https://example.test/hostile", Name: "hostile"}
	s.DB.Create(&repo)
	now := time.Now().UTC()
	started := now.Add(-time.Hour)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName: "vuln-scan", Model: "=2+5", StartedAt: &started, FinishedAt: &now})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/reporting/report.csv?interval=all"))
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	modelCol := slices.Index(rows[0], "model")
	var seen bool
	for _, row := range rows[1:] {
		if row[slices.Index(rows[0], "row_type")] != "model" {
			continue
		}
		seen = true
		if got := row[modelCol]; got != "'=2+5" {
			t.Errorf("model cell = %q, want neutralised '=2+5", got)
		}
	}
	if !seen {
		t.Fatal("no model row emitted")
	}
}

// TestImportedModelCannotInjectCSVFormula is the import-to-CSV regression:
// a sharing bundle carrying a formula as its model must reach neither the
// finding row nor the reporting CSV. The ingest boundary drops it, so the
// finding imports unattributed and no CSV cell leads with a formula
// trigger.
func TestImportedModelCannotInjectCSVFormula(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	body := `{"repository":"https://example.test/injected","findings":[
		{"title":"t","severity":"high","location":"a.go:1","model":"=1+1"}]}`
	r := httptest.NewRequest("POST", "/api/v1/import", strings.NewReader(body))
	asOperator(r)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatalf("import status %d: %s", w.Code, w.Body)
	}
	var f db.Finding
	if err := s.DB.First(&f).Error; err != nil {
		t.Fatal(err)
	}
	if f.Model != "" {
		t.Errorf("imported Finding.Model = %q, want dropped", f.Model)
	}

	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/reporting/report.csv?interval=all"))
	if strings.Contains(w.Body.String(), "=1+1") {
		t.Error("hostile model text reached the reporting CSV")
	}
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for i, row := range rows[1:] {
		for j, cell := range row {
			if cell == "" {
				continue
			}
			switch cell[0] {
			case '=', '+', '-', '@', '\t', '\r':
				t.Errorf("row %d column %q starts with formula trigger: %q", i+1, rows[0][j], cell)
			}
		}
	}
}

func TestCSVRecordIsAlwaysHeaderWidth(t *testing.T) {
	if got := csvRecord(nil); len(got) != len(reportCSVHeader) {
		t.Errorf("csvRecord(nil) width = %d, want %d", len(got), len(reportCSVHeader))
	}
	// An unknown column is dropped rather than widening the record.
	got := csvRecord(map[string]string{"period": "week", "not_a_column": "x"})
	if len(got) != len(reportCSVHeader) {
		t.Fatalf("width = %d, want %d", len(got), len(reportCSVHeader))
	}
	if got[0] != "week" {
		t.Errorf("period cell = %q, want week", got[0])
	}
	for _, cell := range got[1:] {
		if cell == "x" {
			t.Error("unknown column leaked into the record")
		}
	}
}

// With an unbounded period the "selected period" and "all time" columns are
// the same population, so rendering both put two identical "All time"
// headings side by side on the default view.
func TestReportingCostAveragesColumnsMatchThePeriod(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	seedReportCorpus(t, s)

	countHeadings := func(body, heading string) int {
		return strings.Count(body, `<th class="text-right">`+heading+`</th>`)
	}

	t.Run("all time collapses to one column", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", "/reporting?interval=all"))
		if w.Code != 200 {
			t.Fatalf("status %d", w.Code)
		}
		if got := countHeadings(w.Body.String(), "All time"); got != 1 {
			t.Errorf("All time column count = %d, want 1", got)
		}
	})

	t.Run("bounded period keeps both columns", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", "/reporting?interval=week"))
		if w.Code != 200 {
			t.Fatalf("status %d", w.Code)
		}
		body := w.Body.String()
		if got := countHeadings(body, "All time"); got != 1 {
			t.Errorf("All time column count = %d, want 1", got)
		}
		if got := countHeadings(body, "Week"); got != 1 {
			t.Errorf("Week column count = %d, want 1", got)
		}
	})
}

// A failing read must not render as a quiet week. The exports are files an
// operator archives, so a zeroed report passing as a real one is worse than
// an error.
func TestReportingFailsRatherThanReportingZeros(t *testing.T) {
	for _, path := range []string{"/reporting", "/reporting/report.csv", "/reporting/report.json"} {
		t.Run(path, func(t *testing.T) {
			s, cleanup := newTestServer(t)
			defer cleanup()
			seedReportCorpus(t, s)
			if err := s.DB.Exec("DROP TABLE scans").Error; err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, localReq("GET", path))
			if w.Code != http.StatusInternalServerError {
				t.Errorf("status = %d, want 500; body: %s", w.Code, w.Body)
			}
			if strings.Contains(w.Body.String(), "repositories_scanned") {
				t.Error("a failed read still produced report content")
			}
		})
	}
}
