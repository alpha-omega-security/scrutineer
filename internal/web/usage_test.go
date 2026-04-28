package web

import (
	"math"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
)

func almostEq(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestPercentile(t *testing.T) {
	cases := []struct {
		xs   []float64
		p    float64
		want float64
	}{
		{[]float64{5}, 0.5, 5},
		{[]float64{1, 2, 3, 4}, 0.5, 2.5},
		{[]float64{1, 2, 3, 4, 5}, 0.5, 3},
		{[]float64{0, 10}, 0.9, 9},
		{[]float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 0.9, 9.1},
		{[]float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 1.0, 10},
		{[]float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 0.0, 1},
	}
	for _, tc := range cases {
		if got := percentile(tc.xs, tc.p); !almostEq(got, tc.want) {
			t.Errorf("percentile(%v, %v) = %v, want %v", tc.xs, tc.p, got, tc.want)
		}
	}
}

func TestSummarise(t *testing.T) {
	got := summarise([]float64{4, 1, 3, 2})
	if !almostEq(got.Min, 1) || !almostEq(got.Max, 4) || !almostEq(got.Sum, 10) || !almostEq(got.Median, 2.5) {
		t.Errorf("summarise = %+v", got)
	}
	if z := summarise(nil); z != (Stats{}) {
		t.Errorf("empty summarise = %+v", z)
	}
}

func TestFormatUSD(t *testing.T) {
	cases := []struct {
		v    float64
		want string
	}{
		{0, "$0.00"},
		{0.0042, "$0.0042"},
		{0.09, "$0.0900"},
		{0.10, "$0.10"},
		{12.345, "$12.35"},
	}
	for _, tc := range cases {
		if got := formatUSD(tc.v); got != tc.want {
			t.Errorf("formatUSD(%v) = %q, want %q", tc.v, got, tc.want)
		}
	}
}

func TestUsage_perSkillStatsAndOrdering(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://x/u", Name: "u"}
	s.DB.Create(&repo)

	mk := func(skill string, status db.ScanStatus, cost float64, turns int) {
		s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: skill,
			Status: status, CostUSD: cost, Turns: turns})
	}
	// deep-dive: three done runs spread across the cost range.
	mk("security-deep-dive", db.ScanDone, 1.00, 10)
	mk("security-deep-dive", db.ScanDone, 3.00, 30)
	mk("security-deep-dive", db.ScanDone, 8.00, 80)
	// metadata: two cheap runs, one failed (still counted).
	mk("metadata", db.ScanDone, 0.0012, 1)
	mk("metadata", db.ScanFailed, 0.0034, 2)
	// queued/running excluded.
	mk("metadata", db.ScanQueued, 0, 0)
	mk("security-deep-dive", db.ScanRunning, 0, 0)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/usage"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()

	// Grand total = 12.0046, rendered at 2dp.
	if !strings.Contains(body, "$12.00") {
		t.Errorf("missing grand total in body")
	}
	// 5 counted runs (queued/running excluded).
	if !strings.Contains(body, "5 runs") {
		t.Errorf("missing run count")
	}
	// deep-dive median is $3.00, max $8.00.
	for _, want := range []string{"security-deep-dive", "$3.00", "$8.00"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	// metadata costs are sub-dollar so render at 4dp.
	if !strings.Contains(body, "$0.0012") {
		t.Errorf("missing 4dp metadata min cost")
	}
	// Ordered by total cost desc: deep-dive ($12) before metadata ($0.0046).
	if strings.Index(body, "security-deep-dive") > strings.Index(body, ">metadata<") {
		t.Errorf("expected deep-dive row before metadata row")
	}
}

func TestRepoShow_totalCostBadge(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	now := time.Now()
	repo := db.Repository{URL: "https://x/spend", Name: "spend", FetchedAt: &now}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "a", Status: db.ScanDone, CostUSD: 1.50})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "b", Status: db.ScanDone, CostUSD: 0.25})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/repositories/1"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "$1.75") {
		t.Errorf("repo summary missing total cost $1.75")
	}
}
