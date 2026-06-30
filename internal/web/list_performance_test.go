package web

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scrutineer/internal/db"

	"gorm.io/gorm"
)

func TestListPagesQueryCountsStayBounded(t *testing.T) {
	cases := []struct {
		name string
		path string
		max  int64
	}{
		{name: "repositories", path: "/", max: 8},
		{name: "findings", path: "/findings", max: 8},
		{name: "scans", path: "/scans", max: 6},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oneRow := listPageQueryCount(t, tc.path, 1)
			manyRows := listPageQueryCount(t, tc.path, 60)

			if manyRows > oneRow+1 {
				t.Fatalf("%s query count grew with rows: 1 row=%d, 60 rows=%d", tc.path, oneRow, manyRows)
			}
			if manyRows > tc.max {
				t.Fatalf("%s ran %d queries, want <= %d", tc.path, manyRows, tc.max)
			}
		})
	}
}

func TestScanListStatsAggregatesCounts(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/stats", Name: "stats"}
	s.DB.Create(&repo)
	for _, status := range []db.ScanStatus{db.ScanQueued, db.ScanQueued, db.ScanPaused, db.ScanRunning} {
		s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: status})
	}
	// A scan paused because the account hit an account-level Claude problem
	// (auto-paused by the worker), plus an unrelated failure that must not
	// be counted.
	s.DB.Create(&db.Scan{
		RepositoryID: repo.ID,
		Kind:         "skill",
		Status:       db.ScanPaused,
		Error:        "Claude account access paused. Queued scan held automatically; resume once the account recovers.",
	})
	s.DB.Create(&db.Scan{
		RepositoryID: repo.ID,
		Kind:         "skill",
		Status:       db.ScanFailed,
		Error:        "different failure",
	})

	// PausedCount counts both the bare paused scan and the account-paused one;
	// AccountPausedCount counts only the latter.
	stats := s.scanListStats()
	if stats.QueuedCount != 2 || stats.PausedCount != 2 || stats.AccountPausedCount != 1 {
		t.Fatalf("scanListStats = %+v, want queued=2 paused=2 account-paused=1", stats)
	}
}

func BenchmarkListPagesLargeDataset(b *testing.B) {
	s, done := newTestServer(b)
	defer done()
	seedListPagePerfFixtures(b, s, 500)

	for _, path := range []string{"/", "/findings", "/scans"} {
		b.Run(path, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, localReq("GET", path))
				if w.Code != 200 {
					b.Fatalf("%s status %d: %s", path, w.Code, w.Body)
				}
			}
		})
	}
}

// The repo list renders the disk-usage badge from Repository.DiskBytes, not
// by walking each repo's clone cache per row (#126). Seeding the column with
// no cache directory on disk and seeing the size render proves the column is
// the source: the old per-row filepath.Walk would have found nothing and
// shown "-".
func TestRepoList_diskBadgeReadsCachedColumn(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/sized", Name: "sized", DiskBytes: 2048}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	row := requireRepoListRow(t, w.Body.String(), repo.ID)
	if !strings.Contains(row, "2.0 KB") {
		t.Errorf("repo row did not render cached disk size from the column: %s", row)
	}
}

func listPageQueryCount(t *testing.T, path string, rows int) int64 {
	t.Helper()
	s, done := newTestServer(t)
	defer done()
	seedListPagePerfFixtures(t, s, rows)
	getCount := countDBQueries(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", path))
	if w.Code != 200 {
		t.Fatalf("%s status %d: %s", path, w.Code, w.Body)
	}
	return getCount()
}

func countDBQueries(t testing.TB, s *Server) func() int64 {
	t.Helper()
	var count atomic.Int64
	name := fmt.Sprintf("scrutineer:test-query-count:%d", time.Now().UnixNano())
	callback := func(*gorm.DB) {
		count.Add(1)
	}
	if err := s.DB.Callback().Query().Before("gorm:query").Register(name+":query", callback); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Callback().Raw().Before("gorm:raw").Register(name+":raw", callback); err != nil {
		t.Fatal(err)
	}
	return count.Load
}

func seedListPagePerfFixtures(t testing.TB, s *Server, rows int) {
	t.Helper()
	for i := 0; i < rows; i++ {
		repo := db.Repository{
			URL:         fmt.Sprintf("https://example.com/repo-%03d", i),
			Name:        fmt.Sprintf("repo-%03d", i),
			FullName:    fmt.Sprintf("org/repo-%03d", i),
			Owner:       "org",
			Description: "fixture repository",
			Languages:   "Go, Java",
		}
		if err := s.DB.Create(&repo).Error; err != nil {
			t.Fatal(err)
		}
		scan := db.Scan{
			RepositoryID:   repo.ID,
			Kind:           "skill",
			Status:         db.ScanDone,
			StatusPriority: db.StatusPriorityFor(db.ScanDone),
			SkillName:      deepDiveSkillName,
			FindingsCount:  2,
			Ref:            "main",
		}
		if err := s.DB.Create(&scan).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.DB.Create(&db.Scan{
			RepositoryID:   repo.ID,
			Kind:           "skill",
			Status:         db.ScanQueued,
			StatusPriority: db.StatusPriorityFor(db.ScanQueued),
			SkillName:      "metadata",
		}).Error; err != nil {
			t.Fatal(err)
		}
		for j, severity := range []string{"High", "Medium"} {
			if err := s.DB.Create(&db.Finding{
				ScanID:       scan.ID,
				RepositoryID: repo.ID,
				FindingID:    fmt.Sprintf("F%d-%d", i, j),
				Title:        fmt.Sprintf("finding %d-%d", i, j),
				Severity:     severity,
				Status:       db.FindingNew,
			}).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
}
