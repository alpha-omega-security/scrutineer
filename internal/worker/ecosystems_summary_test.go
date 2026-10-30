package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ecosystems "github.com/ecosyste-ms/ecosystems-go"
	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
	"scrutineer/internal/queue"
)

type summaryHTTPFixture struct {
	status  atomic.Int32
	commits atomic.Int32
	issues  atomic.Int32
	fetcher *productionEcosystemsFetcher
}

func newSummaryHTTPFixture(t *testing.T, status int) *summaryHTTPFixture {
	t.Helper()
	f := new(summaryHTTPFixture)
	f.status.Store(int32(status))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Query().Get("url") != "https://github.com/acme/widget" {
			t.Errorf("request: %s %s", r.Method, r.URL)
		}
		var payload string
		switch r.URL.Path {
		case "/commits/repositories/lookup":
			f.commits.Add(1)
			payload = `{"full_name":"acme/widget","total_commits":42}`
		case "/issues/repositories/lookup":
			f.issues.Add(1)
			payload = `{"full_name":"acme/widget","issues_count":7}`
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		code := int(f.status.Load())
		w.WriteHeader(code)
		if code == http.StatusOK {
			_, _ = w.Write([]byte(payload))
		}
	}))
	t.Cleanup(server.Close)
	client, err := ecosystems.NewClient("scrutineer-test", ecosystems.WithCommitsServer(server.URL+"/commits"), ecosystems.WithIssuesServer(server.URL+"/issues"))
	if err != nil {
		t.Fatal(err)
	}
	f.fetcher = &productionEcosystemsFetcher{ecosystems: client}
	return f
}

func summaryCacheRepo(t *testing.T, gdb *gorm.DB, cached bool) db.Repository {
	t.Helper()
	fresh := time.Now().UTC()
	repo := db.Repository{
		URL: "https://github.com/acme/widget", Name: "widget",
		EcosystemsRepoFetchedAt: &fresh, EcosystemsPackagesFetchedAt: &fresh,
		EcosystemsAdvisoriesFetchedAt: &fresh, EcosystemsDependentsFetchedAt: &fresh,
	}
	if cached {
		stale := fresh.Add(-8 * 24 * time.Hour)
		repo.EcosystemsCommitsData = `{"total_commits":1}`
		repo.EcosystemsIssuesData = `{"issues_count":1}`
		repo.EcosystemsCommitsFetchedAt = &stale
		repo.EcosystemsIssuesFetchedAt = &stale
	}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	return repo
}

func runSummaryRefreshScan(t *testing.T, gdb *gorm.DB, repoID uint, f ecosystemsFetcher, logs *bytes.Buffer) {
	t.Helper()
	skill := db.Skill{Name: "summary-test", Body: "test", OutputFile: "report.json", OutputKind: "repo_metadata", Active: true, Version: 1, Source: "ui"}
	if err := gdb.Where("name = ?", skill.Name).FirstOrCreate(&skill).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repoID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID, Model: "fake"}
	if err := gdb.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewJSONHandler(logs, nil))
	w := &Worker{DB: gdb, Log: log, DataDir: t.TempDir(), Runner: fakeRunner{skillRes: SkillResult{Commit: "abc", Report: `{}`}}, PrepareRepoSrc: stubPrepareRepoSrc}
	w.RefreshEcosystemsCache = func(ctx context.Context, id uint) error {
		return refreshEcosystems(ctx, gdb, id, true, log, f)
	}
	body, err := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	var saved db.Scan
	if err := gdb.First(&saved, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if saved.Status != db.ScanDone {
		t.Fatalf("scan status=%s error=%s", saved.Status, saved.Error)
	}
}

func TestScanEcosystemsAbsentSummaries(t *testing.T) {
	for _, status := range []int{http.StatusAccepted, http.StatusNotFound} {
		for _, cached := range []bool{false, true} {
			t.Run(fmt.Sprintf("status=%d/cached=%t", status, cached), func(t *testing.T) {
				gdb := dbtest.Open(t)
				repo := summaryCacheRepo(t, gdb, cached)
				f := newSummaryHTTPFixture(t, status)
				var logs bytes.Buffer
				runSummaryRefreshScan(t, gdb, repo.ID, f.fetcher, &logs)
				assertSummaryCacheUnchanged(t, gdb, repo)
				if strings.Contains(logs.String(), `"level":"WARN"`) {
					t.Fatalf("absent summary warning: %s", &logs)
				}
				if f.commits.Load() != 1 || f.issues.Load() != 1 {
					t.Fatalf("requests: commits=%d issues=%d", f.commits.Load(), f.issues.Load())
				}
				f.status.Store(http.StatusOK)
				runSummaryRefreshScan(t, gdb, repo.ID, f.fetcher, &logs)
				assertSummaryCacheRefreshed(t, gdb, repo.ID)
				runSummaryRefreshScan(t, gdb, repo.ID, f.fetcher, &logs)
				if f.commits.Load() != 2 || f.issues.Load() != 2 {
					t.Fatalf("requests after fresh scan: commits=%d issues=%d", f.commits.Load(), f.issues.Load())
				}
				t.Logf("HTTP %d preserved cached=%t without warnings; later HTTP 200 refreshed both summaries", status, cached)
			})
		}
	}
}

func assertSummaryCacheUnchanged(t *testing.T, gdb *gorm.DB, repo db.Repository) {
	t.Helper()
	var saved db.Repository
	if err := gdb.First(&saved, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	if saved.EcosystemsCommitsData != repo.EcosystemsCommitsData || saved.EcosystemsIssuesData != repo.EcosystemsIssuesData {
		t.Fatal("absent summary replaced cached payload")
	}
	for _, pair := range [][2]*time.Time{{saved.EcosystemsCommitsFetchedAt, repo.EcosystemsCommitsFetchedAt}, {saved.EcosystemsIssuesFetchedAt, repo.EcosystemsIssuesFetchedAt}} {
		if pair[0] == nil && pair[1] == nil {
			continue
		}
		if pair[0] == nil || pair[1] == nil || !pair[0].Equal(*pair[1]) {
			t.Fatalf("absent summary changed timestamp: %v", pair)
		}
	}
}

func assertSummaryCacheRefreshed(t *testing.T, gdb *gorm.DB, repoID uint) {
	t.Helper()
	var saved db.Repository
	if err := gdb.First(&saved, repoID).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(saved.EcosystemsCommitsData, `"total_commits":42`) || !strings.Contains(saved.EcosystemsIssuesData, `"issues_count":7`) {
		t.Fatal("successful response not cached")
	}
	if saved.EcosystemsCommitsFetchedAt == nil || saved.EcosystemsIssuesFetchedAt == nil {
		t.Fatal("successful response missing timestamps")
	}
}

func TestScanEcosystemsSummaryErrorsStillWarn(t *testing.T) {
	gdb := dbtest.Open(t)
	repo := summaryCacheRepo(t, gdb, true)
	f := newSummaryHTTPFixture(t, http.StatusInternalServerError)
	var logs bytes.Buffer
	runSummaryRefreshScan(t, gdb, repo.ID, f.fetcher, &logs)
	assertSummaryCacheUnchanged(t, gdb, repo)
	for _, source := range []string{"commits", "issues"} {
		if !strings.Contains(logs.String(), `"source":"`+source+`"`) {
			t.Errorf("missing %s warning: %s", source, &logs)
		}
	}
	if strings.Count(logs.String(), "ecosystems fetch failed") != 2 {
		t.Fatalf("fetch warnings: %s", &logs)
	}
}
