package web

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
	"scrutineer/internal/queue"
	"scrutineer/internal/testutil"
	"scrutineer/internal/worker"
)

func TestPostgresWeb(t *testing.T) {
	gdb, err := db.OpenBackend(db.Options{Dialect: db.DialectPostgres, DSN: testutil.PostgresDSN(t)})
	if err != nil {
		t.Fatal(err)
	}
	testDatabaseWeb(t, gdb, queue.Postgres)
}

func TestSQLiteWebSearch(t *testing.T) {
	testDatabaseWeb(t, dbtest.Open(t), queue.SQLite)
}

func testDatabaseWeb(t *testing.T, gdb *gorm.DB, dialect queue.Dialect) {
	t.Helper()
	sqldb, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	q, err := queue.New(sqldb, log, 1, dialect)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(gdb, q, log, NewBroker(), &worker.Worker{DB: gdb, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/brew", Name: "Homebrew", Owner: "Homebrew", Languages: "Ruby"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Commit: "abc123", Status: db.ScanRunning, SkillName: "security-deep-dive", APIToken: "postgres-test-token"}
	if err := gdb.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	skill := db.Skill{Name: "dependencies", OutputKind: "dependencies"}
	if err := gdb.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	for _, row := range []any{
		&db.Scan{RepositoryID: repo.ID, SkillID: &skill.ID, Status: db.ScanDone, Commit: "deps-commit"},
		&db.Dependency{RepositoryID: repo.ID, Name: "example", ManifestPath: "go.mod"},
		&db.Finding{RepositoryID: repo.ID, ScanID: scan.ID, Title: "Homebrew finding", Severity: "High", Status: "open"},
		&db.Package{RepositoryID: repo.ID, Name: "Homebrew package"},
		&db.Advisory{RepositoryID: repo.ID, Title: "Homebrew advisory"},
		&db.Maintainer{Login: "Homebrew"},
		&db.CNA{ShortName: "Homebrew"},
	} {
		if err := gdb.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	handler := s.Handler()
	for _, tc := range []struct{ path, want string }{
		{"/repositories?q=homebrew", fmt.Sprintf(`id="repo-%d"`, repo.ID)},
		{"/repositories?language=ruby", fmt.Sprintf(`id="repo-%d"`, repo.ID)},
		{"/findings?q=homebrew", "Homebrew finding"},
		{"/packages?q=homebrew", "Homebrew package"},
		{"/advisories?q=homebrew", "Homebrew advisory"},
		{"/orgs?q=homebrew", "/orgs/Homebrew"},
		{"/maintainers?q=homebrew", "/maintainers/"},
		{"/api/cnas?q=homebrew", `"Homebrew"`},
		{"/scans?sort=repository", "Homebrew"},
		{fmt.Sprintf("/repositories/%d", repo.ID), "deps-commit"},
		{"/settings", "Settings"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			r := localReq(http.MethodGet, tc.path)
			r.Header.Set("Authorization", "Bearer "+scan.APIToken)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("GET %s: status %d, missing %q: %.500s", tc.path, w.Code, tc.want, w.Body.String())
			}
		})
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, localReq(http.MethodGet, "/repositories?q=missing"))
	if strings.Contains(w.Body.String(), fmt.Sprintf(`id="repo-%d"`, repo.ID)) {
		t.Fatal("search returned a nonmatching repository")
	}
}
