package web

import (
	"net/http"
	"net/http/httptest"
	"scrutineer/internal/db"
	"scrutineer/internal/worker"
	"strings"
	"testing"
)

func TestOveragePauseBannerAfterRestart(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker = &worker.Worker{DB: s.DB, PauseOnOverage: true, DowngradeOnOverage: true}
	repo := db.Repository{URL: "https://example.com/overage", Name: "overage"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanPaused, Error: worker.OveragePauseReason}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/scans", "/usage"} {
		result := httptest.NewRecorder()
		s.Handler().ServeHTTP(result, localReq(http.MethodGet, path))
		if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), "Subscription overage: model scans are paused") {
			t.Fatalf("%s missing pause banner: status=%d", path, result.Code)
		}
		if strings.Contains(result.Body.String(), "Model fallback active.") {
			t.Fatal("downgrade banner displayed while paused")
		}
	}
}
