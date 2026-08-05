package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func TestFindingShowMigrationGuideRendersAlternativesAndDependents(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{
		URL:      "https://github.com/example/zombie",
		Name:     "zombie",
		FullName: "example/zombie",
		Archived: true,
		Health:   db.RepositoryHealthAbandoned,
	}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: "security-deep-dive"}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	finding := db.Finding{
		RepositoryID: repo.ID,
		ScanID:       scan.ID,
		Title:        "Unsafe parser",
		Severity:     "High",
		Status:       db.FindingTriaged,
	}
	if err := s.DB.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}
	pkg := db.Package{
		RepositoryID:   repo.ID,
		Name:           "zombie",
		Ecosystem:      "npm",
		PURL:           "pkg:npm/zombie",
		LatestVersion:  "1.2.3",
		DependentRepos: 1200,
	}
	if err := s.DB.Create(&pkg).Error; err != nil {
		t.Fatal(err)
	}
	for i, count := range []int{800, 1000, 1200} {
		if err := s.DB.Create(&db.DependentCountSnapshot{
			RepositoryID:   repo.ID,
			DependentRepos: count,
			ObservedAt:     time.Date(2026, time.January+time.Month(i), 1, 0, 0, 0, 0, time.UTC),
		}).Error; err != nil {
			t.Fatal(err)
		}
	}
	alt := db.PackageAlternative{
		RepositoryID: repo.ID,
		PURL:         "pkg:npm/zombie-next",
		Kind:         db.PackageAlternativeSuccessor,
		Note:         "Maintained successor with compatible parser API",
	}
	if err := s.DB.Create(&alt).Error; err != nil {
		t.Fatal(err)
	}
	dep := db.Dependent{
		RepositoryID:   repo.ID,
		Name:           "consumer",
		Ecosystem:      "npm",
		RepositoryURL:  "https://github.com/example/consumer",
		DependentRepos: 300,
	}
	if err := s.DB.Create(&dep).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&db.FindingDependent{
		FindingID:      finding.ID,
		DependentID:    dep.ID,
		Status:         db.ExposureKnownAffected,
		Rationale:      "consumer reaches the vulnerable parser",
		CampaignStatus: db.CampaignNotified,
		CampaignNote:   "issue opened with consumer",
	}).Error; err != nil {
		t.Fatal(err)
	}
	needsReview := db.Dependent{
		RepositoryID:   repo.ID,
		Name:           "needs-review",
		Ecosystem:      "npm",
		RepositoryURL:  "https://github.com/example/needs-review",
		DependentRepos: 200,
	}
	if err := s.DB.Create(&needsReview).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&db.FindingDependent{
		FindingID:   finding.ID,
		DependentID: needsReview.ID,
	}).Error; err != nil {
		t.Fatal(err)
	}
	for i := range migrationGuideRowLimit {
		safe := db.Dependent{
			RepositoryID:   repo.ID,
			Name:           fmt.Sprintf("safe-%02d", i),
			Ecosystem:      "npm",
			RepositoryURL:  fmt.Sprintf("https://github.com/example/safe-%02d", i),
			DependentRepos: 1000 - i,
		}
		if err := s.DB.Create(&safe).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.DB.Create(&db.FindingDependent{
			FindingID:   finding.ID,
			DependentID: safe.ID,
			Status:      db.ExposureKnownNotAffected,
		}).Error; err != nil {
			t.Fatal(err)
		}
	}
	fixed := db.Dependent{
		RepositoryID:   repo.ID,
		Name:           "fixed-consumer",
		Ecosystem:      "npm",
		RepositoryURL:  "https://github.com/example/fixed-consumer",
		DependentRepos: 700,
	}
	if err := s.DB.Create(&fixed).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&db.FindingDependent{
		FindingID:   finding.ID,
		DependentID: fixed.ID,
		Status:      db.ExposureFixed,
	}).Error; err != nil {
		t.Fatal(err)
	}
	trackedFixed := db.Dependent{
		RepositoryID:   repo.ID,
		Name:           "migrated-consumer",
		Ecosystem:      "npm",
		RepositoryURL:  "https://github.com/example/migrated-consumer",
		DependentRepos: 600,
	}
	if err := s.DB.Create(&trackedFixed).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&db.FindingDependent{
		FindingID:      finding.ID,
		DependentID:    trackedFixed.ID,
		Status:         db.ExposureFixed,
		CampaignStatus: db.CampaignMigrated,
		CampaignNote:   "released with the successor",
	}).Error; err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d", finding.ID)))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{
		"Migration guide",
		string(db.RepositoryHealthAbandoned),
		"pkg:npm/zombie",
		"pkg:npm/zombie-next",
		"Maintained successor",
		"Dependent reach over time",
		"3 observations from 2026-01-01 to 2026-03-01",
		"Latest: 1200 repos",
		"Change: +400",
		"Peak 1200",
		"consumer reaches the vulnerable parser",
		"issue opened with consumer",
		`value="notified" selected`,
		"migrated-consumer",
		"released with the successor",
		`value="migrated" selected`,
		"needs-review",
		db.ExposureUnderInvestigation,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("finding page missing %q:\n%s", want, body)
		}
	}
	guideStart := strings.Index(body, "Migration guide")
	if guideStart < 0 {
		t.Fatalf("finding page missing migration guide:\n%s", body)
	}
	guide := body[guideStart:]
	if end := strings.Index(guide, "Fix validation"); end >= 0 {
		guide = guide[:end]
	}
	if strings.Contains(guide, "safe-00") {
		t.Fatalf("known-not-affected dependent should not be prioritized in migration guide:\n%s", guide)
	}
	if strings.Contains(guide, "fixed-consumer") {
		t.Fatalf("fixed dependent should not be prioritized in migration guide:\n%s", guide)
	}

	assertSingleObservationTrend(t, s, repo.ID, finding.ID)
}

func assertSingleObservationTrend(t *testing.T, s *Server, repoID, findingID uint) {
	t.Helper()
	if err := s.DB.Where("repository_id = ?", repoID).Delete(&db.DependentCountSnapshot{}).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&db.DependentCountSnapshot{
		RepositoryID:   repoID,
		DependentRepos: 900,
		ObservedAt:     time.Date(2026, time.April, 1, 0, 0, 0, 0, time.UTC),
	}).Error; err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d", findingID)))
	if w.Code != http.StatusOK {
		t.Fatalf("single-observation status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, "1 observation from 2026-04-01 to 2026-04-01; latest count 900.") {
		t.Fatalf("single-observation description is missing:\n%s", body)
	}
	if strings.Contains(body, "Change:") || strings.Contains(body, "latest count 900, change") {
		t.Fatalf("single-observation trend announces a meaningless change:\n%s", body)
	}
}

func TestLoadDependentCountTrendKeepsLatestObservationsInChronologicalOrder(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/example/history", Name: "history"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	start := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	for i := range dependentCountHistoryLimit + 2 {
		if err := s.DB.Create(&db.DependentCountSnapshot{
			RepositoryID:   repo.ID,
			DependentRepos: i,
			ObservedAt:     start.AddDate(0, i, 0),
		}).Error; err != nil {
			t.Fatal(err)
		}
	}

	trend, err := loadDependentCountTrend(s.DB, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if trend == nil {
		t.Fatal("trend is nil")
	}
	if trend.SampleSize != dependentCountHistoryLimit {
		t.Fatalf("sample size = %d, want %d", trend.SampleSize, dependentCountHistoryLimit)
	}
	if trend.Points[0].DependentRepos != 2 || trend.Latest != dependentCountHistoryLimit+1 {
		t.Fatalf("trend endpoints = first %d latest %d, want 2 and %d", trend.Points[0].DependentRepos, trend.Latest, dependentCountHistoryLimit+1)
	}
	if len(trend.Segments) != dependentCountHistoryLimit-1 {
		t.Errorf("segments = %d, want %d", len(trend.Segments), dependentCountHistoryLimit-1)
	}
	for i := 1; i < len(trend.Points); i++ {
		if trend.Points[i].X <= trend.Points[i-1].X {
			t.Fatalf("point %d x=%d does not follow point %d x=%d", i, trend.Points[i].X, i-1, trend.Points[i-1].X)
		}
	}
}

func TestLoadMigrationGuideDependentsKeepsTrackedResolvedRowsOutsideLimit(t *testing.T) {
	exposureRows := make([]db.FindingDependent, 0, migrationGuideRowLimit+2)
	dependentsByID := make(map[uint]db.Dependent, migrationGuideRowLimit+2)
	for i := range migrationGuideRowLimit + 1 {
		id := uint(i + 1)
		name := fmt.Sprintf("actionable-%02d", i)
		dependentsByID[id] = db.Dependent{
			ID:             id,
			Name:           name,
			DependentRepos: 1000 - i,
		}
		exposureRows = append(exposureRows, db.FindingDependent{
			DependentID: id,
			Status:      db.ExposureKnownAffected,
		})
	}

	const trackedID = 100
	dependentsByID[trackedID] = db.Dependent{
		ID:             trackedID,
		Name:           "tracked-fixed",
		DependentRepos: 1,
	}
	exposureRows = append(exposureRows, db.FindingDependent{
		DependentID:    trackedID,
		Status:         db.ExposureFixed,
		CampaignStatus: db.CampaignMigrated,
		CampaignNote:   "migration complete",
	})

	var guide findingMigrationGuide
	loadMigrationGuideDependents(exposureRows, dependentsByID, &guide)
	if got, want := len(guide.PriorityDependents), migrationGuideRowLimit+1; got != want {
		t.Fatalf("priority rows = %d, want %d", got, want)
	}
	if got := guide.PriorityDependents[len(guide.PriorityDependents)-1]; got.DependentID != trackedID || got.CampaignStatus != db.CampaignMigrated {
		t.Fatalf("last priority row = %+v, want tracked resolved campaign", got)
	}
	for _, row := range guide.PriorityDependents {
		if row.Name == "actionable-10" {
			t.Fatal("actionable row beyond the top-10 cap was retained")
		}
	}
}

func TestFindingDependentCampaignUpdate(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/example/zombie", Health: db.RepositoryHealthZombie}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	finding := db.Finding{RepositoryID: repo.ID, ScanID: scan.ID, Title: "Bug", Status: db.FindingTriaged}
	if err := s.DB.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}
	otherFinding := db.Finding{RepositoryID: repo.ID, ScanID: scan.ID, Title: "Other bug", Status: db.FindingTriaged}
	if err := s.DB.Create(&otherFinding).Error; err != nil {
		t.Fatal(err)
	}
	dependent := db.Dependent{RepositoryID: repo.ID, Name: "consumer"}
	if err := s.DB.Create(&dependent).Error; err != nil {
		t.Fatal(err)
	}
	otherDependent := db.Dependent{RepositoryID: repo.ID, Name: "other-consumer"}
	if err := s.DB.Create(&otherDependent).Error; err != nil {
		t.Fatal(err)
	}
	exposureAt := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	row := db.FindingDependent{
		FindingID: finding.ID, DependentID: dependent.ID,
		Status: db.ExposureKnownAffected, UpdatedAt: exposureAt,
	}
	if err := s.DB.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&db.FindingDependent{
		FindingID: otherFinding.ID, DependentID: otherDependent.ID,
		Status: db.ExposureKnownAffected,
	}).Error; err != nil {
		t.Fatal(err)
	}

	path := fmt.Sprintf("/findings/%d/dependents/%d/campaign", finding.ID, dependent.ID)
	w := postForm(t, s, path, url.Values{
		"status": {string(db.CampaignAcked)},
		"note":   {"  maintainer confirmed migration plan  "},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var stored db.FindingDependent
	if err := s.DB.First(&stored, row.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.CampaignStatus != db.CampaignAcked || stored.CampaignNote != "maintainer confirmed migration plan" || stored.CampaignUpdatedAt == nil {
		t.Fatalf("stored campaign = %+v", stored)
	}
	if !stored.UpdatedAt.Equal(exposureAt) {
		t.Errorf("campaign update changed exposure timestamp: got %v, want %v", stored.UpdatedAt, exposureAt)
	}

	w = postForm(t, s, path, url.Values{"status": {"invalid"}})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid status code = %d, want %d", w.Code, http.StatusUnprocessableEntity)
	}
	w = postForm(t, s,
		fmt.Sprintf("/findings/%d/dependents/%d/campaign", finding.ID, otherDependent.ID),
		url.Values{"status": {string(db.CampaignDeclined)}},
	)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-finding status code = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestFindingShowMigrationGuideSummarizesNonActionableDependents(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{
		URL:      "https://github.com/example/quiet-zombie",
		Name:     "quiet-zombie",
		FullName: "example/quiet-zombie",
		Archived: true,
		Health:   db.RepositoryHealthAbandoned,
	}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: "security-deep-dive"}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	finding := db.Finding{
		RepositoryID: repo.ID,
		ScanID:       scan.ID,
		Title:        "Fixed everywhere",
		Severity:     "High",
		Status:       db.FindingTriaged,
	}
	if err := s.DB.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name   string
		status string
	}{
		{name: "safe-consumer", status: db.ExposureKnownNotAffected},
		{name: "fixed-consumer", status: db.ExposureFixed},
	} {
		dep := db.Dependent{
			RepositoryID:   repo.ID,
			Name:           row.name,
			Ecosystem:      "npm",
			RepositoryURL:  "https://github.com/example/" + row.name,
			DependentRepos: 100,
		}
		if err := s.DB.Create(&dep).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.DB.Create(&db.FindingDependent{
			FindingID:   finding.ID,
			DependentID: dep.ID,
			Status:      row.status,
		}).Error; err != nil {
			t.Fatal(err)
		}
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d", finding.ID)))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{
		"Exposure tracking has 2 rows",
		"1 known not affected",
		"1 fixed",
		"No affected or under-investigation dependents need migration follow-up yet",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("finding page missing %q:\n%s", want, body)
		}
	}
}

func TestFindingShowMigrationGuideHiddenForActiveRepoWithoutAlternatives(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{
		URL:      "https://github.com/example/active",
		Name:     "active",
		FullName: "example/active",
		Health:   db.RepositoryHealthActive,
	}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: "security-deep-dive"}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	finding := db.Finding{RepositoryID: repo.ID, ScanID: scan.ID, Title: "Bug", Severity: "Medium", Status: db.FindingTriaged}
	if err := s.DB.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d", finding.ID)))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if body := w.Body.String(); strings.Contains(body, "Migration guide") {
		t.Fatalf("active repo without alternatives should not show migration guide:\n%s", body)
	}
}
