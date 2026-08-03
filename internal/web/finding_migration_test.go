package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
		FindingID:   finding.ID,
		DependentID: dep.ID,
		Status:      db.ExposureKnownAffected,
		Rationale:   "consumer reaches the vulnerable parser",
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
		"consumer reaches the vulnerable parser",
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
