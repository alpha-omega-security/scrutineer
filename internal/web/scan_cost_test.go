package web

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

// A scan with tokens but no cost ran against a model nothing prices. It must
// not read "-", which is what a scan that never reached the model shows.
func TestScanCostShowsUnpricedRuns(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/cost", Name: "cost"}
	s.DB.Create(&repo)
	priced := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "priced", Status: db.ScanDone,
		Model: "claude-opus-5", CostUSD: 1.25, InputTokens: 100}
	unpriced := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "unpriced", Status: db.ScanFailed,
		Model: "openrouter/meta/muse-spark-1.3-contributor", InputTokens: 28400, CacheReadTokens: 121100, OutputTokens: 2521}
	unused := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "unused", Status: db.ScanFailed, Model: "claude-opus-5"}
	for _, sc := range []*db.Scan{&priced, &unpriced, &unused} {
		if err := s.DB.Create(sc).Error; err != nil {
			t.Fatal(err)
		}
	}

	const tooltip = `data-tooltip="Tokens were recorded but no price is known for openrouter/meta/muse-spark-1.3-contributor">unpriced</span>`
	fragment := httptest.NewRecorder()
	r := localReq("GET", fmt.Sprintf("/repositories/%d/scans", repo.ID))
	r.Header.Set("HX-Request", "true")
	s.Handler().ServeHTTP(fragment, r)
	lists := map[string]string{
		"scan list":     getRepoPagePath(t, s, "/scans"),
		"repo page":     getRepoPage(t, s, repo.ID),
		"repo fragment": fragment.Body.String(),
	}
	for name, body := range lists {
		rows := map[*db.Scan]string{}
		for _, sc := range []*db.Scan{&priced, &unpriced, &unused} {
			rows[sc] = scanRow(t, body, fmt.Sprintf(`<tr id="scan-%d"`, sc.ID))
		}
		if !strings.Contains(rows[&priced], "$1.25") {
			t.Errorf("%s: priced row lost its cost: %s", name, rows[&priced])
		}
		if !strings.Contains(rows[&unpriced], tooltip) {
			t.Errorf("%s: unpriced row does not say unpriced: %s", name, rows[&unpriced])
		}
		if strings.Contains(rows[&unused], "unpriced") {
			t.Errorf("%s: row without usage reads unpriced: %s", name, rows[&unused])
		}
	}

	scanPage := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d", unpriced.ID))
	if !strings.Contains(scanPage, tooltip) {
		t.Error("scan page does not say the cost is unpriced")
	}
	if page := getRepoPagePath(t, s, fmt.Sprintf("/scans/%d", unused.ID)); strings.Contains(page, ">unpriced<") {
		t.Error("scan page without usage reads unpriced")
	}
}
