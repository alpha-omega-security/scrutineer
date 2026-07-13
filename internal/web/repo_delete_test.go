package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

//nolint:maintidx // exhaustive fixture: seeds one of every linked table then asserts each is gone; splitting would scatter the coverage.
func TestRepoDelete_removesRepoAndAllLinkedData(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	// Pin to one connection and force foreign_keys ON so this test enforces
	// FK constraints exactly as production does — a pooled in-memory DB applies
	// the pragma to only one connection, which silently disables enforcement.
	sqldb, _ := s.DB.DB()
	sqldb.SetMaxOpenConns(1)
	if err := s.DB.Exec("PRAGMA foreign_keys=ON").Error; err != nil {
		t.Fatal(err)
	}

	dataDir := t.TempDir()
	s.Worker = &worker.Worker{DataDir: dataDir}

	repo := db.Repository{URL: "https://github.com/acme/doomed", Name: "doomed"}
	s.DB.Create(&repo)

	// A second repo whose data must survive the delete untouched.
	keep := db.Repository{URL: "https://github.com/acme/keep", Name: "keep"}
	s.DB.Create(&keep)
	keepScan := db.Scan{RepositoryID: keep.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&keepScan)
	s.DB.Create(&db.Finding{ScanID: keepScan.ID, RepositoryID: keep.ID, Title: "survivor", Severity: "High"})

	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&scan)
	finding := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "doomed finding", Severity: "High"}
	s.DB.Create(&finding)

	// A finding-scoped scan (verify/patch/exposure) carries scans.finding_id,
	// whose FK to findings is ON DELETE NO ACTION — this is what blocks naive
	// "delete findings then scans" ordering in production.
	verifyScan := db.Scan{RepositoryID: repo.ID, FindingID: &finding.ID, Kind: "skill",
		Status: db.ScanDone, SkillName: "verify"}
	s.DB.Create(&verifyScan)

	// A finding-scoped scan living on a *different* repo but pointing at the
	// doomed finding: it must survive (its repo is untouched) yet have its
	// finding_id link cleared, or the finding delete would 787 again.
	crossRepoScan := db.Scan{RepositoryID: keep.ID, FindingID: &finding.ID, Kind: "skill",
		Status: db.ScanDone, SkillName: "exposure"}
	s.DB.Create(&crossRepoScan)

	s.DB.Create(&db.FindingNote{FindingID: finding.ID, Body: "note"})
	s.DB.Create(&db.FindingCommunication{FindingID: finding.ID, Channel: "email", Direction: "outbound"})
	s.DB.Create(&db.FindingReference{FindingID: finding.ID, URL: "https://x/ref"})
	s.DB.Create(&db.FindingHistory{FindingID: finding.ID, Field: "status", NewValue: "new"})

	dependent := db.Dependent{RepositoryID: repo.ID, Name: "downstream", Ecosystem: "npm"}
	s.DB.Create(&dependent)
	s.DB.Create(&db.FindingDependent{FindingID: finding.ID, DependentID: dependent.ID, Status: db.ExposureKnownAffected})

	label := db.FindingLabel{Name: "wontfix"}
	s.DB.Create(&label)
	if err := s.DB.Model(&finding).Association("Labels").Append(&label); err != nil {
		t.Fatal(err)
	}

	s.DB.Create(&db.Subproject{RepositoryID: repo.ID, Path: "cli"})
	s.DB.Create(&db.Dependency{RepositoryID: repo.ID, Name: "left-pad", Ecosystem: "npm"})
	s.DB.Create(&db.Package{RepositoryID: repo.ID, Name: "acme-pkg", Ecosystem: "npm"})
	s.DB.Create(&db.Advisory{RepositoryID: repo.ID, Title: "CVE-2026-0001"})

	maintainer := db.Maintainer{Login: "alice", Name: "Alice", Status: db.MaintainerActive}
	s.DB.Create(&maintainer)
	if err := s.DB.Model(&repo).Association("Maintainers").Append(&maintainer); err != nil {
		t.Fatal(err)
	}

	upload := db.SBOMUpload{Name: "bom", Packages: []db.SBOMPackage{
		{Name: "acme-pkg", PURL: "pkg:npm/acme-pkg", RepositoryID: &repo.ID},
	}}
	s.DB.Create(&upload)

	// On-disk clone cache for the doomed repo.
	cacheDir := worker.RepoCacheRoot(dataDir, repo.URL)
	if err := os.MkdirAll(filepath.Join(cacheDir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "src", "file.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Per-scan workspaces and claude session stores left on disk (a scan that
	// crashed before its own cleanup, or a failed scan whose store is kept).
	doomedWS, doomedCfg := mkScanDirs(t, dataDir, scan.ID)
	verifyWS, _ := mkScanDirs(t, dataDir, verifyScan.ID)
	keepWS, _ := mkScanDirs(t, dataDir, keepScan.ID)

	r := httptest.NewRequest("POST", fmt.Sprintf("/repositories/%d/delete", repo.ID), nil)
	r.Host = testHost
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want 303; body=%s", w.Code, w.Body)
	}
	if loc := w.Header().Get("Location"); loc != "/" {
		t.Errorf("redirect Location = %q, want /", loc)
	}

	count := func(model any, where string, args ...any) int64 {
		var n int64
		s.DB.Model(model).Where(where, args...).Count(&n)
		return n
	}

	if n := count(&db.Repository{}, "id = ?", repo.ID); n != 0 {
		t.Errorf("repository row survived (%d)", n)
	}
	for name, n := range map[string]int64{
		"scans":        count(&db.Scan{}, "repository_id = ?", repo.ID),
		"findings":     count(&db.Finding{}, "repository_id = ?", repo.ID),
		"subprojects":  count(&db.Subproject{}, "repository_id = ?", repo.ID),
		"dependencies": count(&db.Dependency{}, "repository_id = ?", repo.ID),
		"dependents":   count(&db.Dependent{}, "repository_id = ?", repo.ID),
		"packages":     count(&db.Package{}, "repository_id = ?", repo.ID),
		"advisories":   count(&db.Advisory{}, "repository_id = ?", repo.ID),
		"notes":        count(&db.FindingNote{}, "finding_id = ?", finding.ID),
		"comms":        count(&db.FindingCommunication{}, "finding_id = ?", finding.ID),
		"refs":         count(&db.FindingReference{}, "finding_id = ?", finding.ID),
		"history":      count(&db.FindingHistory{}, "finding_id = ?", finding.ID),
		"findingdep":   count(&db.FindingDependent{}, "finding_id = ?", finding.ID),
	} {
		if n != 0 {
			t.Errorf("%s rows survived the delete (%d)", name, n)
		}
	}

	// The two join tables have no struct model; check them with raw SQL.
	for _, jt := range []struct {
		table, where string
		id           uint
	}{
		{"finding_labels_join", "finding_id", finding.ID},
		{"repository_maintainers", "repository_id", repo.ID},
	} {
		var n int64
		s.DB.Raw(fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s = ?", jt.table, jt.where), jt.id).Scan(&n)
		if n != 0 {
			t.Errorf("%s rows survived the delete (%d)", jt.table, n)
		}
	}

	// Shared / independent rows must survive.
	if n := count(&db.Maintainer{}, "id = ?", maintainer.ID); n != 1 {
		t.Errorf("maintainer (shared entity) should survive, got %d", n)
	}
	if n := count(&db.FindingLabel{}, "id = ?", label.ID); n != 1 {
		t.Errorf("label definition (shared entity) should survive, got %d", n)
	}

	// The SBOM upload and its package survive; only the repo cross-ref is nulled.
	if n := count(&db.SBOMUpload{}, "id = ?", upload.ID); n != 1 {
		t.Errorf("sbom upload should survive, got %d", n)
	}
	var pkg db.SBOMPackage
	s.DB.First(&pkg, upload.Packages[0].ID)
	if pkg.RepositoryID != nil {
		t.Errorf("sbom package repository_id should be nulled, got %v", *pkg.RepositoryID)
	}

	// The unrelated repo is untouched.
	if n := count(&db.Repository{}, "id = ?", keep.ID); n != 1 {
		t.Errorf("unrelated repo was deleted")
	}
	if n := count(&db.Finding{}, "repository_id = ?", keep.ID); n != 1 {
		t.Errorf("unrelated repo's findings were deleted")
	}
	// The cross-repo finding-scoped scan survives, but its dangling link is cleared.
	var survivor db.Scan
	if err := s.DB.First(&survivor, crossRepoScan.ID).Error; err != nil {
		t.Errorf("cross-repo scan should survive: %v", err)
	} else if survivor.FindingID != nil {
		t.Errorf("cross-repo scan finding_id should be nulled, got %v", *survivor.FindingID)
	}

	// On-disk clone cache is gone.
	if _, err := os.Stat(cacheDir); !os.IsNotExist(err) {
		t.Errorf("clone cache dir should be removed, stat err=%v", err)
	}
	// The doomed repo's per-scan workspaces and session stores are gone.
	for _, dir := range []string{doomedWS, doomedCfg, verifyWS} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("scan dir %s should be removed, stat err=%v", dir, err)
		}
	}
	// The unrelated repo's workspace is untouched.
	if _, err := os.Stat(keepWS); err != nil {
		t.Errorf("unrelated repo's scan workspace should survive: %v", err)
	}
}

// mkScanDirs creates the on-disk per-scan workspace and claude session store
// for id under dataDir, mirroring what a real scan leaves behind.
func mkScanDirs(t *testing.T, dataDir string, id uint) (ws, cfg string) {
	t.Helper()
	ws = filepath.Join(dataDir, fmt.Sprintf("scan-%d", id))
	cfg = filepath.Join(dataDir, "harness-state", fmt.Sprintf("scan-%d", id))
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg, 0o755); err != nil {
		t.Fatal(err)
	}
	return ws, cfg
}

// A repo with running and queued scans must warn in the delete confirm that
// those scans keep writing to disk until they finish — the followup to #310:
// deleting under a live scan leaves a worker writing into a removed inode.
func TestRepoDelete_confirmWarnsAboutActiveScans(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/acme/busy", Name: "busy"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanRunning, SkillName: deepDiveSkillName})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanQueued, SkillName: "verify"})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/repositories/%d", repo.ID)))
	if w.Code != 200 {
		t.Fatalf("detail status %d: %s", w.Code, w.Body)
	}
	// Count covers both running and queued, so the warning reports 2.
	if body := w.Body.String(); !strings.Contains(body, "2 scan(s) on busy are still running or queued and will keep writing to disk") {
		t.Errorf("delete confirm should warn about the 2 active scans; body=%s", body)
	}
}

// Neither terminal scans (done/failed/cancelled) nor a paused one are in the
// cancellable running/queued set, so the warning must stay out of the confirm
// while the base copy survives. The paused case pins the deliberate exclusion:
// it can't be cancelled and the worker isn't writing for it.
func TestRepoDelete_confirmNoWarningWhenNoActiveScans(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/acme/idle", Name: "idle"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanFailed, SkillName: "verify"})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanCancelled, SkillName: "exposure"})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanPaused, SkillName: "patch"})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/repositories/%d", repo.ID)))
	if w.Code != 200 {
		t.Fatalf("detail status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if strings.Contains(body, "still running or queued and will keep writing to disk") {
		t.Errorf("delete confirm must not warn when every scan is terminal; body=%s", body)
	}
	if !strings.Contains(body, "all its scans and findings, and its cached clone") {
		t.Errorf("base delete confirm copy missing; body=%s", body)
	}
}

func TestRepoDelete_unknownIs404(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	r := httptest.NewRequest("POST", "/repositories/999999/delete", nil)
	r.Host = testHost
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404 for unknown repo, got %d", w.Code)
	}
}

func TestRepoDiskSize_renderedInListAndSummary(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	// No FetchedAt: disk size must render in the summary regardless of
	// whether upstream metadata has been fetched (it renders unconditionally
	// in the list, so the detail page must match). DiskBytes is the cached
	// column the worker refreshes after each scan (#126); both pages read it.
	repo := db.Repository{URL: "https://github.com/acme/sized", Name: "sized", DiskBytes: 2048}
	s.DB.Create(&repo)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/"))
	if w.Code != 200 {
		t.Fatalf("list status %d: %s", w.Code, w.Body)
	}
	row := requireRepoListRow(t, w.Body.String(), repo.ID)
	if !strings.Contains(row, "2.0 KB") {
		t.Errorf("repo list row missing disk size, row=%s", row)
	}

	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/repositories/%d", repo.ID)))
	if w.Code != 200 {
		t.Fatalf("detail status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, "2.0 KB") {
		t.Errorf("repo detail summary missing disk size")
	}
	if !strings.Contains(body, "On-disk size of the cached clone") {
		t.Errorf("repo detail missing disk-size badge")
	}

	// The Delete action is present and its confirm copy matches what the
	// handler does (CLAUDE.md: confirm text must reflect the handler).
	if !strings.Contains(body, fmt.Sprintf("/repositories/%d/delete", repo.ID)) {
		t.Errorf("repo detail missing delete button")
	}
	if !strings.Contains(body, "all its scans and findings, and its cached clone") {
		t.Errorf("delete confirm copy does not describe what is removed")
	}
}

func TestRepoDiskUsage_localRepoIsZero(t *testing.T) {
	if n := worker.RepoDiskUsage(t.TempDir(), db.Repository{URL: "file:///srv/code/app"}); n != 0 {
		t.Errorf("local repo disk usage = %d, want 0 (no managed clone)", n)
	}
}
