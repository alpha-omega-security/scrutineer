package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/git-pkgs/sbom"
	"gorm.io/gorm"

	"scrutineer/internal/db"
)

const (
	sbomMaxUploadBytes = 32 << 20
	sbomResolveTimeout = 10 * time.Minute
)

func (s *Server) registerSBOMRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /sboms", s.sbomList)
	mux.HandleFunc("GET /sboms/new", s.sbomNew)
	mux.HandleFunc("POST /sboms", s.sbomUpload)
	mux.HandleFunc("GET /sboms/{id}", s.sbomShow)
	mux.HandleFunc("POST /sboms/{id}/confirm", s.sbomConfirm)
	mux.HandleFunc("POST /sboms/{id}/resolve", s.sbomResolve)
	mux.HandleFunc("POST /sboms/{id}/delete", s.sbomDelete)
}

func (s *Server) sbomList(w http.ResponseWriter, r *http.Request) {
	q := s.DB.Model(&db.SBOMUpload{})
	sortCol, dir := splitSort(r.URL.Query().Get("sort"))
	switch sortCol {
	case "name":
		q = q.Order(orderByExpr("name", dir, false)).Order("id desc")
	case "format":
		q = q.Order(orderByExpr("format", dir, false)).Order("id desc")
	case "packages":
		q = q.Order(orderByExpr("package_count", dir, true)).Order("id desc")
	case "uploaded":
		q = q.Order(orderByExpr("created_at", dir, true)).Order("id desc")
	default:
		sortCol, dir = defaultSort, ""
		q = q.Order("id desc")
	}
	sort := joinSort(sortCol, dir)

	var total int64
	q.Count(&total)
	page := paginate(r, total)
	var rows []db.SBOMUpload
	q.Limit(perPage).Offset((page.N - 1) * perPage).Find(&rows)
	s.render(w, r, "sboms.html", map[string]any{"SBOMs": rows, "Page": page, "Sort": sort})
}

func (s *Server) sbomNew(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "sbom_new.html", nil)
}

func (s *Server) sbomUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, sbomMaxUploadBytes)
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	doc, err := sbom.Parse(data)
	if err != nil {
		http.Error(w, "parse SBOM: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}

	up := db.SBOMUpload{
		Name:          firstNonEmpty(doc.Document.Name, header.Filename),
		Filename:      header.Filename,
		Format:        string(doc.Type),
		SpecVersion:   doc.SpecVersion,
		Raw:           data,
		PackageCount:  len(doc.Packages),
		ImportPending: true,
	}
	scope := doc.ClassifyScope()
	for _, p := range doc.Packages {
		up.Packages = append(up.Packages, db.SBOMPackage{
			Name:      p.Name,
			Version:   p.Version,
			PURL:      p.PURL(),
			Ecosystem: purlType(p.PURL()),
			License:   firstNonEmpty(p.LicenseDeclared, p.LicenseConcluded),
			Scope:     scope[p.ID],
		})
	}
	if err := s.DB.Create(&up).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.redirect(w, r, fmt.Sprintf("/sboms/%d", up.ID))
}

type sbomScopeCounts struct {
	Direct     int
	Transitive int
	Unknown    int
}

func countSBOMScopes(pkgs []db.SBOMPackage) sbomScopeCounts {
	var counts sbomScopeCounts
	for _, p := range pkgs {
		switch p.Scope {
		case sbom.ScopeDirect:
			counts.Direct++
		case sbom.ScopeTransitive:
			counts.Transitive++
		default:
			counts.Unknown++
		}
	}
	return counts
}

// anyPackageHasScope reports whether at least one package carries a
// direct/transitive scope value; flat-list SBOMs leave them all blank, in
// which case the scope filter is hidden.
func anyPackageHasScope(pkgs []db.SBOMPackage) bool {
	for _, p := range pkgs {
		if p.Scope != "" {
			return true
		}
	}
	return false
}

func (s *Server) sbomShow(w http.ResponseWriter, r *http.Request) {
	var up db.SBOMUpload
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.DB.Preload("Packages.Repository").First(&up, id).Error; err != nil {
		http.NotFound(w, r)
		return
	}

	hasScope := anyPackageHasScope(up.Packages)
	scopeCounts := countSBOMScopes(up.Packages)

	scope := r.URL.Query().Get("scope")
	pkgs := up.Packages
	if hasScope && (scope == sbom.ScopeDirect || scope == sbom.ScopeTransitive) {
		filtered := make([]db.SBOMPackage, 0, len(up.Packages))
		for _, p := range up.Packages {
			if p.Scope == scope {
				filtered = append(filtered, p)
			}
		}
		pkgs = filtered
	} else {
		scope = ""
	}

	reposByID := make(map[uint]db.Repository)
	for _, p := range pkgs {
		if p.Repository != nil {
			reposByID[p.Repository.ID] = *p.Repository
		}
	}
	repoIDs := make([]uint, 0, len(reposByID))
	for id := range reposByID {
		repoIDs = append(repoIDs, id)
	}

	sortCol, dir := splitSort(r.URL.Query().Get("sort"))
	var findings []db.Finding
	var findingsTotal int64
	var advisories []db.Advisory
	var advisoriesTotal int64
	if len(repoIDs) > 0 {
		// Deep-dive findings only — the SBOM "Findings" tab is a
		// downstream-impact view, where lint output from per-repo scanners
		// (zizmor, semgrep) would be misleading at this level.
		q := s.DB.Where("repository_id IN ? AND status NOT IN ?", repoIDs, db.ClosedFindingLifecycles).
			Where("scan_id IN (?)", findingsScanIDs(s.DB))
		if sev := r.URL.Query().Get("severity"); sev != "" {
			q = q.Where("severity = ?", sev)
		}
		if category := r.URL.Query().Get("category"); category != "" {
			q = applyCWECategoryFilter(q, category)
		}
		switch sortCol {
		case sortSeverity:
			// severityOrder ranks the most severe LOWEST, so the "desc" logical
			// default is ascending on the expression; !wantDesc flips it.
			q = q.Order(orderBySuffix("("+severityOrder+")", !wantDesc(dir, true))).Order("findings.id desc")
		case sortRepository:
			q = q.Joins("JOIN repositories r ON r.id = findings.repository_id").
				Order(orderByExpr("r.name", dir, false)).Order("findings.id desc")
		default:
			sortCol, dir = defaultSort, ""
			q = q.Order("id desc")
		}
		q.Model(&db.Finding{}).Count(&findingsTotal)
		q.Limit(tabRowCap).Find(&findings)

		advQ := s.DB.Where("repository_id IN ? AND withdrawn_at IS NULL", repoIDs)
		advQ.Model(&db.Advisory{}).Count(&advisoriesTotal)
		advQ.Order("cvss_score desc, published_at desc").Limit(tabRowCap).Find(&advisories)
	}

	resolved, withRepo := 0, 0
	for _, p := range pkgs {
		if p.RepositoryID != nil || p.ResolveError != "" {
			resolved++
		}
		if p.RepositoryID != nil {
			withRepo++
		}
	}

	s.render(w, r, "sbom_show.html", map[string]any{
		"SBOM": up, "Packages": pkgs,
		"Findings": findings, "FindingsTotal": findingsTotal,
		"Advisories": advisories, "AdvisoriesTotal": advisoriesTotal,
		"Repos":    reposByID,
		"Resolved": resolved, "WithRepo": withRepo,
		"Severity": r.URL.Query().Get("severity"), "Sort": joinSort(sortCol, dir),
		"Category":   r.URL.Query().Get("category"),
		"Categories": CWECategories(), "Uncategorized": UncategorizedCWE,
		"Scope": scope, "HasScope": hasScope, "ScopeCounts": scopeCounts,
	})
}

// sbomConfirm starts repository resolution for a newly parsed SBOM. The
// conditional update makes a repeated click harmless: only the first request
// changes the pending state and launches the background resolver.
func (s *Server) sbomConfirm(w http.ResponseWriter, r *http.Request) {
	up, ok := loadByID[db.SBOMUpload](s, w, r)
	if !ok {
		return
	}
	result := s.DB.Model(&db.SBOMUpload{}).
		Where("id = ? AND import_pending = ?", up.ID, true).
		Update("import_pending", false)
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}
	if result.RowsAffected > 0 {
		s.goResolve(up.ID)
		setFlash(w, Flash{Category: successKey, Title: fmt.Sprintf("Importing %d SBOM packages", up.PackageCount)})
	}
	s.redirect(w, r, fmt.Sprintf("/sboms/%d", up.ID))
}

func (s *Server) sbomResolve(w http.ResponseWriter, r *http.Request) {
	up, ok := loadByID[db.SBOMUpload](s, w, r)
	if !ok {
		return
	}
	if up.ImportPending {
		http.Error(w, "confirm SBOM import before resolving repositories", http.StatusConflict)
		return
	}
	s.goResolve(up.ID)
	s.redirect(w, r, fmt.Sprintf("/sboms/%d", up.ID))
}

// goResolve launches resolveSBOMPackages. Indirected so tests can run it
// synchronously and avoid racing the in-memory database teardown.
func (s *Server) goResolve(uploadID uint) {
	if s.resolveSync {
		s.resolveSBOMPackages(uploadID)
		return
	}
	go s.resolveSBOMPackages(uploadID)
}

func (s *Server) sbomDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Delete the upload's packages explicitly inside one transaction rather
	// than leaning on the SBOMUpload.Packages ON DELETE CASCADE: sqlite's
	// foreign_keys pragma is per-connection and enforced on only one pooled
	// connection, so the cascade silently no-ops on most serving connections
	// and orphans the package rows (same reason repoDelete deletes children
	// by hand).
	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("sbom_upload_id = ?", id).Delete(&db.SBOMPackage{}).Error; err != nil {
			return err
		}
		return tx.Delete(&db.SBOMUpload{}, id).Error
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, "/sboms")
}

// resolveSBOMPackages walks every unresolved package in the upload, looks up
// its source repository via packages.ecosyste.ms, FirstOrCreates the repo,
// enqueues the default triage skill if the repo is new, and links the
// package row. Runs in the background after the operator confirms import so the page can render
// immediately.
func (s *Server) resolveSBOMPackages(uploadID uint) {
	ctx, cancel := context.WithTimeout(context.Background(), sbomResolveTimeout)
	defer cancel()

	var pkgs []db.SBOMPackage
	s.DB.Where("sbom_upload_id = ? AND repository_id IS NULL", uploadID).Find(&pkgs)

	for i := range pkgs {
		p := &pkgs[i]
		if p.PURL == "" {
			s.DB.Model(p).Update("resolve_error", "no purl")
			continue
		}
		repoURL := s.resolvePURL(ctx, p.PURL)
		if repoURL == "" {
			s.DB.Model(p).Update("resolve_error", "no repository_url for purl")
			continue
		}
		input, err := ParseRepoInput(repoURL)
		if err != nil {
			s.DB.Model(p).Update("resolve_error", err.Error())
			continue
		}
		repo, _, err := s.createOrTriageRepo(ctx, input, "", p.Scope != sbom.ScopeTransitive)
		if err != nil {
			s.DB.Model(p).Update("resolve_error", err.Error())
			continue
		}
		s.DB.Model(p).Updates(map[string]any{"repository_id": repo.ID, "resolve_error": ""})
	}
}

// purlType returns the ecosystem segment of a Package URL (the bit between
// "pkg:" and the first "/").
func purlType(purl string) string {
	const prefix = "pkg:"
	if !strings.HasPrefix(purl, prefix) {
		return ""
	}
	rest := purl[len(prefix):]
	if i := strings.IndexByte(rest, '/'); i > 0 {
		return rest[:i]
	}
	return rest
}
