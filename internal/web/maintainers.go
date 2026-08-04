package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"scrutineer/internal/db"
)

const maintainerRepositoryCountSQL = `(
	SELECT COUNT(*)
	FROM repository_maintainers rm_count
	WHERE rm_count.maintainer_id = maintainers.id
)`

var maintainerFindingCountSQL = `(
	SELECT COUNT(f.id)
	FROM repository_maintainers rm_count
	JOIN findings f ON f.repository_id = rm_count.repository_id
	LEFT JOIN scans s ON s.id = f.scan_id
	WHERE rm_count.maintainer_id = maintainers.id
	  AND ` + aliasedFindingsScanFilter + `
)`

type maintainerListRow struct {
	db.Maintainer
	RepositoryCount int `gorm:"column:repository_count"`
	FindingCount    int `gorm:"column:finding_count"`
}

func (s *Server) maintainersList(w http.ResponseWriter, r *http.Request) {
	q := s.DB.Model(&db.Maintainer{})
	status := r.URL.Query().Get(statusKey)
	if status != "" {
		q = q.Where("status = ?", status)
	}
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	if search != "" {
		like := "%" + search + "%"
		q = q.Where("login LIKE ? OR name LIKE ? OR email LIKE ? OR company LIKE ? OR notes LIKE ?",
			like, like, like, like, like)
	}

	const nameSort = "name"
	sortCol, dir := splitSort(r.URL.Query().Get("sort"))
	switch sortCol {
	case "findings":
		q = q.Order(orderByExpr(maintainerFindingCountSQL, dir, true)).
			Order("CASE WHEN name = '' THEN 1 ELSE 0 END, name, login")
	case "repos":
		q = q.Order(orderByExpr(maintainerRepositoryCountSQL, dir, true)).
			Order("CASE WHEN name = '' THEN 1 ELSE 0 END, name, login")
	case "login":
		q = q.Order(orderByExpr("login", dir, false))
	case statusKey:
		q = q.Order(orderByExpr("status", dir, false)).Order("name")
	case "email":
		q = q.Order(orderByExpr("email", dir, false)).Order("name")
	case "company":
		q = q.Order(orderByExpr("company", dir, false)).Order("name")
	case "newest":
		q = q.Order(orderByExpr("id", dir, true))
	case nameSort:
		// Push empty names to the end regardless of direction.
		q = q.Order("CASE WHEN name = '' THEN 1 ELSE 0 END").
			Order(orderByExpr("name", dir, false)).Order("login")
	default:
		sortCol, dir = nameSort, ""
		q = q.Order("CASE WHEN name = '' THEN 1 ELSE 0 END, name, login")
	}
	sort := joinSort(sortCol, dir)

	var total int64
	q.Count(&total)
	page := paginate(r, total)

	var rows []maintainerListRow
	q.Select("maintainers.*, " + maintainerRepositoryCountSQL + " AS repository_count, " +
		maintainerFindingCountSQL + " AS finding_count").
		Limit(perPage).Offset((page.N - 1) * perPage).Scan(&rows)

	s.render(w, r, "maintainers.html", map[string]any{
		"Maintainers": rows,
		"Page":        page,
		"Status":      status,
		"Q":           search,
		"Sort":        sort,
	})
}

// maintainerDoNotContact flips the DoNotContact flag on a maintainer.
// Toggle semantics — form posts an explicit `value` of "true" or "false".
func (s *Server) maintainerDoNotContact(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	var m db.Maintainer
	if err := s.DB.First(&m, id).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	value := r.FormValue("value") == "true"
	if err := s.DB.Model(&db.Maintainer{}).Where("id = ?", m.ID).
		Update("do_not_contact", value).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/maintainers/%d", m.ID))
}

func (s *Server) maintainerShow(w http.ResponseWriter, r *http.Request) {
	var m db.Maintainer
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.DB.Preload("Repositories").First(&m, id).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	// Gather findings across all their repos
	repoIDs := make([]uint, 0, len(m.Repositories))
	for _, repo := range m.Repositories {
		repoIDs = append(repoIDs, repo.ID)
	}
	var findings []db.Finding
	if len(repoIDs) > 0 {
		// Same filter the Findings tab applies elsewhere: deep-dive only,
		// keeping scanner noise off the maintainer view used for disclosure
		// routing.
		s.DB.Where("repository_id IN ?", repoIDs).
			Where("scan_id IN (?)", findingsScanIDs(s.DB)).
			Order("id desc").Find(&findings)
	}
	reposByID := loadRepoMap(s.DB, findings, findingRepoID)
	s.render(w, r, "maintainer_show.html", map[string]any{
		"M": m, "Findings": findings, "Repos": reposByID,
	})
}
