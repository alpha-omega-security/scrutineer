package web

import (
	"cmp"
	"net/http"
	"slices"
	"strings"
	"time"

	"gorm.io/gorm"
	"scrutineer/internal/db"
)

const sortTemplateKey = "Sort"

type priorityScanStats struct {
	RepositoryID  uint
	FindingsTotal int
	LastScanID    uint
	LastScanAt    *time.Time
}

type priorityRepoRow struct {
	*db.RepositoryPriority
	priorityScanStats
}

func loadPriorityScanStats(g *gorm.DB) (map[uint]priorityScanStats, error) {
	var stats []priorityScanStats
	err := g.Model(&db.Repository{}).
		Select("repositories.id AS repository_id, (" + deepDiveFindingsCountSQL + ") AS findings_total, latest.id AS last_scan_id, latest.created_at AS last_scan_at").
		Joins("LEFT JOIN scans latest ON latest.id = (SELECT MAX(id) FROM scans WHERE scans.repository_id = repositories.id)").Scan(&stats).Error
	if err != nil {
		return nil, err
	}
	byRepo := make(map[uint]priorityScanStats, len(stats))
	for _, stat := range stats {
		byRepo[stat.RepositoryID] = stat
	}
	return byRepo, nil
}

func (s *Server) repoPriorities(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	view, err := db.LoadRepositoryPriorities(s.DB.WithContext(r.Context()), time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stats, err := loadPriorityScanStats(s.DB.WithContext(r.Context()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows := make([]priorityRepoRow, 0, len(view.Rows))
	for _, repo := range view.Rows {
		if priorityMatches(repo, r) {
			rows = append(rows, priorityRepoRow{repo, stats[repo.ID]})
		}
	}
	key, dir := splitSort(query.Get("sort"))
	if !slices.Contains([]string{"consumers", "oldest", "repository", findingsField, "scanned"}, key) {
		key, dir = "consumers", ""
	}
	sortPriorities(rows, key, dir)
	page := paginate(r, int64(len(rows)))
	start := min((page.N-1)*perPage, len(rows))
	data := map[string]any{
		"Priorities": true, "Rows": rows[start:min(start+perPage, len(rows))], "Page": page, "Cohort": view,
		sortTemplateKey: joinSort(key, dir), "Q": query.Get("q"), "Queue": query.Get("queue"), "Language": query.Get("language"),
	}
	if isHX(r) {
		s.render(w, r, "repo_priorities.html", data)
	} else {
		s.render(w, r, "index.html", data)
	}
}

func priorityMatches(repo *db.RepositoryPriority, r *http.Request) bool {
	query := r.URL.Query()
	if !strings.Contains(strings.ToLower(repo.URL), strings.ToLower(strings.TrimSpace(query.Get("q")))) {
		return false
	}
	if language := query.Get("language"); language != "" && !slices.ContainsFunc(strings.Split(repo.Languages, ","), func(l string) bool { return strings.EqualFold(strings.TrimSpace(l), language) }) {
		return false
	}
	switch query.Get("queue") {
	case "new":
		return repo.Inventory == nil
	case "refresh":
		return len(repo.Refresh) > 0
	case "review":
		return repo.Inventory != nil && len(repo.Signals) > 0
	}
	return true
}

func sortPriorities(rows []priorityRepoRow, key, dir string) {
	slices.SortFunc(rows, func(a, b priorityRepoRow) int {
		var order int
		switch key {
		case "consumers":
			order = cmp.Compare(len(a.Consumers), len(b.Consumers))
		case "oldest":
			order = priorityDate(a.RepositoryPriority).Compare(priorityDate(b.RepositoryPriority))
		case "repository":
			order = strings.Compare(a.URL, b.URL)
		case findingsField:
			order = cmp.Compare(a.FindingsTotal, b.FindingsTotal)
		case "scanned":
			order = cmp.Compare(a.LastScanID, b.LastScanID)
		}
		if wantDesc(dir, key == "consumers" || key == findingsField || key == "scanned") {
			order = -order
		}
		if order == 0 {
			return strings.Compare(a.URL, b.URL)
		}
		return order
	})
}

func priorityDate(repo *db.RepositoryPriority) time.Time {
	if repo.Inventory != nil && repo.Inventory.FinishedAt != nil {
		return *repo.Inventory.FinishedAt
	}
	return time.Time{}
}
