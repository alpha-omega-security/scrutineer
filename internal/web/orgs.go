package web

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"scrutineer/internal/db"
)

// parseAnyTime tries the handful of timestamp shapes SQLite gives us
// back when a column is read via a raw SELECT (no type hint). Returns
// (zero, false) for unparseable input so callers can decide what to do.
func parseAnyTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// orgRow is one row on the orgs index — an aggregate over all repos
// sharing the same Owner value.
type orgRow struct {
	Owner         string
	Repos         int
	FindingsTotal int
	LastActivity  *time.Time
}

func (s *Server) orgsList(w http.ResponseWriter, r *http.Request) {
	search := strings.TrimSpace(r.URL.Query().Get("q"))

	// SQLite returns MAX() over a datetime column as a string; scan into
	// a string and parse to *time.Time ourselves rather than fight GORM.
	type aggRow struct {
		Owner        string
		Repos        int
		LastActivity string
	}
	var aggs []aggRow
	q := s.DB.Model(&db.Repository{}).
		Select("owner, COUNT(*) AS repos, MAX(updated_at) AS last_activity").
		Where("owner != ''").
		Group("owner")
	if search != "" {
		q = q.Where("owner LIKE ?", "%"+search+"%")
	}
	q.Scan(&aggs)

	// One grouped query gets finding totals per owner.
	findingCounts := map[string]int{}
	if len(aggs) > 0 {
		type c struct {
			Owner string
			N     int
		}
		var counts []c
		// LEFT JOIN scans so the COUNT only includes the findings the Findings
		// tab shows — the LLM audits (security-deep-dive, vuln-scan) plus
		// operator imports, via aliasedFindingsScanFilter. Tool-scanner output
		// (zizmor, semgrep) is shown per-repo in the Scanners tab, not in
		// cross-org totals.
		s.DB.Raw(`
			SELECT r.owner, COUNT(f.id) AS n
			FROM repositories r
			LEFT JOIN findings f ON f.repository_id = r.id
			LEFT JOIN scans s ON s.id = f.scan_id
			WHERE r.owner != ''
			  AND `+aliasedFindingsScanFilter+`
			GROUP BY r.owner
		`, deepDiveSkillName, vulnScanSkillName).Scan(&counts)
		for _, x := range counts {
			findingCounts[x.Owner] = x.N
		}
	}

	rows := make([]orgRow, 0, len(aggs))
	for _, a := range aggs {
		row := orgRow{
			Owner:         a.Owner,
			Repos:         a.Repos,
			FindingsTotal: findingCounts[a.Owner],
		}
		if t, ok := parseAnyTime(a.LastActivity); ok {
			row.LastActivity = &t
		}
		rows = append(rows, row)
	}

	const nameSort = "name"
	sortBy := r.URL.Query().Get("sort")
	switch sortBy {
	case "findings":
		sortSlice(rows, func(a, b orgRow) bool { return a.FindingsTotal > b.FindingsTotal })
	case "repos":
		sortSlice(rows, func(a, b orgRow) bool { return a.Repos > b.Repos })
	case defaultSort:
		sortSlice(rows, func(a, b orgRow) bool {
			if a.LastActivity == nil {
				return false
			}
			if b.LastActivity == nil {
				return true
			}
			return a.LastActivity.After(*b.LastActivity)
		})
	default:
		sortBy = nameSort
		sortSlice(rows, func(a, b orgRow) bool {
			return strings.ToLower(a.Owner) < strings.ToLower(b.Owner)
		})
	}

	s.render(w, r, "orgs.html", map[string]any{
		"Orgs": rows, "Q": search, "Sort": sortBy,
	})
}

// sortSlice is a tiny wrapper so the handler reads like `sortSlice(rows,
// less)` without pulling sort.Slice's (i, j int) idiom into each case.
func sortSlice[T any](s []T, less func(a, b T) bool) {
	sort.Slice(s, func(i, j int) bool { return less(s[i], s[j]) })
}

func (s *Server) orgShow(w http.ResponseWriter, r *http.Request) {
	owner := r.PathValue("login")
	if owner == "" {
		http.NotFound(w, r)
		return
	}

	var repos []db.Repository
	s.DB.Where("owner = ?", owner).Order("name").Find(&repos)
	if len(repos) == 0 {
		http.NotFound(w, r)
		return
	}
	repoIDs := make([]uint, 0, len(repos))
	for _, r := range repos {
		repoIDs = append(repoIDs, r.ID)
	}

	// Per-repo finding count for the repos table, plus the full finding
	// list for the Findings tab. Scanner skills (zizmor, semgrep) are kept
	// out of both so the org summary matches the repo Findings tab; the
	// per-repo Scanners tab is where that output lives.
	findingCounts := map[uint]int{}
	type rowCount struct {
		RepositoryID uint
		N            int
	}
	var counts []rowCount
	s.DB.Model(&db.Finding{}).
		Select("repository_id, COUNT(*) AS n").
		Where("repository_id IN ?", repoIDs).
		Where("status NOT IN ?", db.ClosedFindingLifecycles).
		Where("scan_id IN (?)", findingsScanIDs(s.DB)).
		Group("repository_id").Scan(&counts)
	for _, c := range counts {
		findingCounts[c.RepositoryID] = c.N
	}

	const orgTabLimit = 200
	// Sort by severity (Critical→High→Medium→Low), then newest first
	// within a severity. Purely alphabetical severity would put Low
	// before Medium, which misreads for a stakeholder scanning the tab.
	category := r.URL.Query().Get("category")
	findingsQ := s.DB.Where("repository_id IN ?", repoIDs).
		Where("status NOT IN ?", db.ClosedFindingLifecycles).
		Where("scan_id IN (?)", findingsScanIDs(s.DB))
	if category != "" {
		findingsQ = applyCWECategoryFilter(findingsQ, category)
	}
	var findings []db.Finding
	findingsQ.Order(severityOrder).Order("id desc").
		Limit(orgTabLimit).Find(&findings)
	reposByID := loadRepoMap(s.DB, findings, findingRepoID)

	var advisories []db.Advisory
	s.DB.Where("repository_id IN ?", repoIDs).Order("cvss_score desc").
		Limit(orgTabLimit).Find(&advisories)
	advisoryRepos := loadRepoMap(s.DB, advisories, advisoryRepoID)

	var maintainers []db.Maintainer
	s.DB.Joins("JOIN repository_maintainers rm ON rm.maintainer_id = maintainers.id").
		Where("rm.repository_id IN ?", repoIDs).
		Distinct().Order("maintainers.name").Find(&maintainers)

	s.render(w, r, "org_show.html", map[string]any{
		"Owner":         owner,
		"Repos":         repos,
		"FindingCounts": findingCounts,
		"Findings":      findings,
		"FindingRepos":  reposByID,
		"Advisories":    advisories,
		"AdvisoryRepos": advisoryRepos,
		"Maintainers":   maintainers,
		"Category":      category,
		"Categories":    CWECategories(),
		"Uncategorized": UncategorizedCWE,
	})
}
