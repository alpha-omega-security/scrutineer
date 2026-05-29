package web

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
	"scrutineer/internal/worker"
)

// ErrSkillRequiresRemote is returned by enqueueSkillWith when the caller
// asks to run a `requires_remote` skill against a local-directory repo.
// The API layer maps it to 404 so triage's existing "skill not found or
// inactive" skip branch handles it without needing a new bucket.
var ErrSkillRequiresRemote = errors.New("skill requires a remote repository")

// ErrSkillProfileMismatch is returned by enqueueSkillWith when the caller
// forces a runner profile that does not match the skill's required one.
// The API layer maps it to 400 so the operator gets immediate feedback
// instead of a ghost scan failing on the worker.
var ErrSkillProfileMismatch = errors.New("skill requires a different runner profile")

//go:embed templates/*.html
var tmplFS embed.FS

//go:embed static
var staticFS embed.FS

type Server struct {
	DB     *gorm.DB
	Queue  *queue.Queue
	Log    *slog.Logger
	Broker *Broker
	Worker *worker.Worker
	tmpl   *template.Template

	// SkillsRepoSHA pins the commit of -skills-repo loaded at startup. Set
	// once by main after loadSkills resolves it; stamped onto every Scan
	// row enqueueSkillWith creates so two runs a week apart can be told
	// apart even if the upstream branch has moved. Empty when -skills-repo
	// is not configured.
	SkillsRepoSHA string

	// resolvePURL maps a Package URL to its source repository URL via
	// packages.ecosyste.ms. Field rather than direct call so tests can
	// stub the network lookup.
	resolvePURL func(ctx context.Context, purl string) string
	resolveSync bool

	skillNamesMu    sync.Mutex
	skillNamesCache []string
	skillNamesTTL   time.Time
}

// displaySeverity maps any known casing of a severity string to its
// canonical Title-case form. Advisory rows come from
// advisories.ecosyste.ms upper-cased and use MODERATE; findings use
// Title case with Medium.
func displaySeverity(s string) string {
	switch s {
	case "Critical", "CRITICAL":
		return "Critical"
	case "High", "HIGH":
		return "High"
	case "Medium", "MEDIUM", "MODERATE":
		return "Medium"
	case "Low", "LOW":
		return "Low"
	}
	return s
}

func New(gdb *gorm.DB, q *queue.Queue, log *slog.Logger, broker *Broker, w *worker.Worker) (*Server, error) {
	funcs := template.FuncMap{
		"since": func(v any) string {
			var t time.Time
			switch x := v.(type) {
			case time.Time:
				t = x
			case *time.Time:
				if x == nil {
					return ""
				}
				t = *x
			default:
				return ""
			}
			if t.IsZero() {
				return ""
			}
			return humanDuration(time.Since(t)) + " ago"
		},
		"dur":      humanDuration,
		"usd":      formatUSD,
		"pct":      formatPct,
		"status":   func(s db.ScanStatus) string { return string(s) },
		"fstatus":  func(s db.FindingLifecycle) string { return string(s) },
		"sevlabel": displaySeverity,
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[kv[i].(string)] = kv[i+1]
			}
			return m
		},
		"list": func(xs ...string) []string { return xs },
		"cwename": func(id string) string {
			if _, c, ok := LookupCWE(id); ok {
				return c.Name
			}
			return ""
		},
		"catlabel":   CategoryLabel,
		"cwecatid":   CWECategoryID,
		"md":         renderMarkdown,
		"jsontree":   jsonTree,
		"prettyjson": prettyJSON,
		"bignum":     bignum,
		"lookup": func(m any, key string) uint {
			if mm, ok := m.(map[string]uint); ok {
				return mm[key]
			}
			return 0
		},
		"locurl": func(repoID, commit, loc any) string {
			var id uint
			switch v := repoID.(type) {
			case uint:
				id = v
			case int:
				id = uint(v)
			case uint64:
				id = uint(v)
			}
			c, _ := commit.(string)
			l, _ := loc.(string)
			return locationURL(id, c, l)
		},
		"forgeBlobURL":   forgeBlobURL,
		"forgeCommitURL": forgeCommitURL,
		"domain": func(u string) string {
			u = strings.TrimPrefix(u, "https://")
			u = strings.TrimPrefix(u, "http://")
			if i := strings.IndexByte(u, '/'); i >= 0 {
				u = u[:i]
			}
			return u
		},
		"trimscheme": func(u string) string {
			for _, p := range []string{"https://", "http://", "git@", "ssh://"} {
				u = strings.TrimPrefix(u, p)
			}
			return strings.TrimSuffix(u, ".git")
		},
		"crumbs": func(kv ...string) []map[string]string {
			var out []map[string]string
			for i := 0; i+1 < len(kv); i += 2 {
				out = append(out, map[string]string{"Label": kv[i], "URL": kv[i+1]})
			}
			return out
		},
		"short": func(s string) string {
			const n = 12
			if len(s) > n {
				return s[:n]
			}
			return s
		},
		"bytes": func(b int64) string {
			const unit = 1024
			if b < unit {
				return fmt.Sprintf("%d B", b)
			}
			div, exp := int64(unit), 0
			for n := b / unit; n >= unit; n /= unit {
				div *= unit
				exp++
			}
			return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
		},
	}
	t, err := template.New("").Funcs(funcs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	if _, err := getCSAFSchema(); err != nil {
		return nil, fmt.Errorf("load csaf schema: %w", err)
	}
	return &Server{DB: gdb, Queue: q, Log: log, Broker: broker, Worker: w, tmpl: t,
		resolvePURL: resolvePURLRepo}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.FileServerFS(staticFS))
	mux.HandleFunc("GET /events", s.events)
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /repositories", s.repoList)
	mux.HandleFunc("GET /repositories/new", s.repoNew)
	mux.HandleFunc("POST /repositories", s.repoCreate)
	mux.HandleFunc("POST /repositories/bulk", s.repoBulkCreate)
	mux.HandleFunc("GET /repositories/{id}", s.repoShow)
	mux.HandleFunc("GET /repositories/{id}/blob/{commit}/{path...}", s.repoBlob)
	mux.HandleFunc("GET /repositories/{id}/report.md", s.repoReport)
	mux.HandleFunc("POST /repositories/{id}/scan", s.repoScan)
	mux.HandleFunc("POST /repositories/{id}/disclosure-channel", s.repoDisclosureChannel)
	mux.HandleFunc("GET /scans", s.jobs)
	mux.HandleFunc("GET /orgs", s.orgsList)
	mux.HandleFunc("GET /orgs/{login}", s.orgShow)
	mux.HandleFunc("GET /orgs/{login}/findings.md", s.orgReport)
	mux.HandleFunc("GET /orgs/{login}/summary.md", s.orgSummary)
	mux.HandleFunc("GET /maintainers", s.maintainersList)
	mux.HandleFunc("GET /maintainers/{id}", s.maintainerShow)
	mux.HandleFunc("POST /maintainers/{id}/do-not-contact", s.maintainerDoNotContact)
	mux.HandleFunc("GET /findings", s.findings)
	mux.HandleFunc("GET /findings/{id}", s.findingShow)
	mux.HandleFunc("GET /findings/{id}/csaf.json", s.findingCSAF)
	mux.HandleFunc("POST /findings/{id}/status", s.findingStatus)
	mux.HandleFunc("POST /findings/{id}/verify", s.findingVerify)
	mux.HandleFunc("POST /repositories/{id}/verify-all", s.repoVerifyAll)
	mux.HandleFunc("POST /findings/{id}/disclose", s.findingDisclose)
	mux.HandleFunc("POST /findings/{id}/patch", s.findingPatchRun)
	mux.HandleFunc("POST /findings/{id}/exposure", s.findingExposureRun)
	mux.HandleFunc("GET /findings/{id}/patch.diff", s.findingPatchDownload)
	mux.HandleFunc("POST /findings/{id}/notes", s.findingNotes)
	mux.HandleFunc("POST /findings/{id}/fields", s.findingFields)
	mux.HandleFunc("POST /findings/{id}/communications", s.findingCommunications)
	mux.HandleFunc("POST /findings/{id}/references", s.findingReferences)
	mux.HandleFunc("POST /findings/{id}/labels", s.findingLabels)
	mux.HandleFunc("POST /dependencies/{id}/scan", s.depScan)
	mux.HandleFunc("POST /dependents/{id}/scan", s.dependentScan)
	mux.HandleFunc("GET /packages", s.packages)
	mux.HandleFunc("GET /packages/{id}", s.packageShow)
	mux.HandleFunc("GET /advisories", s.advisoriesList)
	mux.HandleFunc("GET /scans/{id}", s.scanShow)
	mux.HandleFunc("GET /scans/{id}/report.md", s.scanReport)
	mux.HandleFunc("POST /scans/{id}/retry", s.scanRetry)
	mux.HandleFunc("POST /scans/retry-failed", s.scansRetryFailed)
	mux.HandleFunc("POST /scans/{id}/cancel", s.scanCancel)
	mux.HandleFunc("GET /scans/{id}/log", s.scanLog)
	mux.HandleFunc("GET /usage", s.usage)
	s.registerSBOMRoutes(mux)
	mux.HandleFunc("GET /skills", s.skillsList)
	mux.HandleFunc("GET /skills/new", s.skillNew)
	mux.HandleFunc("POST /skills", s.skillCreate)
	mux.HandleFunc("GET /skills/{id}", s.skillShow)
	mux.HandleFunc("GET /skills/{id}/edit", s.skillEdit)
	mux.HandleFunc("POST /skills/{id}", s.skillUpdate)
	mux.HandleFunc("POST /repositories/{id}/skill-scan", s.skillRun)
	mux.HandleFunc("GET /settings", s.settingsShow)
	mux.HandleFunc("POST /settings/theme", s.settingsUpdateTheme)
	mux.HandleFunc("POST /settings/model", s.settingsUpdateModel)
	mux.HandleFunc("POST /settings/color-scheme", s.settingsUpdateColorScheme)

	// API routes get bearer-auth middleware and skip the browser CSRF checks;
	// skills call these from inside a scan workspace, not from a browser.
	// /api/v1/* are unauthenticated JSONL export endpoints sharing the
	// browser's host-only boundary; see threatmodel.md.
	root := http.NewServeMux()
	root.Handle("/api/v1/", securityHeaders(http.StripPrefix(exportPrefix, s.exportHandler())))
	root.Handle("/api/", s.apiHandler())
	root.Handle("/", securityHeaders(mux))
	return logRequests(s.Log, root)
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Nav"] = navKey(r.URL.Path)
	data["Theme"] = resolveTheme(r)
	data["ColorScheme"] = resolveColorScheme(r)
	data["Flash"] = popFlash(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.Log.Error("render", "tmpl", name, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Flash is a one-shot message carried across a redirect via the "flash"
// cookie and rendered server-side into #toaster on the next page load.
type Flash struct {
	Category    string `json:"c"`
	Title       string `json:"t"`
	Description string `json:"d,omitempty"`
	Href        string `json:"h,omitempty"`
	Label       string `json:"l,omitempty"`
}

func setFlash(w http.ResponseWriter, f Flash) {
	b, _ := json.Marshal(f)
	http.SetCookie(w, &http.Cookie{
		Name:     "flash",
		Value:    base64.RawURLEncoding.EncodeToString(b),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func popFlash(w http.ResponseWriter, r *http.Request) *Flash {
	c, err := r.Cookie("flash")
	if err != nil || c.Value == "" {
		return nil
	}
	http.SetCookie(w, &http.Cookie{Name: "flash", Path: "/", MaxAge: -1})
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	var f Flash
	if json.Unmarshal(raw, &f) != nil {
		return nil
	}
	return &f
}

// navKey maps a request path to the sidebar item that should be marked
// aria-current. Paths not in the table fall through to the repositories
// index, which is also the home page.
func navKey(path string) string {
	for _, p := range []struct{ prefix, key string }{
		{"/settings", "settings"}, {"/usage", "usage"}, {"/skills", "skills"}, {"/maintainers", "maintainers"},
		{"/orgs", "orgs"}, {"/packages", "packages"}, {"/advisories", "advisories"},
		{"/findings", "findings"}, {"/scans", "scans"}, {"/sboms", "sboms"},
	} {
		if strings.HasPrefix(path, p.prefix) {
			return p.key
		}
	}
	return "repos"
}

func isHX(r *http.Request) bool { return r.Header.Get("HX-Request") != "" }

// redirect sends a 303 for plain form posts and HX-Redirect for htmx
// requests, so every POST handler works with or without javascript.
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, path string) {
	if isHX(r) {
		w.Header().Set("HX-Redirect", path)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	s.repoList(w, r)
}

const (
	perPage     = 20
	defaultSort = "newest"
	// sortRepository and sortSeverity are the shared sort options used by
	// the findings, scans, advisories, and SBOM indexes.
	sortRepository = "repository"
	sortSeverity   = "severity"
)

type Page struct {
	N     int
	Pages int
	Total int64
	Path  string
	Query url.Values
}

func (p Page) href(n int) string {
	q := url.Values{}
	maps.Copy(q, p.Query)
	q.Set("page", strconv.Itoa(n))
	return p.Path + "?" + q.Encode()
}

func (p Page) PrevURL() string { return p.href(p.N - 1) }
func (p Page) NextURL() string { return p.href(p.N + 1) }

func paginate(r *http.Request, total int64) Page {
	n, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if n < 1 {
		n = 1
	}
	pages := int((total + perPage - 1) / perPage)
	return Page{N: n, Pages: pages, Total: total, Path: r.URL.Path, Query: r.URL.Query()}
}

type repoRow struct {
	db.Repository
	LastScan      *db.Scan
	FindingsTotal int
}

// distinctLanguages returns the sorted set of individual language names
// across every repository. Repository.Languages is a ", "-joined string
// written by the metadata/repo-overview parsers, so the dropdown has to
// split it rather than DISTINCT the column, otherwise every combination
// (and ordering) of languages becomes its own filter option.
func distinctLanguages(gdb *gorm.DB) []string {
	var raw []string
	gdb.Model(&db.Repository{}).Where("languages != ''").Distinct("languages").Pluck("languages", &raw)
	seen := map[string]struct{}{}
	for _, joined := range raw {
		for l := range strings.SplitSeq(joined, ",") {
			if l = strings.TrimSpace(l); l != "" {
				seen[l] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for l := range seen {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

func (s *Server) repoList(w http.ResponseWriter, r *http.Request) {
	q := s.DB.Model(&db.Repository{})
	lang := r.URL.Query().Get("language")
	if lang != "" {
		// languages is a ", "-joined list; wrapping both sides lets one
		// LIKE match start/middle/end/only without four OR clauses.
		q = q.Where("(', ' || languages || ', ') LIKE ?", "%, "+lang+", %")
	}
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	if search != "" {
		like := "%" + search + "%"
		q = q.Where("name LIKE ? OR url LIKE ? OR full_name LIKE ? OR description LIKE ?",
			like, like, like, like)
	}

	sort := r.URL.Query().Get("sort")
	const nameSort = "name"
	switch sort {
	case nameSort:
		q = q.Order(nameSort)
	case "stars":
		q = q.Order("stars desc")
	case "language":
		q = q.Order("languages, name")
	case "findings":
		// Correlated subquery keeps the existing Count/Find chain intact
		// (a JOIN+GROUP BY would change what Count(&total) returns). Low-
		// thousands of repos so the per-row subselect is fine on sqlite.
		// Scanner-skill findings (zizmor, semgrep, …) are excluded so the
		// list reflects curated audit output, matching the repo Findings tab.
		q = q.Order("(" + deepDiveFindingsCountSQL + ") desc, updated_at desc")
	default:
		sort = defaultSort
		q = q.Order("updated_at desc")
	}

	var total int64
	q.Count(&total)
	page := paginate(r, total)

	var repos []db.Repository
	q.Limit(perPage).Offset((page.N - 1) * perPage).Find(&repos)

	// Batch-load findings count and last scan per page (N rows) rather
	// than per-repo (N rows × 2 queries). For 20 rows per page this
	// collapses 40 queries into 2.
	repoIDs := make([]uint, 0, len(repos))
	for _, r := range repos {
		repoIDs = append(repoIDs, r.ID)
	}
	findingCounts := map[uint]int{}
	if len(repoIDs) > 0 {
		type rowCount struct {
			RepositoryID uint
			N            int
		}
		var counts []rowCount
		// Scope to deep-dive findings only so the column matches the repo
		// page's Findings tab; scanner output (zizmor/semgrep) is reachable
		// via that repo's Scanners tab.
		s.DB.Model(&db.Finding{}).
			Select("repository_id, COUNT(*) AS n").
			Where("repository_id IN ?", repoIDs).
			Where("scan_id IN (?)", deepDiveScanIDs(s.DB)).
			Group("repository_id").
			Scan(&counts)
		for _, c := range counts {
			findingCounts[c.RepositoryID] = c.N
		}
	}
	lastScans := map[uint]*db.Scan{}
	if len(repoIDs) > 0 {
		// For each repo, the latest scan. A single query using a grouped
		// subquery avoids one-query-per-row.
		var scans []db.Scan
		s.DB.Raw(`
			SELECT s.* FROM scans s
			JOIN (SELECT repository_id, MAX(id) AS max_id FROM scans
				WHERE repository_id IN ? GROUP BY repository_id) latest
			ON latest.max_id = s.id
		`, repoIDs).Scan(&scans)
		for i := range scans {
			lastScans[scans[i].RepositoryID] = &scans[i]
		}
	}

	rows := make([]repoRow, 0, len(repos))
	for _, repo := range repos {
		rows = append(rows, repoRow{
			Repository:    repo,
			LastScan:      lastScans[repo.ID],
			FindingsTotal: findingCounts[repo.ID],
		})
	}
	languages := distinctLanguages(s.DB)

	data := map[string]any{
		"Rows": rows, "Page": page, "Language": lang, "Sort": sort, "Languages": languages,
		"Q": search,
	}
	if isHX(r) {
		s.render(w, r, "repo_list.html", data)
	} else {
		s.render(w, r, "index.html", data)
	}
}

// loadRepoMap batch-loads the repositories referenced by a slice of
// rows and returns a map keyed by repository ID. The repoID accessor
// abstracts over Finding.RepositoryID, Advisory.RepositoryID and any
// other row shape that links back to a repository. Templates render
// per-row repo info by looking up the map.
func loadRepoMap[T any](gdb *gorm.DB, rows []T, repoID func(T) uint) map[uint]db.Repository {
	seen := make(map[uint]bool)
	ids := make([]uint, 0)
	for _, row := range rows {
		id := repoID(row)
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	result := make(map[uint]db.Repository, len(ids))
	if len(ids) == 0 {
		return result
	}
	var repos []db.Repository
	gdb.Where("id IN ?", ids).Find(&repos)
	for _, r := range repos {
		result[r.ID] = r
	}
	return result
}

func findingRepoID(f db.Finding) uint   { return f.RepositoryID }
func advisoryRepoID(a db.Advisory) uint { return a.RepositoryID }

// severityOrder is a SQL CASE expression that ranks db.SeverityLevels
// highest-first with unknown values last, derived from the same slice
// SeverityAtLeast uses so the two never disagree.
var severityOrder = func() string {
	var b strings.Builder
	b.WriteString("CASE severity")
	for i, s := range db.SeverityLevels {
		fmt.Fprintf(&b, " WHEN '%s' THEN %d", s, len(db.SeverityLevels)-1-i)
	}
	fmt.Fprintf(&b, " ELSE %d END", len(db.SeverityLevels))
	return b.String()
}()

// loadByID loads the row whose primary key matches the request's {id}
// path parameter, writing a 404 and returning ok=false when it does
// not exist. It collapses the four-line First-then-NotFound prelude
// that opened most show/edit handlers.
//
//nolint:ireturn // T is a concrete struct at every call site, not an interface
func loadByID[T any](s *Server, w http.ResponseWriter, r *http.Request) (T, bool) {
	var v T
	if err := s.DB.First(&v, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return v, false
	}
	return v, true
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// loadRepoFindings returns the open findings for a repo split into two
// slices: deep-dive output and tool-scanner output (zizmor, semgrep, …).
// Findings with no matching scan or an empty skill_name are treated as
// deep-dive so legacy rows don't get lost. The returned scanSkill and
// scanCommit maps are keyed by scan ID; the template reads scanSkill to
// label scanner cards and scanCommit to build forge links for each
// finding's location (each scan can be on a different commit).
// When category is non-empty, only the deep-dive slice is narrowed to the
// View-1400 bucket; scanner findings are returned unfiltered so the Scanners
// tab stays reachable.
func loadRepoFindings(gdb *gorm.DB, repoID uint, category string) ([]db.Finding, []db.Finding, map[uint]string, map[uint]string) {
	var all []db.Finding
	gdb.Where("repository_id = ? AND status NOT IN ?", repoID,
		[]db.FindingLifecycle{db.FindingRejected, db.FindingDuplicate}).
		Order(severityOrder).Order("id desc").Find(&all)

	scanSkill := map[uint]string{}
	scanCommit := map[uint]string{}
	if len(all) == 0 {
		return nil, nil, scanSkill, scanCommit
	}
	var rows []struct {
		ID        uint
		SkillName string
		Commit    string
	}
	gdb.Raw("SELECT id, COALESCE(skill_name, '') AS skill_name, COALESCE(`commit`, '') AS `commit` FROM scans WHERE repository_id = ?", repoID).Scan(&rows)
	for _, row := range rows {
		scanSkill[row.ID] = row.SkillName
		scanCommit[row.ID] = row.Commit
	}
	var deepDive, scanners []db.Finding
	for _, f := range all {
		name := scanSkill[f.ScanID]
		if name == "" || name == deepDiveSkillName {
			if category != "" && !findingMatchesCategory(f.CWE, category) {
				continue
			}
			deepDive = append(deepDive, f)
		} else {
			scanners = append(scanners, f)
		}
	}
	return deepDive, scanners, scanSkill, scanCommit
}

func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	q := s.DB.Model(&db.Finding{})
	// Default to deep-dive findings only; scanner skills (zizmor, semgrep)
	// are noisy enough to drown out the audit list. ?scanners=1 includes
	// them and is exposed as a toggle in the UI.
	scanners := r.URL.Query().Get("scanners") == "1"
	if !scanners {
		q = q.Where("scan_id IN (?)", deepDiveScanIDs(s.DB))
	}
	sev := r.URL.Query().Get("severity")
	if sev != "" {
		q = q.Where("severity = ?", sev)
	}
	status := r.URL.Query().Get("status")
	if status != "" {
		q = q.Where("status = ?", status)
	}
	category := r.URL.Query().Get("category")
	if category != "" {
		q = applyCWECategoryFilter(q, category)
	}
	owner := r.URL.Query().Get("owner")
	if owner != "" {
		q = q.Where("repository_id IN (?)",
			s.DB.Model(&db.Repository{}).Select("id").Where("owner = ?", owner))
	}
	missed := r.URL.Query().Get("missed") == "1"
	if missed {
		q = q.Where("missed_count > 0")
	}
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	if search != "" {
		like := "%" + search + "%"
		q = q.Where("title LIKE ? OR location LIKE ? OR cwe LIKE ? OR cve_id LIKE ? OR affected LIKE ?",
			like, like, like, like, like)
	}

	sort := r.URL.Query().Get("sort")
	switch sort {
	case sortSeverity:
		q = q.Order(severityOrder).Order("id desc")
	case sortRepository:
		q = q.Joins("JOIN repositories r ON r.id = findings.repository_id").
			Order("r.name").Order("findings.id desc")
	default:
		sort = defaultSort
		q = q.Order("id desc")
	}

	var total int64
	q.Count(&total)
	page := paginate(r, total)

	var rows []db.Finding
	q.Limit(perPage).Offset((page.N - 1) * perPage).Find(&rows)

	reposByID := loadRepoMap(s.DB, rows, findingRepoID)
	anySubPath := false
	for _, r := range rows {
		if r.SubPath != "" {
			anySubPath = true
			break
		}
	}
	var missedTotal int64
	s.DB.Model(&db.Finding{}).Where("missed_count > 0").Count(&missedTotal)

	var scannerTotal int64
	s.DB.Model(&db.Finding{}).
		Where("scan_id NOT IN (?)", deepDiveScanIDs(s.DB)).
		Count(&scannerTotal)

	s.render(w, r, "findings.html", map[string]any{
		"Findings": rows, "Page": page, "Severity": sev, "Sort": sort,
		"Category": category, "Categories": CWECategories(), "Uncategorized": UncategorizedCWE,
		"Repos": reposByID, "Q": search, "AnySubPath": anySubPath,
		"Owner": owner, "Missed": missed, "MissedTotal": missedTotal,
		"Scanners": scanners, "ScannerTotal": scannerTotal,
		"Status": status, "Statuses": db.FindingLifecycles,
	})
}

func (s *Server) depScan(w http.ResponseWriter, r *http.Request) {
	dep, ok := loadByID[db.Dependency](s, w, r)
	if !ok {
		return
	}

	repoURL := resolveDepRepoURL(r.Context(), dep)
	if repoURL == "" {
		http.Error(w, "could not resolve repository URL for "+dep.Name, http.StatusUnprocessableEntity)
		return
	}
	s.addRepoAndScan(w, r, repoURL)
}

func resolveDepRepoURL(ctx context.Context, dep db.Dependency) string {
	return resolvePURLRepo(ctx, dep.PURL)
}

// resolvePURLRepo asks packages.ecosyste.ms for the repository_url behind a
// PURL. Returns empty string if the lookup fails or no repo is recorded.
func resolvePURLRepo(ctx context.Context, purl string) string {
	if purl == "" {
		return ""
	}
	_, raw, err := worker.FetchPackagesByPURL(ctx, purl)
	if err != nil {
		return ""
	}
	var pkgs []struct {
		RepoURL string `json:"repository_url"`
	}
	if json.Unmarshal(raw, &pkgs) == nil && len(pkgs) > 0 && pkgs[0].RepoURL != "" {
		return pkgs[0].RepoURL
	}
	return ""
}

func (s *Server) dependentScan(w http.ResponseWriter, r *http.Request) {
	dep, ok := loadByID[db.Dependent](s, w, r)
	if !ok {
		return
	}
	if dep.RepositoryURL == "" {
		http.Error(w, "no repository URL for this dependent", http.StatusUnprocessableEntity)
		return
	}
	s.addRepoAndScan(w, r, dep.RepositoryURL)
}

const (
	// defaultSkillName is the skill scrutineer enqueues when a repository is
	// first added. It owns the decision about which other skills to run;
	// editing that skill changes the default pipeline with no Go changes.
	defaultSkillName = "triage"
	// deepDiveSkillName is the skill whose reports feed the Summary, Findings
	// and Threat Model tabs on the repository page.
	deepDiveSkillName = "security-deep-dive"
	// threatModelSkillName is the skill whose report feeds the Threat Model
	// tab when present; repos that predate it fall back to the boundaries
	// section of the deep-dive report so older scans keep rendering.
	threatModelSkillName = "threat-model"
	zizmorSkillName      = "zizmor"
)

// deepDiveFindingsCountSQL is a correlated subselect that counts deep-dive
// findings for the surrounding repositories row. Used in the repos list
// "findings" sort. Tool-scanner skills are excluded so the ordering matches
// the counts shown in the Findings column.
const deepDiveFindingsCountSQL = `SELECT COUNT(*) FROM findings f
    WHERE f.repository_id = repositories.id
      AND f.scan_id IN (SELECT id FROM scans
        WHERE skill_name = '` + deepDiveSkillName + `' OR skill_name = '' OR skill_name IS NULL)`

// deepDiveScanIDs returns a GORM subquery selecting scan IDs that belong to
// the curated audit (security-deep-dive) or to legacy/empty skill_name rows.
// Use it as a `scan_id IN (?)` filter to keep listings consistent with the
// repo Findings tab.
func deepDiveScanIDs(gdb *gorm.DB) *gorm.DB {
	return gdb.Model(&db.Scan{}).Select("id").
		Where("skill_name = ? OR skill_name = '' OR skill_name IS NULL", deepDiveSkillName)
}

func findingSupportsExposure(scan db.Scan) bool {
	return scan.SkillName != zizmorSkillName
}

func (s *Server) addRepoAndScan(w http.ResponseWriter, r *http.Request, repoURL string) {
	input, err := ParseRepoInput(repoURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	repo, _, err := s.createOrTriageRepo(r.Context(), input, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/repositories/%d", repo.ID))
}

func (s *Server) findingStatus(w http.ResponseWriter, r *http.Request) {
	f, ok := loadByID[db.Finding](s, w, r)
	if !ok {
		return
	}
	status := db.FindingLifecycle(r.FormValue("status"))
	switch status {
	case db.FindingNew, db.FindingEnriched, db.FindingTriaged, db.FindingReady,
		db.FindingReported, db.FindingAcknowledged, db.FindingFixed, db.FindingPublished,
		db.FindingRejected, db.FindingDuplicate:
		if err := db.WriteFindingField(s.DB, f.ID, "status", string(status), db.SourceAnalyst, ""); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "invalid status", http.StatusUnprocessableEntity)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/findings/%d", f.ID))
}

// verifySkillName is the skill the Verify button on the finding page runs.
const verifySkillName = "verify"

// discloseSkillName is the skill the Draft disclosure button runs.
const discloseSkillName = "disclose"

// patchSkillName is the skill the Propose patch button runs.
const patchSkillName = "patch"

func (s *Server) findingVerify(w http.ResponseWriter, r *http.Request) {
	s.runFindingSkill(w, r, verifySkillName)
}

func (s *Server) findingDisclose(w http.ResponseWriter, r *http.Request) {
	s.runFindingSkill(w, r, discloseSkillName)
}

func (s *Server) findingPatchRun(w http.ResponseWriter, r *http.Request) {
	s.runFindingSkill(w, r, patchSkillName)
}

func (s *Server) runFindingSkill(w http.ResponseWriter, r *http.Request, name string) {
	f, ok := loadByID[db.Finding](s, w, r)
	if !ok {
		return
	}
	var scan db.Scan
	if err := s.DB.First(&scan, f.ScanID).Error; err != nil {
		http.Error(w, "scan for finding not found", http.StatusInternalServerError)
		return
	}
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", name, true).First(&skill).Error; err != nil {
		http.Error(w, name+" skill is not installed", http.StatusPreconditionFailed)
		return
	}
	scanID, err := s.enqueueSkillScoped(r.Context(), scan.RepositoryID, skill.ID, new(f.ID), r.FormValue("model"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/scans/%d", scanID))
}

// repoVerifyAll is the bulk equivalent of the per-finding Verify button: it
// enqueues the verify skill for every deep-dive finding on the repo that is
// still awaiting verification (status "new"). The ?category= filter is
// honoured so the action scope matches the visible (and badge-counted)
// findings on the tab. Findings that already have a queued or running verify
// scan are skipped, so re-clicking the button doesn't pile up duplicate jobs.
func (s *Server) repoVerifyAll(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", verifySkillName, true).First(&skill).Error; err != nil {
		setFlash(w, Flash{Category: "error", Title: verifySkillName + " skill is not installed"})
		s.redirect(w, r, fmt.Sprintf("/repositories/%d#rt4", repo.ID))
		return
	}

	q := s.DB.Model(&db.Finding{}).
		Where("repository_id = ? AND status = ? AND scan_id IN (?)",
			repo.ID, db.FindingNew, deepDiveScanIDs(s.DB))
	if category := r.URL.Query().Get("category"); category != "" {
		q = applyCWECategoryFilter(q, category)
	}
	var findings []db.Finding
	q.Select("id").Find(&findings)

	model := r.FormValue("model")
	var queued, skipped, errored int
	for _, f := range findings {
		var inflight int64
		s.DB.Model(&db.Scan{}).
			Where("finding_id = ? AND skill_id = ? AND status IN ?",
				f.ID, skill.ID, []db.ScanStatus{db.ScanQueued, db.ScanRunning}).
			Count(&inflight)
		if inflight > 0 {
			skipped++
			continue
		}
		if _, err := s.enqueueSkillScoped(r.Context(), repo.ID, skill.ID, new(f.ID), model); err != nil {
			errored++
			continue
		}
		queued++
	}
	setFlash(w, verifyAllToast(queued, skipped, errored))
	// Land on the Scans tab so the operator can watch the verify jobs run.
	s.redirect(w, r, fmt.Sprintf("/repositories/%d#rt3", repo.ID))
}

func verifyAllToast(queued, skipped, errored int) Flash {
	if queued == 0 && skipped == 0 && errored == 0 {
		return Flash{Category: "success", Title: "No findings awaiting verification"}
	}
	parts := []string{fmt.Sprintf("%d queued", queued)}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d already running", skipped))
	}
	if errored > 0 {
		parts = append(parts, fmt.Sprintf("%d errored", errored))
	}
	cat := "success"
	switch {
	case errored > 0:
		cat = "error"
	case queued == 0:
		cat = "warning"
	}
	return Flash{Category: cat, Title: "Verify all: " + strings.Join(parts, ", ")}
}

func (s *Server) findingNotes(w http.ResponseWriter, r *http.Request) {
	f, ok := loadByID[db.Finding](s, w, r)
	if !ok {
		return
	}
	if _, err := db.AddFindingNote(s.DB, f.ID, r.FormValue("body"), ""); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/findings/%d", f.ID))
}

func (s *Server) packages(w http.ResponseWriter, r *http.Request) {
	q := s.DB.Model(&db.Package{})
	eco := r.URL.Query().Get("ecosystem")
	if eco != "" {
		q = q.Where("ecosystem = ?", eco)
	}
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	if search != "" {
		like := "%" + search + "%"
		// GORM maps the PURL struct field to the `p_url` column.
		q = q.Where("name LIKE ? OR p_url LIKE ? OR licenses LIKE ?", like, like, like)
	}

	sort := r.URL.Query().Get("sort")
	switch sort {
	case "name":
		q = q.Order("name")
	case "downloads":
		q = q.Order("downloads desc")
	case "dependents":
		q = q.Order("dependent_repos desc")
	case "ecosystem":
		q = q.Order("ecosystem, name")
	default:
		sort = "name"
		q = q.Order("name")
	}

	var total int64
	q.Count(&total)
	page := paginate(r, total)

	var rows []db.Package
	q.Limit(perPage).Offset((page.N - 1) * perPage).Find(&rows)

	var ecosystems []string
	s.DB.Model(&db.Package{}).Distinct("ecosystem").Order("ecosystem").Pluck("ecosystem", &ecosystems)

	s.render(w, r, "packages.html", map[string]any{
		"Pkgs": rows, "Page": page, "Ecosystem": eco, "Sort": sort, "Ecosystems": ecosystems,
		"Q": search,
	})
}

func (s *Server) packageShow(w http.ResponseWriter, r *http.Request) {
	var p db.Package
	if err := s.DB.Preload("Repository").First(&p, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	data := map[string]any{"Pkg": p}
	if p.Metadata != "" {
		data["Meta"] = p.Metadata
	}
	s.render(w, r, "package_show.html", data)
}

func (s *Server) advisoriesList(w http.ResponseWriter, r *http.Request) {
	q := s.DB.Model(&db.Advisory{})
	sev := r.URL.Query().Get("severity")
	if sev != "" {
		q = q.Where("severity = ?", sev)
	}
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	if search != "" {
		like := "%" + search + "%"
		q = q.Where("title LIKE ? OR packages LIKE ? OR classification LIKE ? OR uuid LIKE ?",
			like, like, like, like)
	}

	sort := r.URL.Query().Get("sort")
	switch sort {
	case "newest":
		q = q.Order("published_at desc, id desc")
	case sortRepository:
		q = q.Joins("JOIN repositories r ON r.id = advisories.repository_id").
			Order("r.name").Order("advisories.cvss_score desc")
	default:
		sort = "severity"
		q = q.Order("cvss_score desc, id desc")
	}

	var total int64
	q.Count(&total)
	page := paginate(r, total)

	var rows []db.Advisory
	q.Limit(perPage).Offset((page.N - 1) * perPage).Find(&rows)

	reposByID := loadRepoMap(s.DB, rows, advisoryRepoID)
	var severities []string
	s.DB.Model(&db.Advisory{}).Where("severity != ''").Distinct("severity").
		Order("severity").Pluck("severity", &severities)

	s.render(w, r, "advisories.html", map[string]any{
		"Advisories": rows, "Page": page, "Severity": sev, "Sort": sort,
		"Severities": severities, "Repos": reposByID, "Q": search,
	})
}

func (s *Server) findingShow(w http.ResponseWriter, r *http.Request) {
	var f db.Finding
	if err := s.DB.Preload("Labels").First(&f, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	var scan db.Scan
	s.DB.First(&scan, f.ScanID)
	var repo db.Repository
	s.DB.First(&repo, scan.RepositoryID)
	var notes []db.FindingNote
	s.DB.Where("finding_id = ?", f.ID).Order("created_at desc").Find(&notes)
	var comms []db.FindingCommunication
	s.DB.Where("finding_id = ?", f.ID).Order("at desc").Find(&comms)
	var refs []db.FindingReference
	s.DB.Where("finding_id = ?", f.ID).Order("id desc").Find(&refs)
	var history []db.FindingHistory
	s.DB.Where("finding_id = ?", f.ID).Order("created_at desc").Find(&history)
	var labels []db.FindingLabel
	s.DB.Order("name").Find(&labels)
	selected := make(map[string]bool, len(f.Labels))
	for _, l := range f.Labels {
		selected[l.Name] = true
	}

	type exposureRow struct {
		Dep    db.Dependent
		Status string
		Justif string
		Why    string
		At     time.Time
	}
	var fdRows []db.FindingDependent
	s.DB.Where("finding_id = ?", f.ID).Find(&fdRows)
	exposures := make([]exposureRow, 0, len(fdRows))
	if len(fdRows) > 0 {
		depIDs := make([]uint, len(fdRows))
		for i, r := range fdRows {
			depIDs[i] = r.DependentID
		}
		var depRows []db.Dependent
		s.DB.Where("id IN ?", depIDs).Find(&depRows)
		byID := make(map[uint]db.Dependent, len(depRows))
		for _, d := range depRows {
			byID[d.ID] = d
		}
		for _, r := range fdRows {
			exposures = append(exposures, exposureRow{
				Dep:    byID[r.DependentID],
				Status: r.Status,
				Justif: r.Justification,
				Why:    r.Rationale,
				At:     r.UpdatedAt,
			})
		}
	}

	data := map[string]any{
		"F":              f,
		"Scan":           scan,
		"Repo":           repo,
		"Notes":          notes,
		"Communications": comms,
		"References":     refs,
		"History":        history,
		"AllLabels":      labels,
		"Selected":       selected,
		"Exposures":      exposures,
		"ShowExposure":   findingSupportsExposure(scan),
	}
	if id, c, ok := LookupCWE(f.CWE); ok {
		data["CWE"] = map[string]any{"ID": id, "Name": c.Name, "Description": c.Description}
	}
	if patchScan, patchRep, _ := s.latestPatchScan(f.ID); patchRep != nil {
		data["PatchScan"] = patchScan
		data["Patch"] = patchRep
	}
	s.render(w, r, "finding_show.html", data)
}

func (s *Server) repoCreate(w http.ResponseWriter, r *http.Request) {
	input, err := ParseRepoInput(r.FormValue("url"))
	if err != nil {
		s.repoCreateError(w, r, "Invalid repository URL", err, http.StatusUnprocessableEntity)
		return
	}
	repo, _, err := s.createOrTriageRepo(r.Context(), input, r.FormValue("model"))
	if err != nil {
		s.repoCreateError(w, r, "Couldn't add repository", err, http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/repositories/%d", repo.ID))
}

// repoCreateError renders feedback for a failed Add Repository submission.
// htmx clients get an inline alert inside the dialog (a toast would render
// behind the modal's top layer); plain form posts fall back to a basic
// error page.
func (s *Server) repoCreateError(w http.ResponseWriter, r *http.Request, title string, err error, status int) {
	if !isHX(r) {
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if execErr := s.tmpl.ExecuteTemplate(w, "add-repo-alert-oob", Flash{
		Title:       title,
		Description: err.Error(),
	}); execErr != nil {
		s.Log.Error("render add-repo-alert-oob", "err", execErr)
	}
}

// repoNew is the no-javascript fallback for the Add Repository dialog.
func (s *Server) repoNew(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "repo_new.html", map[string]any{"Bulk": r.FormValue("bulk") != ""})
}

// repoBulkCreate accepts a newline-separated list of repository URLs,
// creates each one that is not already in the database, and enqueues the
// default skill for every new row. Duplicates and unparseable lines are
// reported back via a flash toast rather than failing the whole submission;
// partial success is the expected case for a pasted list.
func (s *Server) repoBulkCreate(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("urls")
	lines := strings.Split(raw, "\n")
	var created, skipped int
	var invalid []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		input, err := ParseRepoInput(line)
		if err != nil {
			invalid = append(invalid, line)
			continue
		}
		_, isNew, err := s.createOrTriageRepo(r.Context(), input, r.FormValue("model"))
		if err != nil {
			invalid = append(invalid, line)
			continue
		}
		if isNew {
			created++
		} else {
			skipped++
		}
	}
	if created == 0 && skipped == 0 && len(invalid) == 0 {
		http.Error(w, "no URLs supplied", http.StatusUnprocessableEntity)
		return
	}
	setFlash(w, Flash{
		Category:    bulkToastCategory(created, invalid),
		Title:       bulkToastTitle(created, skipped, len(invalid)),
		Description: bulkToastDescription(invalid),
	})
	s.redirect(w, r, "/")
}

// createOrTriageRepo is the shared path for both single-add and bulk-add.
// It FirstOrCreates the Repository row and, when the row is new, enqueues
// the default skill. isNew reports whether the repo was actually created
// (so callers can distinguish "queued" from "already present").
func (s *Server) createOrTriageRepo(ctx context.Context, input RepoInput, model string) (db.Repository, bool, error) {
	if input.Local {
		path := strings.TrimPrefix(input.CloneURL, LocalScheme)
		info, err := os.Stat(path)
		if err != nil {
			return db.Repository{}, false, fmt.Errorf("local path %s: %w", path, err)
		}
		if !info.IsDir() {
			return db.Repository{}, false, fmt.Errorf("local path %s is not a directory", path)
		}
	}
	existing := int64(0)
	s.DB.Model(&db.Repository{}).Where("url = ?", input.CloneURL).Count(&existing)
	// Owner, FullName, and HTMLURL seed from ParseRepoInput so the orgs
	// view groups newly added repos and finding-location links work before
	// the metadata job has run; the metadata job later overwrites them
	// with the canonical forge values.
	repo := db.Repository{
		URL:     input.CloneURL,
		Name:    input.Name,
		Owner:   input.Owner,
		HTMLURL: DefaultHTMLURL(input.CloneURL),
	}
	if input.Owner != "" {
		repo.FullName = input.Owner + "/" + input.Name
	}
	if err := s.DB.Where(db.Repository{URL: input.CloneURL}).FirstOrCreate(&repo).Error; err != nil {
		return repo, false, err
	}
	isNew := existing == 0
	if !isNew && input.Branch == "" && input.SubPath == "" {
		return repo, false, nil
	}
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", defaultSkillName, true).First(&skill).Error; err != nil {
		s.Log.Warn("default skill not found, repo added with no scans", "skill", defaultSkillName)
		return repo, isNew, nil
	}
	if repo.IsLocal() && skill.RequiresRemote {
		s.Log.Info("default skill requires remote, skipping for local repo", "skill", skill.Name, "repo", repo.URL)
		return repo, isNew, nil
	}
	if _, err := s.enqueueSkillWith(ctx, repo.ID, skill.ID, ScanOpts{
		Model:   model,
		SubPath: input.SubPath,
		Ref:     input.Branch,
	}); err != nil {
		return repo, isNew, err
	}
	return repo, isNew, nil
}

func bulkToastCategory(created int, invalid []string) string {
	if created > 0 && len(invalid) == 0 {
		return "success"
	}
	if created == 0 && len(invalid) > 0 {
		return "error"
	}
	return "warning"
}

func bulkToastTitle(created, skipped, invalid int) string {
	parts := []string{fmt.Sprintf("%d added", created)}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d already present", skipped))
	}
	if invalid > 0 {
		parts = append(parts, fmt.Sprintf("%d invalid", invalid))
	}
	return strings.Join(parts, ", ")
}

func bulkToastDescription(invalid []string) string {
	if len(invalid) == 0 {
		return ""
	}
	const maxShow = 3
	if len(invalid) <= maxShow {
		return "Rejected: " + strings.Join(invalid, ", ")
	}
	return fmt.Sprintf("Rejected: %s, and %d more", strings.Join(invalid[:maxShow], ", "), len(invalid)-maxShow)
}

func (s *Server) repoShow(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	var scans []db.Scan
	// Per (skill_name, sub_path) we want just the latest scan — the repo
	// page should read like "this is the state of each job on this repo",
	// not a scroll of every historical attempt. Older runs are still
	// reachable via /scans/{id} and the global /scans index.
	s.DB.Raw(`
		SELECT s.* FROM scans s
		JOIN (
			SELECT COALESCE(skill_name, '') AS sn, COALESCE(sub_path, '') AS sp, MAX(id) AS max_id
			FROM scans WHERE repository_id = ?
			GROUP BY sn, sp
		) latest ON latest.max_id = s.id
		ORDER BY s.id DESC
	`, repo.ID).Scan(&scans)

	// The security-deep-dive skill owns the structured audit report; the
	// Summary and Findings tabs render from its scans. The Threat Model tab
	// renders the threat-model skill's report when one exists, falling back
	// to the deep-dive report's boundaries/inventory section so repositories
	// scanned before the threat-model skill landed keep their tab content.
	var latest, tmScan, tmFallback *db.Scan
	for i := range scans {
		sc := &scans[i]
		switch sc.SkillName {
		case deepDiveSkillName:
			if latest == nil {
				latest = sc
				s.DB.Where("scan_id = ?", latest.ID).Find(&latest.Findings)
			}
			if tmFallback == nil && sc.Status == db.ScanDone && sc.Report != "" {
				tmFallback = sc
			}
		case threatModelSkillName:
			if tmScan == nil && sc.Status == db.ScanDone && sc.Report != "" {
				tmScan = sc
			}
		}
		if latest != nil && tmScan != nil && tmFallback != nil {
			break
		}
	}
	if tmScan == nil {
		tmScan = tmFallback
	}
	var threatModel map[string]any
	if tmScan != nil {
		_ = json.Unmarshal([]byte(tmScan.Report), &threatModel)
	}

	var totalCost float64
	s.DB.Model(&db.Scan{}).Where("repository_id = ?", repo.ID).
		Select("COALESCE(SUM(cost_usd), 0)").Scan(&totalCost)

	category := r.URL.Query().Get("category")
	findings, scannerFindings, scanSkill, scanCommit := loadRepoFindings(s.DB, repo.ID, category)

	// Count deep-dive findings still awaiting verification, scoped to the
	// same category filter as the visible list. Drives the "Verify all new"
	// button on the Findings tab; the bulk handler acts on this exact set.
	newFindingsQuery := s.DB.Model(&db.Finding{}).
		Where("repository_id = ? AND status = ? AND scan_id IN (?)",
			repo.ID, db.FindingNew, deepDiveScanIDs(s.DB))
	if category != "" {
		newFindingsQuery = applyCWECategoryFilter(newFindingsQuery, category)
	}
	var newFindings int64
	newFindingsQuery.Count(&newFindings)

	var maintainers []db.Maintainer
	s.DB.Joins("JOIN repository_maintainers ON repository_maintainers.maintainer_id = maintainers.id").
		Where("repository_maintainers.repository_id = ?", repo.ID).Find(&maintainers)

	var rawDeps []db.Dependency
	s.DB.Where("repository_id = ?", repo.ID).Order("ecosystem, name, manifest_kind desc").Find(&rawDeps)
	deps := groupDeps(rawDeps)

	var pkgs []db.Package
	s.DB.Where("repository_id = ?", repo.ID).Order("dependent_repos desc, downloads desc").Find(&pkgs)

	var dependents []db.Dependent
	s.DB.Where("repository_id = ?", repo.ID).Order("dependent_repos desc").Find(&dependents)

	var advisories []db.Advisory
	s.DB.Where("repository_id = ?", repo.ID).Order("cvss_score desc").Find(&advisories)

	knownPURLs := s.lookupKnownPURLs(deps)
	knownURLs := s.lookupKnownURLs(dependents)

	// Pass repo html_url and commit for location links in threat model
	tmCommit := ""
	if tmScan != nil {
		tmCommit = tmScan.Commit
	}

	var activeSkills []db.Skill
	s.DB.Where("active = ?", true).Order("name").Find(&activeSkills)

	var subprojects []db.Subproject
	s.DB.Where("repository_id = ?", repo.ID).Order("path").Find(&subprojects)
	subScanCount := map[string]int{}
	if len(subprojects) > 0 {
		rows := make([]struct {
			SubPath string
			N       int
		}, 0)
		s.DB.Raw(`SELECT sub_path, COUNT(*) AS n FROM scans
			WHERE repository_id = ? AND sub_path != '' GROUP BY sub_path`,
			repo.ID).Scan(&rows)
		for _, r := range rows {
			subScanCount[r.SubPath] = r.N
		}
	}

	// Count failed scans in the latest-per-skill set: same scope as the
	// retry-failed handler would act on for this repo. Drives the
	// "Retry failed" button on the Scans tab.
	var failedScans int
	for _, sc := range scans {
		if sc.Status == db.ScanFailed {
			failedScans++
		}
	}

	data := map[string]any{
		"Repo": repo, "Scans": scans, "Latest": latest,
		"Findings":        findings,
		"ScannerFindings": scannerFindings,
		"ScanSkill":       scanSkill,
		"ScanCommit":      scanCommit,
		"NewFindingCount": int(newFindings),
		"FailedScans":     failedScans,
		"TotalCost":       totalCost,
		"TMCommit":        tmCommit,
		"Deps":            deps, "Pkgs": pkgs, "Dependents": dependents, "Advisories": advisories, "Maintainers": maintainers, "ThreatModel": threatModel,
		"KnownURLs": knownURLs, "KnownPURLs": knownPURLs,
		"Skills":        activeSkills,
		"Subprojects":   subprojects,
		"SubScanCount":  subScanCount,
		"Category":      category,
		"Categories":    CWECategories(),
		"Uncategorized": UncategorizedCWE,
	}
	s.render(w, r, "repo_show.html", data)
}

func (s *Server) repoScan(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	// The "New scan" button enqueues the deep-dive skill; everything else is
	// triggered either by the triage skill or by the explicit Run skill menu.
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", deepDiveSkillName, true).First(&skill).Error; err != nil {
		http.Error(w, deepDiveSkillName+" skill is not installed", http.StatusPreconditionFailed)
		return
	}
	if _, err := s.enqueueSkillWith(r.Context(), repo.ID, skill.ID, ScanOpts{
		Model:   r.FormValue("model"),
		SubPath: strings.TrimSpace(r.FormValue("sub_path")),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/repositories/%d", repo.ID))
}

// repoDisclosureChannel lets the analyst overwrite (or clear) the
// disclosure channel that the maintainers skill wrote onto the repo.
// Empty submission clears the field.
func (s *Server) repoDisclosureChannel(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	var repo db.Repository
	if err := s.DB.First(&repo, id).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	value := strings.TrimSpace(r.FormValue("disclosure_channel"))
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
		Update("disclosure_channel", value).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/repositories/%d", repo.ID))
}

// ScanOpts carries the optional inputs to an enqueue call. Keeps the
// enqueue signature from drifting into an unreadable positional list as
// new options (SubPath, FindingID, Model) accumulate.
type ScanOpts struct {
	Model       string
	FindingID   *uint
	DependentID *uint
	SubPath     string
	Ref         string
	Profile     string
}

func (s *Server) enqueueSkill(ctx context.Context, repoID, skillID uint, model string) (uint, error) {
	return s.enqueueSkillWith(ctx, repoID, skillID, ScanOpts{Model: model})
}

// enqueueSkillScoped is a thin shim preserved for call sites that already
// pass a finding id. New code should prefer enqueueSkillWith + ScanOpts.
func (s *Server) enqueueSkillScoped(ctx context.Context, repoID, skillID uint, findingID *uint, model string) (uint, error) {
	return s.enqueueSkillWith(ctx, repoID, skillID, ScanOpts{Model: model, FindingID: findingID})
}

// enqueueSkillWith creates a skill scan using the given ScanOpts. Empty
// fields default cleanly: unset FindingID means not-finding-scoped, empty
// SubPath means root-scoped. Model precedence is: explicit opts.Model >
// the skill's preferred Model > server default.
func (s *Server) enqueueSkillWith(ctx context.Context, repoID, skillID uint, opts ScanOpts) (uint, error) {
	var repo db.Repository
	if err := s.DB.Select("id, url").First(&repo, repoID).Error; err != nil {
		return 0, err
	}
	var sk db.Skill
	hasSkill := s.DB.Select("name, requires_remote, requires_profile, model").First(&sk, skillID).Error == nil
	if repo.IsLocal() && hasSkill && sk.RequiresRemote {
		return 0, fmt.Errorf("%w: %q", ErrSkillRequiresRemote, sk.Name)
	}
	if hasSkill && sk.RequiresProfile != "" && opts.Profile != "" && opts.Profile != sk.RequiresProfile {
		return 0, fmt.Errorf("%w: %q needs %q, got %q", ErrSkillProfileMismatch, sk.Name, sk.RequiresProfile, opts.Profile)
	}
	if !ValidModel(opts.Model) {
		if hasSkill && ValidModel(sk.Model) {
			opts.Model = sk.Model
		} else {
			opts.Model = DefaultModel()
		}
	}
	kind := worker.JobSkill
	if opts.DependentID != nil {
		kind = worker.JobExposure
	}
	scan := db.Scan{
		RepositoryID:   repoID,
		Kind:           kind,
		Status:         db.ScanQueued,
		StatusPriority: db.StatusPriorityFor(db.ScanQueued),
		Model:          opts.Model,
		SkillID:        &skillID,
		SkillName:      sk.Name,
		FindingID:      opts.FindingID,
		DependentID:    opts.DependentID,
		SubPath:        opts.SubPath,
		Ref:            opts.Ref,
		Profile:        opts.Profile,
		SkillsRepoSHA:  s.SkillsRepoSHA,
		APIToken:       NewAPIToken(),
	}
	if err := s.DB.Create(&scan).Error; err != nil {
		return 0, err
	}
	prio := worker.PrioScan
	if opts.FindingID != nil {
		prio = worker.PrioFinding
	}
	if err := s.Queue.Enqueue(ctx, kind, scan.ID, prio); err != nil {
		return 0, err
	}
	s.DB.Model(&db.Repository{}).Where("id = ?", repoID).Update("updated_at", time.Now())
	return scan.ID, nil
}

const (
	billion  = 1_000_000_000
	million  = 1_000_000
	thousand = 1_000
)

func bignum(n any) string {
	var v int64
	switch x := n.(type) {
	case int:
		v = int64(x)
	case int64:
		v = x
	default:
		return fmt.Sprint(n)
	}
	switch {
	case v >= billion:
		return fmt.Sprintf("%.1fB", float64(v)/float64(billion))
	case v >= million:
		return fmt.Sprintf("%.1fM", float64(v)/float64(million))
	case v >= thousand*10:
		return fmt.Sprintf("%.1fK", float64(v)/float64(thousand))
	default:
		return fmt.Sprint(v)
	}
}

// DepGroup is a dependency deduplicated by name+ecosystem, with all manifest
// paths and the best version (lockfile wins over manifest).
type DepGroup struct {
	db.Dependency
	Manifests []string
}

func groupDeps(deps []db.Dependency) []DepGroup {
	type key struct{ Name, Eco string }
	order := []key{}
	m := map[key]*DepGroup{}
	for _, d := range deps {
		k := key{d.Name, d.Ecosystem}
		g, ok := m[k]
		if !ok {
			g = &DepGroup{Dependency: d}
			m[k] = g
			order = append(order, k)
		}
		g.Manifests = append(g.Manifests, d.ManifestPath)
		// Prefer lockfile version (exact) over manifest (range)
		if d.ManifestKind == "lockfile" && g.ManifestKind != "lockfile" {
			g.Requirement = d.Requirement
			g.ManifestKind = d.ManifestKind
		}
	}
	out := make([]DepGroup, 0, len(order))
	for _, k := range order {
		out = append(out, *m[k])
	}
	return out
}

func (s *Server) lookupKnownPURLs(deps []DepGroup) map[string]uint {
	m := map[string]uint{}
	if len(deps) == 0 {
		return m
	}
	purls := make([]string, 0, len(deps))
	for _, d := range deps {
		if d.PURL != "" {
			purls = append(purls, d.PURL)
			if base, _, ok := strings.Cut(d.PURL, "?"); ok {
				purls = append(purls, base)
			}
		}
	}
	if len(purls) == 0 {
		return m
	}
	var rows []struct {
		PURL         string
		RepositoryID uint
	}
	s.DB.Model(&db.Package{}).Select("p_url, repository_id").
		Where("p_url IN ?", purls).Find(&rows)
	for _, r := range rows {
		m[r.PURL] = r.RepositoryID
		if base, _, ok := strings.Cut(r.PURL, "?"); ok {
			m[base] = r.RepositoryID
		}
	}
	return m
}

func (s *Server) lookupKnownURLs(dependents []db.Dependent) map[string]uint {
	m := map[string]uint{}
	if len(dependents) == 0 {
		return m
	}
	urls := make([]string, 0, len(dependents))
	for _, d := range dependents {
		if d.RepositoryURL != "" {
			urls = append(urls, d.RepositoryURL)
		}
	}
	if len(urls) == 0 {
		return m
	}
	var repos []db.Repository
	s.DB.Select("id", "url").Where("url IN ?", urls).Find(&repos)
	for _, r := range repos {
		m[r.URL] = r.ID
	}
	return m
}

func humanDuration(d time.Duration) string {
	const (
		minPerHour = 60
		hourPerDay = 24
		day        = hourPerDay * time.Hour
	)
	switch {
	case d < time.Second:
		return "0s"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < day:
		h := int(d.Hours())
		m := int(d.Minutes()) % minPerHour
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	default:
		return fmt.Sprintf("%dd", int(d.Hours())/hourPerDay)
	}
}

const pctScale = 100

func formatPct(v float64) string { return fmt.Sprintf("%.0f%%", v*pctScale) }

// formatUSD renders a dollar amount with enough precision that the cheap
// metadata-style scans (fractions of a cent) don't all read as $0.00,
// while keeping deep-dive runs at the two decimal places people expect.
func formatUSD(v float64) string {
	const smallDollar = 0.10
	if v > 0 && v < smallDollar {
		return fmt.Sprintf("$%.4f", v)
	}
	return fmt.Sprintf("$%.2f", v)
}

// cspPolicy blocks inline scripts (the XSS mitigation that motivated this
// header) and locks down loading to same-origin resources. 'unsafe-inline' is
// kept for styles because tailwindcss-browser injects style tags at runtime.
const cspPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"font-src 'self' data:; " +
	"connect-src 'self'; " +
	"base-uri 'self'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'; " +
	"object-src 'none'"

// securityHeaders enforces T3 mitigations: host header check to prevent DNS
// rebinding, Sec-Fetch-Site check on POST to prevent cross-origin CSRF, and
// a CSP that prevents stored XSS in any rendered content from executing JS.
func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", cspPolicy)
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			http.Error(w, "forbidden: invalid host", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			fetchSite := r.Header.Get("Sec-Fetch-Site")
			// Browsers always send Sec-Fetch-Site; its absence means a non-browser
			// client (curl, etc) which is fine. But "cross-site" means CSRF.
			if fetchSite == "cross-site" {
				http.Error(w, "forbidden: cross-site POST", http.StatusForbidden)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

func logRequests(log *slog.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		log.Info("http", "method", r.Method, "path", r.URL.Path, "dur", time.Since(start).Round(time.Millisecond))
	})
}
