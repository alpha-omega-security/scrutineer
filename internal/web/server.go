package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
	"scrutineer/internal/worker"
)

//go:embed templates/*.html
var tmplFS embed.FS

//go:embed static
var staticFS embed.FS

type Server struct {
	DB     *gorm.DB
	Queue  *queue.Queue
	Log    *slog.Logger
	Broker *Broker
	tmpl   *template.Template
}

func New(gdb *gorm.DB, q *queue.Queue, log *slog.Logger, broker *Broker) (*Server, error) {
	funcs := template.FuncMap{
		"since": func(t *time.Time) string {
			if t == nil {
				return ""
			}
			return humanDuration(time.Since(*t)) + " ago"
		},
		"dur":    humanDuration,
		"status":  func(s db.ScanStatus) string { return string(s) },
		"fstatus": func(s db.FindingLifecycle) string { return string(s) },
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[kv[i].(string)] = kv[i+1]
			}
			return m
		},
		"models": func() []Model { return Models },
		"list": func(xs ...string) []string { return xs },
		"cwename": func(id string) string {
			if _, c, ok := LookupCWE(id); ok {
				return c.Name
			}
			return ""
		},
		"jsontree": jsonTree,
		"bignum": bignum,
		"lookup": func(m any, key string) uint {
			if mm, ok := m.(map[string]uint); ok {
				return mm[key]
			}
			return 0
		},
		"locurl": func(htmlURL, commit, loc any) string {
			h, _ := htmlURL.(string)
			c, _ := commit.(string)
			l, _ := loc.(string)
			return locationURL(h, c, l)
		},
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
	}
	t, err := template.New("").Funcs(funcs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{DB: gdb, Queue: q, Log: log, Broker: broker, tmpl: t}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.FileServerFS(staticFS))
	mux.HandleFunc("GET /events", s.events)
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /repositories", s.repoList)
	mux.HandleFunc("POST /repositories", s.repoCreate)
	mux.HandleFunc("GET /repositories/{id}", s.repoShow)
	mux.HandleFunc("POST /repositories/{id}/scan", s.repoScan)
	mux.HandleFunc("GET /jobs", s.jobs)
	mux.HandleFunc("GET /maintainers", s.maintainersList)
	mux.HandleFunc("GET /maintainers/{id}", s.maintainerShow)
	mux.HandleFunc("GET /findings", s.findings)
	mux.HandleFunc("GET /findings/{id}", s.findingShow)
	mux.HandleFunc("POST /findings/{id}/status", s.findingStatus)
	mux.HandleFunc("POST /findings/{id}/verify", s.findingVerify)
	mux.HandleFunc("POST /findings/{id}/notes", s.findingNotes)
	mux.HandleFunc("POST /dependencies/{id}/scan", s.depScan)
	mux.HandleFunc("POST /dependents/{id}/scan", s.dependentScan)
	mux.HandleFunc("GET /packages", s.packages)
	mux.HandleFunc("GET /packages/{id}", s.packageShow)
	mux.HandleFunc("GET /scans/{id}", s.scanShow)
	mux.HandleFunc("POST /scans/{id}/retry", s.scanRetry)
	mux.HandleFunc("GET /scans/{id}/log", s.scanLog)
	mux.HandleFunc("GET /skills", s.skillsList)
	mux.HandleFunc("GET /skills/new", s.skillNew)
	mux.HandleFunc("POST /skills", s.skillCreate)
	mux.HandleFunc("GET /skills/{id}", s.skillShow)
	mux.HandleFunc("GET /skills/{id}/edit", s.skillEdit)
	mux.HandleFunc("POST /skills/{id}", s.skillUpdate)
	mux.HandleFunc("POST /repositories/{id}/skill-scan", s.skillRun)

	// API routes get bearer-auth middleware and skip the browser CSRF checks;
	// skills call these from inside a scan workspace, not from a browser.
	root := http.NewServeMux()
	root.Handle("/api/", s.apiHandler())
	root.Handle("/", securityHeaders(mux))
	return logRequests(s.Log, root)
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.Log.Error("render", "tmpl", name, "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	s.repoList(w, r)
}

const (
	perPage       = 20
	defaultSort   = "newest"
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
	LastScan *db.Scan
}

func (s *Server) repoList(w http.ResponseWriter, r *http.Request) {
	q := s.DB.Model(&db.Repository{})
	lang := r.URL.Query().Get("language")
	if lang != "" {
		q = q.Where("languages = ?", lang)
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
	default:
		sort = defaultSort
		q = q.Order("updated_at desc")
	}

	var total int64
	q.Count(&total)
	page := paginate(r, total)

	var repos []db.Repository
	q.Limit(perPage).Offset((page.N - 1) * perPage).Find(&repos)

	rows := make([]repoRow, 0, len(repos))
	for _, repo := range repos {
		row := repoRow{Repository: repo}
		var last db.Scan
		if err := s.DB.Where("repository_id = ?", repo.ID).
			Order("id desc").First(&last).Error; err == nil {
			row.LastScan = &last
		}
		rows = append(rows, row)
	}
	var languages []string
	s.DB.Model(&db.Repository{}).Where("languages != ''").Distinct("languages").Order("languages").Pluck("languages", &languages)

	data := map[string]any{
		"Rows": rows, "Page": page, "Language": lang, "Sort": sort, "Languages": languages,
	}
	if r.Header.Get("HX-Request") != "" {
		s.render(w, "repo_list.html", data)
	} else {
		s.render(w, "index.html", data)
	}
}

func (s *Server) maintainersList(w http.ResponseWriter, r *http.Request) {
	q := s.DB.Model(&db.Maintainer{})
	status := r.URL.Query().Get("status")
	if status != "" {
		q = q.Where("status = ?", status)
	}
	var total int64
	q.Count(&total)
	page := paginate(r, total)

	var rows []db.Maintainer
	q.Preload("Repositories").Order("login").
		Limit(perPage).Offset((page.N - 1) * perPage).Find(&rows)

	s.render(w, "maintainers.html", map[string]any{
		"Maintainers": rows, "Page": page, "Status": status,
	})
}

func (s *Server) maintainerShow(w http.ResponseWriter, r *http.Request) {
	var m db.Maintainer
	if err := s.DB.Preload("Repositories").First(&m, r.PathValue("id")).Error; err != nil {
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
		s.DB.Joins("Scan").Where("\"Scan\".repository_id IN ?", repoIDs).
			Preload("Scan.Repository").Order("id desc").Find(&findings)
	}
	s.render(w, "maintainer_show.html", map[string]any{"M": m, "Findings": findings})
}

var severityOrder = `CASE severity
	WHEN 'Critical' THEN 0 WHEN 'High' THEN 1
	WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END`

func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	q := s.DB.Model(&db.Finding{}).Joins("Scan").Joins("Scan.Repository")
	sev := r.URL.Query().Get("severity")
	if sev != "" {
		q = q.Where("findings.severity = ?", sev)
	}

	sort := r.URL.Query().Get("sort")
	switch sort {
	case "severity":
		q = q.Order(severityOrder).Order("findings.id desc")
	case "repository":
		q = q.Order("`Scan__Repository`.name").Order("findings.id desc")
	default:
		sort = defaultSort
		q = q.Order("findings.id desc")
	}

	var total int64
	q.Count(&total)
	page := paginate(r, total)

	var rows []db.Finding
	q.Preload("Scan.Repository").
		Limit(perPage).Offset((page.N - 1) * perPage).Find(&rows)

	s.render(w, "findings.html", map[string]any{
		"Findings": rows, "Page": page, "Severity": sev, "Sort": sort,
	})
}

func (s *Server) depScan(w http.ResponseWriter, r *http.Request) {
	var dep db.Dependency
	if err := s.DB.First(&dep, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}

	// Try to find existing repo by PURL lookup
	repoURL := resolveDepRepoURL(r.Context(), dep)
	if repoURL == "" {
		http.Error(w, "could not resolve repository URL for "+dep.Name, http.StatusUnprocessableEntity)
		return
	}

	// Find or create
	repo := db.Repository{URL: repoURL, Name: db.NameFromURL(repoURL)}
	if err := s.DB.Where(db.Repository{URL: repoURL}).FirstOrCreate(&repo).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.addRepoAndScan(w, r, repoURL)
}

func resolveDepRepoURL(ctx context.Context, dep db.Dependency) string {
	if dep.PURL == "" {
		return ""
	}
	// packages.ecosyste.ms lookup by PURL
	_, raw, err := worker.FetchPackagesByPURL(ctx, dep.PURL)
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
	var dep db.Dependent
	if err := s.DB.First(&dep, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
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
)

func (s *Server) addRepoAndScan(w http.ResponseWriter, r *http.Request, repoURL string) {
	repo := db.Repository{URL: repoURL, Name: db.NameFromURL(repoURL)}
	if err := s.DB.Where(db.Repository{URL: repoURL}).FirstOrCreate(&repo).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var scanCount int64
	s.DB.Model(&db.Scan{}).Where("repository_id = ?", repo.ID).Count(&scanCount)
	if scanCount == 0 {
		var skill db.Skill
		if err := s.DB.Where("name = ? AND active = ?", defaultSkillName, true).
			First(&skill).Error; err == nil {
			_, _ = s.enqueueSkill(r.Context(), repo.ID, skill.ID, "")
		} else {
			s.Log.Warn("default skill not found, repo added with no scans", "skill", defaultSkillName)
		}
	}
	w.Header().Set("HX-Redirect", fmt.Sprintf("/repositories/%d", repo.ID))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) findingStatus(w http.ResponseWriter, r *http.Request) {
	var f db.Finding
	if err := s.DB.First(&f, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	status := db.FindingLifecycle(r.FormValue("status"))
	switch status {
	case db.FindingNew, db.FindingEnriched, db.FindingTriaged, db.FindingReady,
		db.FindingReported, db.FindingAcknowledged, db.FindingFixed, db.FindingPublished,
		db.FindingRejected, db.FindingDuplicate:
		s.DB.Model(&f).Update("status", status)
	default:
		http.Error(w, "invalid status", http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("HX-Redirect", fmt.Sprintf("/findings/%d", f.ID))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) findingVerify(w http.ResponseWriter, r *http.Request) {
	var f db.Finding
	if err := s.DB.Preload("Scan").First(&f, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	// TODO: enqueue confirm job against this finding
	// For now, move to enriched as a placeholder
	s.DB.Model(&f).Update("status", db.FindingEnriched)
	w.Header().Set("HX-Redirect", fmt.Sprintf("/findings/%d", f.ID))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) findingNotes(w http.ResponseWriter, r *http.Request) {
	var f db.Finding
	if err := s.DB.First(&f, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	s.DB.Model(&f).Update("notes", r.FormValue("notes"))
	w.Header().Set("HX-Redirect", fmt.Sprintf("/findings/%d", f.ID))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) packages(w http.ResponseWriter, r *http.Request) {
	q := s.DB.Model(&db.Package{})
	eco := r.URL.Query().Get("ecosystem")
	if eco != "" {
		q = q.Where("ecosystem = ?", eco)
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

	s.render(w, "packages.html", map[string]any{
		"Pkgs": rows, "Page": page, "Ecosystem": eco, "Sort": sort, "Ecosystems": ecosystems,
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
	s.render(w, "package_show.html", data)
}

func (s *Server) findingShow(w http.ResponseWriter, r *http.Request) {
	var f db.Finding
	if err := s.DB.Preload("Scan.Repository").First(&f, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	data := map[string]any{"F": f}
	if id, c, ok := LookupCWE(f.CWE); ok {
		data["CWE"] = map[string]any{"ID": id, "Name": c.Name, "Description": c.Description}
	}
	s.render(w, "finding_show.html", data)
}

func (s *Server) jobs(w http.ResponseWriter, r *http.Request) {
	q := s.DB.Model(&db.Scan{})
	skillName := r.URL.Query().Get("skill")
	if skillName != "" {
		q = q.Where("skill_name = ?", skillName)
	}
	status := r.URL.Query().Get("status")
	if status != "" {
		q = q.Where("status = ?", status)
	}

	sort := r.URL.Query().Get("sort")
	switch sort {
	case "skill":
		q = q.Order("skill_name, id desc")
	case "status":
		q = q.Order("status, id desc")
	case "repository":
		q = q.Joins("Repository").Order("`Repository`.name, scans.id desc")
	default:
		sort = defaultSort
		q = q.Order("scans.id desc")
	}

	var total int64
	q.Count(&total)
	page := paginate(r, total)

	var scans []db.Scan
	q.Preload("Repository").
		Limit(perPage).Offset((page.N - 1) * perPage).Find(&scans)

	var skillNames []string
	s.DB.Model(&db.Scan{}).Where("skill_name != ''").Distinct("skill_name").
		Order("skill_name").Pluck("skill_name", &skillNames)

	s.render(w, "jobs.html", map[string]any{
		"Scans": scans, "Page": page,
		"Skill": skillName, "Status": status, "Sort": sort, "Skills": skillNames,
	})
}

func (s *Server) repoCreate(w http.ResponseWriter, r *http.Request) {
	url := strings.TrimSpace(r.FormValue("url"))
	if url == "" {
		http.Error(w, "url required", http.StatusUnprocessableEntity)
		return
	}
	repo := db.Repository{URL: url, Name: db.NameFromURL(url)}
	if err := s.DB.Where(db.Repository{URL: url}).FirstOrCreate(&repo).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", defaultSkillName, true).First(&skill).Error; err == nil {
		if _, err := s.enqueueSkill(r.Context(), repo.ID, skill.ID, r.FormValue("model")); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		s.Log.Warn("default skill not found, repo added with no scans", "skill", defaultSkillName)
	}
	w.Header().Set("HX-Redirect", fmt.Sprintf("/repositories/%d", repo.ID))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) repoShow(w http.ResponseWriter, r *http.Request) {
	var repo db.Repository
	if err := s.DB.First(&repo, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	var scans []db.Scan
	s.DB.Where("repository_id = ?", repo.ID).Order("id desc").Find(&scans)

	active := false
	for _, sc := range scans {
		if !sc.Status.Terminal() {
			active = true
			break
		}
	}

	// The security-deep-dive skill owns the structured audit report; everything
	// the Summary/Threat Model/Findings tabs render comes from its scans.
	var latest *db.Scan
	var threatModel map[string]any
	for i := range scans {
		if scans[i].SkillName != deepDiveSkillName {
			continue
		}
		if latest == nil {
			latest = &scans[i]
			s.DB.Where("scan_id = ?", latest.ID).Find(&latest.Findings)
		}
		if scans[i].Status == db.ScanDone && scans[i].Report != "" && threatModel == nil {
			var report map[string]any
			if json.Unmarshal([]byte(scans[i].Report), &report) == nil {
				threatModel = report
			}
		}
		if latest != nil && threatModel != nil {
			break
		}
	}

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

	knownURLs := buildKnownURLs(s.DB)
	knownPURLs := buildKnownPURLs(s.DB)

	// Pass repo html_url and commit for location links in threat model
	tmCommit := ""
	if latest != nil {
		tmCommit = latest.Commit
	}

	var activeSkills []db.Skill
	s.DB.Where("active = ?", true).Order("name").Find(&activeSkills)

	data := map[string]any{
		"Repo": repo, "Scans": scans, "Active": active, "Latest": latest,
		"TMCommit": tmCommit,
		"Deps": deps, "Pkgs": pkgs, "Dependents": dependents, "Advisories": advisories, "Maintainers": maintainers, "ThreatModel": threatModel,
		"KnownURLs": knownURLs, "KnownPURLs": knownPURLs,
		"Skills": activeSkills,
	}
	if r.Header.Get("HX-Target") == "scan-rows" {
		s.maybeToast(w, r, repo.Name, scans)
		if !active {
			// All jobs settled since the page loaded; full refresh so the
			// Summary, Findings and metadata sections pick up results.
			w.Header().Set("HX-Refresh", "true")
		}
		s.render(w, "scan_rows", data)
		return
	}
	s.render(w, "repo_show.html", data)
}

func (s *Server) repoScan(w http.ResponseWriter, r *http.Request) {
	var repo db.Repository
	if err := s.DB.First(&repo, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	// The "New scan" button enqueues the deep-dive skill; everything else is
	// triggered either by the triage skill or by the explicit Run skill menu.
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", deepDiveSkillName, true).First(&skill).Error; err != nil {
		http.Error(w, deepDiveSkillName+" skill is not installed", http.StatusPreconditionFailed)
		return
	}
	if _, err := s.enqueueSkill(r.Context(), repo.ID, skill.ID, r.FormValue("model")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("HX-Redirect", fmt.Sprintf("/repositories/%d", repo.ID))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) scanShow(w http.ResponseWriter, r *http.Request) {
	var scan db.Scan
	if err := s.DB.Preload("Repository").Preload("Findings").First(&scan, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, "scan_show.html", scan)
}

func (s *Server) scanRetry(w http.ResponseWriter, r *http.Request) {
	var scan db.Scan
	if err := s.DB.First(&scan, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	if scan.Kind != worker.JobSkill || scan.SkillID == nil {
		http.Error(w, "scan cannot be retried: no skill reference", http.StatusBadRequest)
		return
	}
	newID, err := s.enqueueSkill(r.Context(), scan.RepositoryID, *scan.SkillID, scan.Model)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("HX-Redirect", fmt.Sprintf("/scans/%d", newID))
	w.WriteHeader(http.StatusNoContent)
}

// scanLog returns just the <pre> log block. The scan page polls this with
// hx-trigger while the scan is running so the operator can watch claude work.
func (s *Server) scanLog(w http.ResponseWriter, r *http.Request) {
	var scan db.Scan
	if err := s.DB.First(&scan, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	if scan.Status != db.ScanQueued && scan.Status != db.ScanRunning {
		// Tell htmx to do a full refresh so the report renders.
		w.Header().Set("HX-Refresh", "true")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "scan_log.html", scan); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) enqueueSkill(ctx context.Context, repoID, skillID uint, model string) (uint, error) {
	if !ValidModel(model) {
		model = DefaultModel()
	}
	scan := db.Scan{
		RepositoryID: repoID,
		Kind:         worker.JobSkill,
		Status:       db.ScanQueued,
		Model:        model,
		SkillID:      &skillID,
		APIToken:     NewAPIToken(),
	}
	if err := s.DB.Create(&scan).Error; err != nil {
		return 0, err
	}
	if err := s.Queue.Enqueue(ctx, worker.JobSkill, scan.ID, worker.PrioScan); err != nil {
		return 0, err
	}
	s.DB.Model(&db.Repository{}).Where("id = ?", repoID).Update("updated_at", time.Now())
	return scan.ID, nil
}

// maybeToast compares scan statuses against the "seen" cookie and emits an
// HX-Trigger header for the first scan that has moved to a terminal state
// since the client last polled. The cookie stores id:status pairs so a page
// reload does not re-toast.
func (s *Server) maybeToast(w http.ResponseWriter, r *http.Request, name string, scans []db.Scan) {
	prev := map[string]string{}
	if c, err := r.Cookie("scanstate"); err == nil {
		for pair := range strings.SplitSeq(c.Value, ",") {
			if k, v, ok := strings.Cut(pair, ":"); ok {
				prev[k] = v
			}
		}
	}
	var cur []string
	for _, sc := range scans {
		id := strconv.Itoa(int(sc.ID))
		cur = append(cur, id+":"+string(sc.Status))
		if sc.Status.Terminal() && prev[id] != "" && prev[id] != string(sc.Status) {
			payload, _ := json.Marshal(map[string]any{"scanStatus": map[string]any{
				"id": sc.ID, "status": sc.Status, "name": name,
			}})
			w.Header().Set("HX-Trigger", string(payload))
		}
	}
	http.SetCookie(w, &http.Cookie{Name: "scanstate", Value: strings.Join(cur, ","), Path: "/", SameSite: http.SameSiteStrictMode})
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

func buildKnownURLs(gdb *gorm.DB) map[string]uint {
	m := map[string]uint{}
	var rows []db.Repository
	gdb.Select("id", "url").Find(&rows)
	for _, r := range rows {
		m[r.URL] = r.ID
	}
	return m
}

func buildKnownPURLs(gdb *gorm.DB) map[string]uint {
	m := map[string]uint{}
	var rows []db.Package
	gdb.Find(&rows)
	for _, p := range rows {
		m[p.PURL] = p.RepositoryID
		if base, _, ok := strings.Cut(p.PURL, "?"); ok {
			m[base] = p.RepositoryID
		}
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

// securityHeaders enforces T3 mitigations: host header check to prevent DNS
// rebinding, and Sec-Fetch-Site check on POST to prevent cross-origin CSRF.
func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		// Strip port for comparison
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
		if host != "127.0.0.1" && host != "localhost" && host != "[::1]" {
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
