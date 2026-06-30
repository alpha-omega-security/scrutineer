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
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
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

// ErrInvalidRef is returned by enqueueSkillWith when opts.Ref fails the
// shared ref-charset validation. Mirrors ErrSkillProfileMismatch so the
// API path rejects a bad ref at the boundary (400) instead of enqueueing
// a scan that will fail later at git-clone time.
var ErrInvalidRef = errors.New("invalid git ref")

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

	// Commit is the git SHA scrutineer itself was built from, shown on the
	// settings page. Set once by main; empty when the build carries no VCS
	// stamp (e.g. an ldflags-less build outside a git checkout).
	Commit string

	// EncRecipients is the parsed recipients file; nil disables encrypted
	// export. Supports age X25519 and SSH public keys.
	EncRecipients []age.Recipient
	// EncIdentities decrypts encrypted imports. Multiple entries support
	// key rotation (old + new). nil disables encrypted import.
	EncIdentities []age.Identity

	// resolvePURL maps a Package URL to its source repository URL via
	// packages.ecosyste.ms. Field rather than direct call so tests can
	// stub the network lookup.
	resolvePURL func(ctx context.Context, purl string) string
	resolveSync bool

	// listBranches enumerates a remote's branches for the add-repo branch
	// picker. Field rather than a direct worker call so tests can stub the
	// network lookup, mirroring resolvePURL.
	listBranches func(ctx context.Context, cloneURL string) ([]string, error)

	// fetchOrgRepos lists every repository in a GitHub org for the
	// org-import path. Field rather than a direct call so tests can stub
	// the network lookup, mirroring resolvePURL and listBranches.
	fetchOrgRepos func(ctx context.Context, org string) ([]OrgRepo, error)

	// prefetchEcosystems warms the per-repository ecosyste.ms cache
	// when a new repo is added, in parallel with the triage enqueue. Field
	// rather than a direct call so tests can stub the network fan-out,
	// mirroring resolvePURL and friends.
	prefetchEcosystems func(repoID uint)

	// Runtime defaults a new scan inherits when the caller pins none.
	// Both are seeded at startup from config/flags and mutable via the
	// settings page, so a request can write while another reads. One
	// mutex covers both; the default-model getter falls back to
	// Models[0] and the default-effort getter to builtinDefaultEffort
	// when unset.
	defaultsMu    sync.RWMutex
	defaultModel  string
	defaultEffort string

	skillNamesMu    sync.Mutex
	skillNamesCache []string
	skillNamesTTL   time.Time

	// toolMeta caches the scanner-tool and container runtime versions shown on
	// the settings page. Gathering them shells out to the runtime, so it is
	// cached behind a TTL to keep the page DB-fast on repeat loads.
	toolMetaMu    sync.Mutex
	toolMetaCache toolMetadata
	toolMetaTTL   time.Time

	// runnerStatus is the result of the boot-time runner-image staleness check
	// (issue #337), set once by main shortly after startup and read by the
	// settings page to render the stale-image banner. The zero value renders
	// nothing, so reads before the check completes are safe.
	runnerStatusMu sync.Mutex
	runnerStatus   worker.RunnerImageStatus
}

// SetRunnerImageStatus records the boot-time runner-image staleness result so
// the settings page can surface it. Called once from main after the background
// check finishes.
func (s *Server) SetRunnerImageStatus(st worker.RunnerImageStatus) {
	s.runnerStatusMu.Lock()
	defer s.runnerStatusMu.Unlock()
	s.runnerStatus = st
}

// runnerImageStatus returns the last recorded staleness result, or the zero
// value (Stale=false) when the check has not run or found nothing to report.
func (s *Server) runnerImageStatus() worker.RunnerImageStatus {
	s.runnerStatusMu.Lock()
	defer s.runnerStatusMu.Unlock()
	return s.runnerStatus
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
		statusKey:  func(s db.ScanStatus) string { return string(s) },
		"fstatus":  func(s db.FindingLifecycle) string { return string(s) },
		"sevlabel": displaySeverity,
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[kv[i].(string)] = kv[i+1]
			}
			return m
		},
		"list":  func(xs ...string) []string { return xs },
		"len64": tmplLen64,
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
	s := &Server{DB: gdb, Queue: q, Log: log, Broker: broker, Worker: w, tmpl: t,
		resolvePURL: resolvePURLRepo, listBranches: worker.ListRemoteBranches,
		fetchOrgRepos: fetchGitHubOrgRepos}
	s.prefetchEcosystems = s.ecosystemsPrefetch
	if w != nil {
		w.OnFindingCreated = s.autoEnqueueRevalidate
		w.OnRevalidateVerdict = s.autoChainVerifyAfterRevalidate
		w.OnScanFinalized = s.onScanFinalized
	}
	return s, nil
}

// ecosystemsPrefetch warms the ecosyste.ms cache for a freshly added repo in a
// detached goroutine: the HTTP request that created the repo returns
// immediately while the fetch runs on its own timeout. Best-effort.
func (s *Server) ecosystemsPrefetch(repoID uint) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), worker.EcosystemsPrefetchTimeout)
		defer cancel()
		if err := worker.RefreshEcosystems(ctx, s.DB, repoID, false, s.Log); err != nil {
			s.Log.Warn("ecosystems prefetch failed", "repo", repoID, "err", err)
		}
	}()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.FileServerFS(staticFS))
	mux.HandleFunc("GET /events", s.events)
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /repositories", s.repoList)
	mux.HandleFunc("GET /repositories/new", s.repoNew)
	mux.HandleFunc("GET /repositories/branches", s.repoBranches)
	mux.HandleFunc("POST /repositories", s.repoCreate)
	mux.HandleFunc("POST /repositories/bulk", s.repoBulkCreate)
	mux.HandleFunc("POST /repositories/org", s.repoOrgImport)
	mux.HandleFunc("GET /repositories/{id}", s.repoShow)
	mux.HandleFunc("GET /repositories/{id}/blob/{commit}/{path...}", s.repoBlob)
	mux.HandleFunc("GET /repositories/{id}/report.md", s.repoReport)
	mux.HandleFunc("POST /repositories/{id}/scan", s.repoScan)
	mux.HandleFunc("POST /repositories/{id}/scan-all", s.repoScanAll)
	mux.HandleFunc("POST /repositories/{id}/validate-fix", s.validateFix)
	mux.HandleFunc("POST /repositories/{id}/delete", s.repoDelete)
	mux.HandleFunc("POST /repositories/{id}/disclosure-channel", s.repoDisclosureChannel)
	mux.HandleFunc("POST /repositories/{id}/threat-model", s.repoThreatModelSave)
	mux.HandleFunc("POST /repositories/{id}/threat-model/run", s.repoThreatModelRun)
	mux.HandleFunc("POST /repositories/{id}/threat-model/clear", s.repoThreatModelClear)
	mux.HandleFunc("GET /scans", s.jobs)
	mux.HandleFunc("GET /orgs", s.orgsList)
	mux.HandleFunc("GET /orgs/{login}", s.orgShow)
	mux.HandleFunc("GET /orgs/{login}/findings.md", s.orgReport)
	mux.HandleFunc("GET /orgs/{login}/summary.md", s.orgSummary)
	mux.HandleFunc("GET /maintainers", s.maintainersList)
	mux.HandleFunc("GET /maintainers/{id}", s.maintainerShow)
	mux.HandleFunc("POST /maintainers/{id}/do-not-contact", s.maintainerDoNotContact)
	mux.HandleFunc("GET /findings", s.findings)
	mux.HandleFunc("GET /audit", s.auditPage)
	mux.HandleFunc("POST /findings/{id}/reviews", s.findingReviewCreate)
	mux.HandleFunc("GET /findings/{id}", s.findingShow)
	mux.HandleFunc("GET /findings/{id}/report.md", s.findingReport)
	mux.HandleFunc("GET /findings/{id}/csaf.json", s.findingCSAF)
	mux.HandleFunc("GET /findings/{id}/osv.json", s.findingOSV)
	mux.HandleFunc("GET /findings/{id}/disclosure.html", s.findingDisclosureHTML)
	mux.HandleFunc("POST /findings/{id}/status", s.findingStatus)
	mux.HandleFunc("POST /findings/{id}/exploited-in-wild", s.findingExploitedInWild)
	mux.HandleFunc("POST /findings/{id}/verify", s.findingVerify)
	mux.HandleFunc("POST /repositories/{id}/verify-all", s.repoVerifyAll)
	mux.HandleFunc("POST /findings/{id}/disclose", s.findingDisclose)
	mux.HandleFunc("POST /findings/{id}/public-issue", s.findingPublicIssue)
	mux.HandleFunc("POST /findings/{id}/mitigate", s.findingMitigate)
	mux.HandleFunc("POST /findings/{id}/patch", s.findingPatchRun)
	mux.HandleFunc("POST /findings/{id}/exposure", s.findingExposureRun)
	mux.HandleFunc("GET /findings/{id}/patch.diff", s.findingPatchDownload)
	mux.HandleFunc("GET /findings/{id}/bundle.tar.gz", s.findingBundleDownload)
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
	mux.HandleFunc("POST /scans/{id}/resume", s.scanResume)
	mux.HandleFunc("POST /scans/pause-queued", s.scansPauseQueued)
	mux.HandleFunc("POST /scans/resume-paused", s.scansResumePaused)
	mux.HandleFunc("POST /scans/retry-failed", s.scansRetryFailed)
	mux.HandleFunc("POST /scans/cancel-all", s.scansCancelAll)
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
	mux.HandleFunc("POST /settings/effort", s.settingsUpdateEffort)
	mux.HandleFunc("POST /settings/color-scheme", s.settingsUpdateColorScheme)
	mux.HandleFunc("POST /settings/concurrency", s.settingsUpdateConcurrency)
	mux.HandleFunc("POST /settings/runner/restart", s.settingsRestartRunner)
	mux.HandleFunc("POST /settings/max-turns", s.settingsUpdateMaxTurns)

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
		{"/findings", "findings"}, {"/scans", "scans"}, {"/sboms", "sboms"}, {"/audit", "audit"},
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
	// tabRowCap bounds per-tab collections on detail pages (repo Findings,
	// Dependencies, Dependents, Advisories; SBOM Findings/Advisories). The
	// tabs are summary views: when a repo has more rows than this, the page
	// shows the first N with a count and a link to the full filtered index.
	tabRowCap = 200
	// historyRowCap bounds the FindingHistory list on a finding page. A
	// finding observed across hundreds of rescans accumulates one row each;
	// only the most recent are useful inline.
	historyRowCap  = 100
	statusKey      = "status"
	allStatusValue = "all"
	errorKey       = "error"
	successKey     = "success"
	warningKey     = "warning"
	// sortRepository and sortSeverity are the shared sort options used by
	// the findings, scans, advisories, and SBOM indexes.
	sortRepository = "repository"
	sortSeverity   = "severity"
)

// tmplLen64 is the len64 template func: returns len(v) as an int64 for
// comparison against COUNT(*)-typed totals. Non-len-able or nil values
// return 0 instead of panicking so a stray template arg renders as
// "not capped" rather than 500ing the page.
func tmplLen64(v any) int64 {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array, reflect.Map, reflect.String, reflect.Chan:
		return int64(rv.Len())
	}
	return 0
}

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
	DiskBytes     int64
	// Branches lists the distinct non-default refs this repo has been
	// scanned on, for the branch tags next to its name. Empty when every
	// scan ran on the default branch.
	Branches []string
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
			Where("scan_id IN (?)", findingsScanIDs(s.DB)).
			Where("status NOT IN ?", db.ClosedFindingLifecycles).
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

	branchesByRepo := map[uint][]string{}
	if len(repoIDs) > 0 {
		// Distinct non-default branches scanned per repo. Ordered by ref so
		// each repo's badges render in a reproducible order.
		type repoRef struct {
			RepositoryID uint
			Ref          string
		}
		var refs []repoRef
		s.DB.Model(&db.Scan{}).
			Select("DISTINCT repository_id, ref").
			Where("repository_id IN ? AND ref != ''", repoIDs).
			Order("ref").
			Scan(&refs)
		for _, rr := range refs {
			branchesByRepo[rr.RepositoryID] = append(branchesByRepo[rr.RepositoryID], rr.Ref)
		}
	}

	rows := make([]repoRow, 0, len(repos))
	for _, repo := range repos {
		rows = append(rows, repoRow{
			Repository:    repo,
			LastScan:      lastScans[repo.ID],
			FindingsTotal: findingCounts[repo.ID],
			// Read the cached size from the row; the worker refreshes it on
			// each scan and a startup backfill seeds it, so the list never
			// walks the clone cache per row (#126).
			DiskBytes: repo.DiskBytes,
			Branches:  branchesByRepo[repo.ID],
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
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return v, false
	}
	if err := s.DB.First(&v, id).Error; err != nil {
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
func loadRepoFindings(gdb *gorm.DB, repoID uint, category string) repoFindings {
	base := func() *gorm.DB {
		return gdb.Model(&db.Finding{}).
			Where("repository_id = ? AND status NOT IN ?", repoID, db.ClosedFindingLifecycles)
	}

	ddQ := base().Where("scan_id IN (?)", findingsScanIDs(gdb))
	if category != "" {
		ddQ = applyCWECategoryFilter(ddQ, category)
	}
	var rf repoFindings
	ddQ.Count(&rf.DeepDiveTotal)
	ddQ.Order(severityOrder).Order("id desc").Limit(tabRowCap).Find(&rf.DeepDive)

	scQ := base().Where("scan_id NOT IN (?)", findingsScanIDs(gdb))
	scQ.Count(&rf.ScannersTotal)
	scQ.Order(severityOrder).Order("id desc").Limit(tabRowCap).Find(&rf.Scanners)

	rf.ScanSkill = map[uint]string{}
	rf.ScanCommit = map[uint]string{}
	if len(rf.DeepDive)+len(rf.Scanners) == 0 {
		return rf
	}
	scanIDs := make([]uint, 0, len(rf.DeepDive)+len(rf.Scanners))
	seen := map[uint]bool{}
	for _, f := range append(rf.DeepDive, rf.Scanners...) {
		if !seen[f.ScanID] {
			seen[f.ScanID] = true
			scanIDs = append(scanIDs, f.ScanID)
		}
	}
	var rows []struct {
		ID        uint
		SkillName string
		Commit    string
	}
	gdb.Raw("SELECT id, COALESCE(skill_name, '') AS skill_name, COALESCE(`commit`, '') AS `commit` FROM scans WHERE id IN ?", scanIDs).Scan(&rows)
	for _, row := range rows {
		rf.ScanSkill[row.ID] = row.SkillName
		rf.ScanCommit[row.ID] = row.Commit
	}
	return rf
}

// repoFindings carries the two capped finding sets for a repo's tabs plus
// the per-scan lookup maps the template needs to render the producing skill
// name and the location-link commit.
type repoFindings struct {
	DeepDive      []db.Finding
	DeepDiveTotal int64
	Scanners      []db.Finding
	ScannersTotal int64
	ScanSkill     map[uint]string
	ScanCommit    map[uint]string
}

func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	// Default to deep-dive findings only; scanner skills (zizmor, semgrep)
	// are noisy enough to drown out the audit list. ?scanners=1 includes
	// them and is exposed as a toggle in the UI.
	scanners := r.URL.Query().Get("scanners") == "1"
	q := s.findingsIndexQuery(r, scanners, true)
	sev := r.URL.Query().Get("severity")
	status := r.URL.Query().Get(statusKey)
	category := r.URL.Query().Get("category")
	owner := r.URL.Query().Get("owner")
	missed := r.URL.Query().Get("missed") == "1"
	search := strings.TrimSpace(r.URL.Query().Get("q"))

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
	missedTotal, scannerTotal := s.findingToggleCounts(r, scanners)

	s.render(w, r, "findings.html", map[string]any{
		"Findings": rows, "Page": page, "Severity": sev, "Sort": sort,
		"Category": category, "Categories": CWECategories(), "Uncategorized": UncategorizedCWE,
		"Repos": reposByID, "Q": search, "AnySubPath": anySubPath,
		"Owner": owner, "Missed": missed, "MissedTotal": missedTotal,
		"Scanners": scanners, "ScannerTotal": scannerTotal,
		"Status": status, "Statuses": db.FindingLifecycles,
	})
}

func (s *Server) findingsIndexQuery(r *http.Request, includeScanners, includeMissed bool) *gorm.DB {
	q := s.DB.Model(&db.Finding{})
	if !includeScanners {
		q = q.Where("scan_id IN (?)", findingsScanIDs(s.DB))
	}
	if sev := r.URL.Query().Get("severity"); sev != "" {
		q = q.Where("severity = ?", sev)
	}
	q = applyFindingStatusFilter(q, r.URL.Query().Get(statusKey))
	if category := r.URL.Query().Get("category"); category != "" {
		q = applyCWECategoryFilter(q, category)
	}
	if owner := r.URL.Query().Get("owner"); owner != "" {
		q = q.Where("repository_id IN (?)",
			s.DB.Model(&db.Repository{}).Select("id").Where("owner = ?", owner))
	}
	if includeMissed && r.URL.Query().Get("missed") == "1" {
		q = q.Where("missed_count > 0")
	}
	if search := strings.TrimSpace(r.URL.Query().Get("q")); search != "" {
		like := "%" + search + "%"
		q = q.Where("title LIKE ? OR location LIKE ? OR cwe LIKE ? OR cve_id LIKE ? OR ghsa_id LIKE ? OR affected LIKE ?",
			like, like, like, like, like, like)
	}
	return q
}

func (s *Server) findingToggleCounts(r *http.Request, scanners bool) (int64, int64) {
	missedWhere, missedArgs := findingIndexWhereSQL(r, scanners, false)
	missedWhere = append(missedWhere, "missed_count > 0")

	scannerWhere, scannerArgs := findingIndexWhereSQL(r, true, true)
	scannerWhere = append(scannerWhere, scannerScanFilter)

	var counts struct {
		MissedTotal  int64
		ScannerTotal int64
	}
	sql := fmt.Sprintf(
		"SELECT (SELECT COUNT(*) FROM findings WHERE %s) AS missed_total, (SELECT COUNT(*) FROM findings WHERE %s) AS scanner_total",
		strings.Join(missedWhere, " AND "),
		strings.Join(scannerWhere, " AND "),
	)
	args := make([]any, 0, len(missedArgs)+len(scannerArgs))
	args = append(args, missedArgs...)
	args = append(args, scannerArgs...)
	s.DB.Raw(sql, args...).Scan(&counts)
	return counts.MissedTotal, counts.ScannerTotal
}

func findingIndexWhereSQL(r *http.Request, includeScanners, includeMissed bool) ([]string, []any) {
	where := []string{"1 = 1"}
	var args []any
	if !includeScanners {
		where = append(where, nonScannerScanFilter)
	}
	if sev := r.URL.Query().Get("severity"); sev != "" {
		where = append(where, "severity = ?")
		args = append(args, sev)
	}
	switch status := r.URL.Query().Get(statusKey); status {
	case "":
		where = append(where, "status NOT IN ("+db.ClosedFindingLifecycleSQLValues()+")")
	case allStatusValue:
	default:
		where = append(where, "status = ?")
		args = append(args, status)
	}
	if category := r.URL.Query().Get("category"); category != "" {
		switch {
		case category == UncategorizedCWE && len(categorizedIDs) == 0:
			where = append(where, "cwe = ''")
		case category == UncategorizedCWE:
			where = append(where, "(cwe = '' OR cwe NOT IN ?)")
			args = append(args, categorizedIDs)
		case len(CWEsInCategory(category)) == 0:
			where = append(where, "1 = 0")
		default:
			where = append(where, "cwe IN ?")
			args = append(args, CWEsInCategory(category))
		}
	}
	if owner := r.URL.Query().Get("owner"); owner != "" {
		where = append(where, "repository_id IN (SELECT id FROM repositories WHERE owner = ?)")
		args = append(args, owner)
	}
	if includeMissed && r.URL.Query().Get("missed") == "1" {
		where = append(where, "missed_count > 0")
	}
	if search := strings.TrimSpace(r.URL.Query().Get("q")); search != "" {
		like := "%" + search + "%"
		where = append(where, "(title LIKE ? OR location LIKE ? OR cwe LIKE ? OR cve_id LIKE ? OR ghsa_id LIKE ? OR affected LIKE ?)")
		args = append(args, like, like, like, like, like, like)
	}
	return where, args
}

func applyFindingStatusFilter(q *gorm.DB, status string) *gorm.DB {
	switch status {
	case "":
		return q.Where("status NOT IN ?", db.ClosedFindingLifecycles)
	case allStatusValue:
		return q
	default:
		return q.Where("status = ?", status)
	}
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
	// vulnScanSkillName is the LLM-driven high-recall candidate scan. Like
	// security-deep-dive it uses a model to find real vulnerabilities, so its
	// findings belong in the curated Findings bucket alongside the deep-dive
	// audit rather than the Scanners tab full of cheap tool output (#458).
	vulnScanSkillName = "vuln-scan"
	// aliasedFindingsScanFilter is the same Findings-tab predicate as
	// nonScannerScanFilter, written for the raw aggregate counts on the
	// maintainers and orgs indexes. Those queries LEFT JOIN scans under the
	// alias `s` and group findings, so they filter s.skill_name/s.kind directly
	// rather than threading findings.scan_id through a subquery. A finding
	// counts when its scan is one of the LLM audits (security-deep-dive,
	// vuln-scan), a legacy/empty skill_name, or an operator import (kind=import);
	// the two ?s bind deepDiveSkillName and vulnScanSkillName in that order.
	// The `s.skill_name IS NULL` arm doubles as the LEFT JOIN "this row has no
	// findings" guard, so zero-count maintainers/orgs stay in the result with
	// n=0. Keep it in lockstep with findingsBucketSkillSQL — a copy that lacked
	// the kind='import' arm is exactly what kept imports out of these totals
	// after they began showing in the Findings tab.
	aliasedFindingsScanFilter = "(s.skill_name IN (?, ?) OR s.skill_name = '' OR s.skill_name IS NULL OR s.kind = 'import')"
	// threatModelSkillName is the skill whose report feeds the Threat Model
	// tab when present; repos that predate it fall back to the boundaries
	// section of the deep-dive report so older scans keep rendering.
	threatModelSkillName = "threat-model"
	zizmorSkillName      = "zizmor"
)

// The Findings-bucket filters are vars rather than consts because they splice
// the skill names through db.SQLStringLiteral for defense-in-depth quote
// escaping — a function call, which a Go const initializer cannot contain.
var (
	// findingsBucketSkillSQL is the single source of truth for which scans'
	// findings populate the curated Findings bucket: the LLM audit skills
	// (security-deep-dive, vuln-scan), legacy claude jobs with an empty or NULL
	// skill_name, and operator imports (kind='import'). An import is a
	// deliberate curation act, not noisy auto-scanner output, so it sits with
	// the audit findings and shows by default rather than behind the Scanners
	// toggle. The skill names are spliced in as literals rather than bound
	// parameters because this fragment is embedded raw into larger SQL (e.g. an
	// Order clause) that can't carry args; each is escaped through
	// db.SQLStringLiteral so a name that ever gained a quote is doubled rather
	// than able to break out (see TestDeepDiveSkillNameSafeForSplicing).
	// Parenthesised so it can be embedded in larger expressions without
	// precedence surprises.
	findingsBucketSkillSQL = "(skill_name IN (" + db.SQLStringLiteral(deepDiveSkillName) + ", " + db.SQLStringLiteral(vulnScanSkillName) + ") OR skill_name = '' OR skill_name IS NULL OR kind = 'import')"
	// nonScannerScanFilter selects findings whose parent scan populates the
	// Findings bucket (findingsBucketSkillSQL) — every finding the UI shows by
	// default. scannerScanFilter is its structural inverse: the cheap tool
	// scanners (semgrep, zizmor) that run as skills and carry the tool name as
	// skill_name. Deriving both from findingsBucketSkillSQL keeps the Findings
	// toggle, the repo Findings tab, and the dedup auto-enqueue agreeing on what
	// "scanner" means without a second copy of the subquery to keep in sync — so
	// vuln-scan findings and imports both count toward the dedup-pass threshold.
	nonScannerScanFilter = "scan_id IN (SELECT id FROM scans WHERE " + findingsBucketSkillSQL + ")"
	scannerScanFilter    = "NOT (" + nonScannerScanFilter + ")"
)

// deepDiveFindingsCountSQL is a correlated subselect that counts curated
// findings for the surrounding repositories row. Used in the repos list
// "findings" sort. Tool-scanner skills are excluded so the ordering matches
// the counts shown in the Findings column. The LLM audit skills
// (security-deep-dive, vuln-scan), legacy rows, and operator imports
// (kind='import') all count via findingsBucketSkillSQL, so the column agrees
// with the Findings tab. The skill names are spliced into findingsBucketSkillSQL
// as text (this fragment feeds an ORDER BY that can't take a bind parameter);
// both are trusted compile-time constants kept free of SQL metacharacters by
// TestDeepDiveSkillNameSafeForSplicing.
var deepDiveFindingsCountSQL = `SELECT COUNT(*) FROM findings f
	    WHERE f.repository_id = repositories.id
	      AND f.status NOT IN (` + db.ClosedFindingLifecycleSQLValues() + `)
	      AND f.scan_id IN (SELECT id FROM scans WHERE ` + findingsBucketSkillSQL + `)`

// findingsScanIDs returns a GORM subquery selecting scan IDs that belong to
// the curated LLM audits (security-deep-dive, vuln-scan), to legacy/empty
// skill_name rows, or to an operator import (kind='import') — everything in
// findingsBucketSkillSQL. Use it as a `scan_id IN (?)` filter to keep listings
// consistent with the repo Findings tab.
func findingsScanIDs(gdb *gorm.DB) *gorm.DB {
	return gdb.Model(&db.Scan{}).Select("id").Where(findingsBucketSkillSQL)
}

// isLLMAuditSkill reports whether a finalized scan is one of the curated LLM
// audits (security-deep-dive, vuln-scan) whose fresh output drives the
// auto-triage funnels (finding-dedup and the revalidate pre-sort). Unlike
// findingsBucketSkillSQL this deliberately excludes legacy empty/NULL
// skill_name rows and imports: those are inert, not a live scan that just
// produced new findings worth triaging.
func isLLMAuditSkill(skillName string) bool {
	return skillName == deepDiveSkillName || skillName == vulnScanSkillName
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
	repo, _, err := s.createOrTriageRepo(r.Context(), input, "", true)
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
	status := db.FindingLifecycle(r.FormValue(statusKey))
	switch status {
	case db.FindingNew, db.FindingEnriched, db.FindingTriaged, db.FindingReady,
		db.FindingReported, db.FindingAcknowledged, db.FindingFixed, db.FindingPublished,
		db.FindingRejected, db.FindingDuplicate:
		if err := db.WriteFindingField(s.DB, f.ID, statusKey, string(status), db.SourceAnalyst, ""); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "invalid status", http.StatusUnprocessableEntity)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/findings/%d", f.ID))
}

// findingExploitedInWild handles the analyst form on the finding page
// for marking whether the finding is being exploited in the wild. The
// status is a closed enum (yes / no / empty for unknown); the evidence
// field is free text and may stand alone (an analyst recording context
// without yet committing to yes/no). Both writes go through
// WriteFindingField so the change history records who set them and
// when.
func (s *Server) findingExploitedInWild(w http.ResponseWriter, r *http.Request) {
	f, ok := loadByID[db.Finding](s, w, r)
	if !ok {
		return
	}
	status := strings.TrimSpace(r.FormValue("exploited_in_wild"))
	switch status {
	case "", "yes", "no":
	default:
		http.Error(w, "exploited_in_wild must be yes, no, or empty", http.StatusUnprocessableEntity)
		return
	}
	evidence := strings.TrimSpace(r.FormValue("exploited_in_wild_evidence"))
	if err := db.WriteFindingField(s.DB, f.ID, "exploited_in_wild", status, db.SourceAnalyst, ""); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := db.WriteFindingField(s.DB, f.ID, "exploited_in_wild_evidence", evidence, db.SourceAnalyst, ""); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/findings/%d", f.ID))
}

// verifySkillName is the skill the Verify button on the finding page runs.
const verifySkillName = "verify"

// discloseSkillName is the skill the Draft disclosure button runs.
const discloseSkillName = "disclose"

// publicIssueSkillName is the skill the File public issue button runs.
const publicIssueSkillName = "public-issue"

// patchSkillName is the skill the Propose patch button runs.
const patchSkillName = "patch"

// mitigateSkillName is the skill the Draft mitigation button runs.
const mitigateSkillName = "mitigate"

func (s *Server) findingVerify(w http.ResponseWriter, r *http.Request) {
	s.runFindingSkill(w, r, verifySkillName, true)
}

func (s *Server) findingDisclose(w http.ResponseWriter, r *http.Request) {
	s.runFindingSkill(w, r, discloseSkillName, false)
}

func (s *Server) findingPublicIssue(w http.ResponseWriter, r *http.Request) {
	s.runFindingSkill(w, r, publicIssueSkillName, false)
}

func (s *Server) findingPatchRun(w http.ResponseWriter, r *http.Request) {
	s.runFindingSkill(w, r, patchSkillName, false)
}

func (s *Server) findingMitigate(w http.ResponseWriter, r *http.Request) {
	s.runFindingSkill(w, r, mitigateSkillName, false)
}

func (s *Server) runFindingSkill(w http.ResponseWriter, r *http.Request, name string, skipOpen bool) {
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
	if skipOpen {
		if openScan, ok := s.openFindingSkillScan(f.ID, name); ok {
			setFlash(w, Flash{Category: warningKey, Title: name + " already queued or running"})
			s.redirect(w, r, fmt.Sprintf("/scans/%d", openScan.ID))
			return
		}
	}
	scanID, err := s.enqueueSkillScoped(r.Context(), scan.RepositoryID, skill.ID, new(f.ID), r.FormValue("model"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/scans/%d", scanID))
}

func (s *Server) openFindingSkillScan(findingID uint, skillName string) (db.Scan, bool) {
	var scan db.Scan
	err := s.DB.
		Where("finding_id = ? AND skill_name = ? AND status IN ?",
			findingID, skillName, []db.ScanStatus{db.ScanQueued, db.ScanRunning}).
		Order("status_priority asc, id desc").
		First(&scan).Error
	if err != nil {
		return db.Scan{}, false
	}
	return scan, true
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
		setFlash(w, Flash{Category: errorKey, Title: verifySkillName + " skill is not installed"})
		s.redirect(w, r, fmt.Sprintf("/repositories/%d#rt4", repo.ID))
		return
	}

	q := s.DB.Model(&db.Finding{}).
		Where("repository_id = ? AND status = ? AND scan_id IN (?)",
			repo.ID, db.FindingNew, findingsScanIDs(s.DB))
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
		return Flash{Category: successKey, Title: "No findings awaiting verification"}
	}
	parts := []string{fmt.Sprintf("%d queued", queued)}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d already running", skipped))
	}
	if errored > 0 {
		parts = append(parts, fmt.Sprintf("%d errored", errored))
	}
	cat := successKey
	switch {
	case errored > 0:
		cat = errorKey
	case queued == 0:
		cat = warningKey
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
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.DB.Preload("Repository").First(&p, id).Error; err != nil {
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

type findingWorkflowData struct {
	db.Finding
	VerifyInFlight bool
}

func (s *Server) findingShow(w http.ResponseWriter, r *http.Request) {
	var f db.Finding
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.DB.Preload("Labels").First(&f, id).Error; err != nil {
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
	var historyTotal int64
	s.DB.Model(&db.FindingHistory{}).Where("finding_id = ?", f.ID).Count(&historyTotal)
	s.DB.Where("finding_id = ?", f.ID).Order("created_at desc").
		Limit(historyRowCap).Find(&history)
	reviews, _ := db.ListFindingReviews(s.DB, f.ID)
	latestRevalidate := db.LatestRevalidateVerdict(s.DB, f.ID)
	var labels []db.FindingLabel
	s.DB.Order("name").Find(&labels)
	selected := make(map[string]bool, len(f.Labels))
	for _, l := range f.Labels {
		selected[l.Name] = true
	}
	_, verifyInFlight := s.openFindingSkillScan(f.ID, verifySkillName)

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
		"F":                f,
		"Scan":             scan,
		"Repo":             repo,
		"Notes":            notes,
		"Communications":   comms,
		"References":       refs,
		"History":          history,
		"HistoryTotal":     historyTotal,
		"Reviews":          reviews,
		"LatestRevalidate": latestRevalidate,
		"AllLabels":        labels,
		"Selected":         selected,
		"Workflow":         findingWorkflowData{Finding: f, VerifyInFlight: verifyInFlight},
		"Exposures":        exposures,
		"ShowExposure":     findingSupportsExposure(scan),
	}
	if data["ShowExposure"].(bool) {
		var depCount int64
		s.DB.Model(&db.Dependent{}).Where("repository_id = ?", scan.RepositoryID).Count(&depCount)
		data["HasDependents"] = depCount > 0
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
	// The explicit branch field is the operator's clear choice, so it wins
	// over any /tree/<branch> already embedded in the pasted URL.
	if ref := strings.TrimSpace(r.FormValue("ref")); ref != "" {
		input.Branch = ref
	}
	repo, _, err := s.createOrTriageRepo(r.Context(), input, r.FormValue("model"), true)
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
	s.repoFormError(w, r, "add-repo-alert-oob", title, err, status)
}

// repoFormError renders an inline error for a failed add-repo-style
// submission. For htmx requests it swaps the named OOB alert template (each
// dialog has its own alert div, so the error lands in the visible one); plain
// posts get a plain-text error at the given status.
func (s *Server) repoFormError(w http.ResponseWriter, r *http.Request, alertTmpl, title string, err error, status int) {
	if !isHX(r) {
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if execErr := s.tmpl.ExecuteTemplate(w, alertTmpl, Flash{
		Title:       title,
		Description: err.Error(),
	}); execErr != nil {
		s.Log.Error("render "+alertTmpl, "err", execErr)
	}
}

// repoNew is the no-javascript fallback for the Add Repository dialog.
func (s *Server) repoNew(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "repo_new.html", map[string]any{
		"Bulk": r.FormValue("bulk") != "",
		"Org":  r.FormValue("org") != "",
	})
}

// branchListTimeout caps the remote ls-remote so a slow or unreachable host
// cannot hang the add-repo form's branch picker.
const branchListTimeout = 8 * time.Second

// repoBranches feeds the add-repo form's branch picker a <datalist> of the
// remote's branch names. Best-effort: a local, non-https, invalid, or
// unreachable URL yields an empty list (the field stays free-text) and the
// request never 500s or blocks the form.
func (s *Server) repoBranches(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var branches []string
	if input, err := ParseRepoInput(r.URL.Query().Get("url")); err == nil && !input.Local {
		ctx, cancel := context.WithTimeout(r.Context(), branchListTimeout)
		defer cancel()
		branches, _ = s.listBranches(ctx, input.CloneURL)
	}
	if err := s.tmpl.ExecuteTemplate(w, "branch-options", branches); err != nil {
		s.Log.Error("render branch-options", "err", err)
	}
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
		_, isNew, err := s.createOrTriageRepo(r.Context(), input, r.FormValue("model"), true)
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
// It FirstOrCreates the Repository row and, when the row is new and triage
// is true, enqueues the default skill. isNew reports whether the repo was
// actually created (so callers can distinguish "queued" from "already present").
func (s *Server) createOrTriageRepo(ctx context.Context, input RepoInput, model string, triage bool) (db.Repository, bool, error) {
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
	// Eagerly warm the ecosyste.ms cache for a freshly added remote repo, in
	// parallel with the triage enqueue below. Local repos have no
	// upstream entry; the goroutine is best-effort and detached from ctx.
	if isNew && !repo.IsLocal() && s.prefetchEcosystems != nil {
		s.prefetchEcosystems(repo.ID)
	}
	if !triage {
		return repo, isNew, nil
	}
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
		return successKey
	}
	if created == 0 && len(invalid) > 0 {
		return errorKey
	}
	return warningKey
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

// repoScanActionCounts returns the number of cancellable (running/queued) and
// resumable (paused) scans on a repo, driving the "Cancel all" and "Resume all"
// bulk buttons on the Scans tab.
func (s *Server) repoScanActionCounts(repoID uint) (active, paused int64) {
	s.DB.Model(&db.Scan{}).Where("repository_id = ? AND status IN ?",
		repoID, []db.ScanStatus{db.ScanRunning, db.ScanQueued}).Count(&active)
	s.DB.Model(&db.Scan{}).Where("repository_id = ? AND status = ?",
		repoID, db.ScanPaused).Count(&paused)
	return active, paused
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
	wb := loadWorkbench(s.DB, &repo, workbenchSeed(tmScan))

	var totalCost float64
	s.DB.Model(&db.Scan{}).Where("repository_id = ?", repo.ID).
		Select("COALESCE(SUM(cost_usd), 0)").Scan(&totalCost)

	category := r.URL.Query().Get("category")
	rf := loadRepoFindings(s.DB, repo.ID, category)

	// Count deep-dive findings still awaiting verification, scoped to the
	// same category filter as the visible list. Drives the "Verify all new"
	// button on the Findings tab; the bulk handler acts on this exact set.
	newFindingsQuery := s.DB.Model(&db.Finding{}).
		Where("repository_id = ? AND status = ? AND scan_id IN (?)",
			repo.ID, db.FindingNew, findingsScanIDs(s.DB))
	if category != "" {
		newFindingsQuery = applyCWECategoryFilter(newFindingsQuery, category)
	}
	var newFindings int64
	newFindingsQuery.Count(&newFindings)

	var maintainers []db.Maintainer
	s.DB.Joins("JOIN repository_maintainers ON repository_maintainers.maintainer_id = maintainers.id").
		Where("repository_maintainers.repository_id = ?", repo.ID).Find(&maintainers)

	// Apply the runtime-only filter in SQL before capping, so the first N
	// rows on the default tab are runtime deps, not whatever sorts first
	// by name. hiddenDeps and depsTotal both describe the same set the tab
	// is rendering.
	showAllDeps := r.URL.Query().Get("deps") == "all"
	hiddenTypes := []string{db.DependencyDev, db.DependencyTest, db.DependencyBuild}
	var hiddenDeps int64
	s.DB.Model(&db.Dependency{}).
		Where("repository_id = ? AND dependency_type IN ?", repo.ID, hiddenTypes).
		Count(&hiddenDeps)
	depQ := s.DB.Model(&db.Dependency{}).Where("repository_id = ?", repo.ID)
	if !showAllDeps {
		depQ = depQ.Where("dependency_type NOT IN ?", hiddenTypes)
	}
	var depsTotal int64
	depQ.Count(&depsTotal)
	var rawDeps []db.Dependency
	depQ.Order("ecosystem, name, manifest_kind desc").Limit(tabRowCap).Find(&rawDeps)
	deps := groupDeps(rawDeps)

	var depsCommit string
	if len(deps) > 0 {
		depsCommit = s.latestDepsCommit(repo.ID)
	}

	var pkgs []db.Package
	s.DB.Where("repository_id = ?", repo.ID).Order("dependent_repos desc, downloads desc").Find(&pkgs)

	var dependents []db.Dependent
	var dependentsTotal int64
	s.DB.Model(&db.Dependent{}).Where("repository_id = ?", repo.ID).Count(&dependentsTotal)
	s.DB.Where("repository_id = ?", repo.ID).Order("dependent_repos desc").
		Limit(tabRowCap).Find(&dependents)

	var advisories []db.Advisory
	var advisoriesTotal int64
	s.DB.Model(&db.Advisory{}).Where("repository_id = ?", repo.ID).Count(&advisoriesTotal)
	s.DB.Where("repository_id = ?", repo.ID).Order("cvss_score desc").
		Limit(tabRowCap).Find(&advisories)

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

	// activeScans drives both the delete-confirm warning (a running scan keeps
	// writing into the repo's clone/workspace until it returns) and the "Cancel
	// all" button; pausedScans drives "Resume all". Both are counted over every
	// scan, not the latest-per-skill set.
	activeScans, pausedScans := s.repoScanActionCounts(repo.ID)

	data := map[string]any{
		"Repo": repo, "Scans": scans, "Latest": latest,
		"Findings":             rf.DeepDive,
		"FindingsTotal":        rf.DeepDiveTotal,
		"ScannerFindings":      rf.Scanners,
		"ScannerFindingsTotal": rf.ScannersTotal,
		"ScanSkill":            rf.ScanSkill,
		"ScanCommit":           rf.ScanCommit,
		"NewFindingCount":      int(newFindings),
		"FailedScans":          failedScans,
		"ActiveScans":          int(activeScans),
		"PausedScans":          int(pausedScans),
		"TotalCost":            totalCost,
		// Cached on the row, refreshed by the worker after each scan (#126).
		"DiskBytes":  repo.DiskBytes,
		"TMCommit":   tmCommit,
		"DepsCommit": depsCommit,
		"Deps":       deps, "DepsTotal": depsTotal,
		"Pkgs":       pkgs,
		"Dependents": dependents, "DependentsTotal": dependentsTotal,
		"Advisories": advisories, "AdvisoriesTotal": advisoriesTotal,
		"Maintainers": maintainers, "ThreatModel": threatModel,
		"KnownURLs": knownURLs, "KnownPURLs": knownPURLs,
		"ShowAllDeps": showAllDeps, "HiddenDeps": hiddenDeps,
		"Skills":        activeSkills,
		"Subprojects":   subprojects,
		"SubScanCount":  subScanCount,
		"Workbench":     wb,
		"Category":      category,
		"Categories":    CWECategories(),
		"Uncategorized": UncategorizedCWE,
		"TabRowCap":     int64(tabRowCap),
	}
	s.render(w, r, "repo_show.html", data)
}

// latestDepsCommit returns the commit of the latest successful dependencies
// scan: the run that owns the current Dependency rows (parseDependenciesOutput
// replaces them wholesale per repo). git-pkgs runs at the clone root, so
// manifest paths are repo-root-relative and resolve through the blob route at
// this commit; the Manifests column links to the in-app code browser when it's
// set. Returns "" when no such commit is recorded.
func (s *Server) latestDepsCommit(repoID uint) string {
	var commits []string
	s.DB.Model(&db.Scan{}).
		Joins("JOIN skills ON skills.id = scans.skill_id").
		Where("scans.repository_id = ? AND skills.output_kind = ? AND scans.status = ? AND scans.`commit` <> ''",
			repoID, "dependencies", db.ScanDone).
		Order("scans.id DESC").
		Limit(1).
		Pluck("scans.commit", &commits)
	if len(commits) > 0 {
		return commits[0]
	}
	return ""
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

// repoScanAll is the bulk equivalent of the per-subproject "Scan" button: it
// enqueues the deep-dive skill for every detected subproject on the repo, so
// the operator doesn't have to click through the list one row at a time.
// Subprojects that already have a queued or running deep-dive scan are skipped,
// so re-clicking the button doesn't pile up duplicate jobs.
func (s *Server) repoScanAll(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", deepDiveSkillName, true).First(&skill).Error; err != nil {
		setFlash(w, Flash{Category: errorKey, Title: deepDiveSkillName + " skill is not installed"})
		s.redirect(w, r, fmt.Sprintf("/repositories/%d", repo.ID))
		return
	}

	var subprojects []db.Subproject
	s.DB.Where("repository_id = ?", repo.ID).Order("path").Find(&subprojects)

	model := r.FormValue("model")
	var queued, skipped, errored int
	for _, sub := range subprojects {
		var inflight int64
		s.DB.Model(&db.Scan{}).
			Where("repository_id = ? AND sub_path = ? AND skill_id = ? AND status IN ?",
				repo.ID, sub.Path, skill.ID, []db.ScanStatus{db.ScanQueued, db.ScanRunning}).
			Count(&inflight)
		if inflight > 0 {
			skipped++
			continue
		}
		if _, err := s.enqueueSkillWith(r.Context(), repo.ID, skill.ID, ScanOpts{
			Model:   model,
			SubPath: sub.Path,
		}); err != nil {
			errored++
			continue
		}
		queued++
	}
	setFlash(w, scanAllToast(queued, skipped, errored))
	// Land on the Scans tab so the operator can watch the jobs run.
	s.redirect(w, r, fmt.Sprintf("/repositories/%d#rt3", repo.ID))
}

func scanAllToast(queued, skipped, errored int) Flash {
	if queued == 0 && skipped == 0 && errored == 0 {
		return Flash{Category: successKey, Title: "No subprojects to scan"}
	}
	parts := []string{fmt.Sprintf("%d queued", queued)}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d already running", skipped))
	}
	if errored > 0 {
		parts = append(parts, fmt.Sprintf("%d errored", errored))
	}
	cat := successKey
	switch {
	case errored > 0:
		cat = errorKey
	case queued == 0:
		cat = warningKey
	}
	return Flash{Category: cat, Title: "Scan all: " + strings.Join(parts, ", ")}
}

// repoDelete removes a repository and every row that hangs off it, then
// drops its on-disk clone cache. Every linked table is deleted explicitly
// inside one transaction rather than leaning on ON DELETE CASCADE, which is
// unreliable here: sqlite's foreign_keys pragma is per-connection and set on
// only one pooled connection. The order matters because foreign_keys *is*
// enforced on the connection that ends up serving the delete in production:
//   - scans.finding_id -> findings.id is NO ACTION (verify/patch scans are
//     finding-scoped), so that link is nulled first or findings can't go.
//   - finding_labels_join.finding_id is also NO ACTION, so the join rows go
//     before the findings they reference.
//   - findings are deleted before scans (findings.scan_id is the cascade
//     direction; the reverse link was already nulled).
//
// Maintainers are shared across repos, so only the join rows go; matched SBOM
// packages belong to their upload, so their cross-reference is nulled rather
// than deleted. The filesystem removal runs after the commit so a failed
// transaction never strands a live repo row with its clone deleted.
func (s *Server) repoDelete(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}

	// Collected before the transaction deletes the scan rows: each scan's
	// per-scan workspace and claude session store under DataDir are reclaimed
	// after the commit.
	var scanIDs []uint
	s.DB.Model(&db.Scan{}).Where("repository_id = ?", repo.ID).Pluck("id", &scanIDs)

	err := s.DB.Transaction(func(tx *gorm.DB) error {
		// Match scans by the *finding's* repo, not the scan's own: a finding-
		// scoped scan can in principle live on a different repository_id than
		// the finding it points at, and any scan referencing a doomed finding
		// must have its NO ACTION link cleared or the finding delete 787s. The
		// subquery also avoids materialising a (possibly >999) id list.
		const findingsOfRepo = "finding_id IN (SELECT id FROM findings WHERE repository_id = ?)"
		if err := tx.Model(&db.Scan{}).Where(findingsOfRepo, repo.ID).
			Update("finding_id", nil).Error; err != nil {
			return err
		}
		// Finding children. notes/comms/refs/history cascade from a finding
		// delete, but are removed here too so the cleanup stays correct even
		// when foreign_keys happens to be off on the serving connection.
		if err := tx.Exec("DELETE FROM finding_labels_join WHERE "+findingsOfRepo, repo.ID).Error; err != nil {
			return err
		}
		for _, child := range []any{
			&db.FindingNote{}, &db.FindingCommunication{}, &db.FindingReference{},
			&db.FindingHistory{}, &db.FindingDependent{},
		} {
			if err := tx.Where(findingsOfRepo, repo.ID).Delete(child).Error; err != nil {
				return err
			}
		}
		for _, child := range []any{
			&db.Finding{}, &db.Scan{}, &db.Subproject{}, &db.Dependency{},
			&db.Dependent{}, &db.Package{}, &db.Advisory{},
		} {
			if err := tx.Where("repository_id = ?", repo.ID).Delete(child).Error; err != nil {
				return err
			}
		}
		if err := tx.Model(&db.SBOMPackage{}).Where("repository_id = ?", repo.ID).
			Update("repository_id", nil).Error; err != nil {
			return err
		}
		if err := tx.Exec("DELETE FROM repository_maintainers WHERE repository_id = ?", repo.ID).Error; err != nil {
			return err
		}
		return tx.Delete(&repo).Error
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := os.RemoveAll(worker.RepoCacheRoot(s.Worker.DataDir, repo.URL)); err != nil {
		s.Log.Error("repoDelete: remove clone cache", "repo", repo.ID, "err", err)
	}
	for _, id := range scanIDs {
		if err := s.Worker.RemoveScanArtifacts(id); err != nil {
			s.Log.Error("repoDelete: remove scan workspace", "scan", id, "err", err)
		}
	}

	setFlash(w, Flash{Category: "success", Title: "Repository deleted",
		Description: repo.Name + " and all its scans, findings and cached clone were removed."})
	s.redirect(w, r, "/")
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
	Effort      string
	FindingID   *uint
	DependentID *uint
	// BaselineScanID marks a fix-validation anchor scan and pins the baseline
	// scan it diffs against. See validate_fix.go.
	BaselineScanID *uint
	SubPath        string
	Ref            string
	Profile        string
	// SessionID and ResumedFromScanID carry a failed scan's claude session
	// into its retry so the new run continues the conversation with
	// `claude -p --resume` instead of restarting from turn 0. Both empty
	// on a normal (non-resuming) enqueue. See scanRetry.
	SessionID         string
	ResumedFromScanID *uint
	// ImportPayload is the raw uploaded report for an ingest-skill run
	// created by the /v1/import fallback; the worker stages it into the
	// workspace at import/report. Empty for every other enqueue.
	ImportPayload []byte
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
// the skill's preferred Model > the high tier. Concrete model IDs win as-is;
// tier names resolve through Settings. Effort precedence is:
// explicit opts.Effort > the runtime default effort.
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
	if err := worker.ValidateGitRef(opts.Ref); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidRef, err)
	}
	if !ValidModelPreference(opts.Model) && hasSkill {
		opts.Model = sk.Model
	}
	opts.Model = resolveModelPreference(s.DB, opts.Model, s.DefaultModel())
	if !ValidEffort(opts.Effort) {
		opts.Effort = s.DefaultEffort()
	}
	kind := worker.JobSkill
	if opts.DependentID != nil {
		kind = worker.JobExposure
	}
	scan := db.Scan{
		RepositoryID:      repoID,
		Kind:              kind,
		Status:            db.ScanQueued,
		StatusPriority:    db.StatusPriorityFor(db.ScanQueued),
		Model:             opts.Model,
		Effort:            opts.Effort,
		SkillID:           &skillID,
		SkillName:         sk.Name,
		FindingID:         opts.FindingID,
		DependentID:       opts.DependentID,
		BaselineScanID:    opts.BaselineScanID,
		SubPath:           opts.SubPath,
		Ref:               opts.Ref,
		Profile:           opts.Profile,
		SessionID:         opts.SessionID,
		ResumedFromScanID: opts.ResumedFromScanID,
		ImportPayload:     opts.ImportPayload,
		SkillsRepoSHA:     s.SkillsRepoSHA,
		APIToken:          NewAPIToken(),
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
		if preferDependencyForGroup(d, g.Dependency) {
			g.Dependency = d
		}
	}
	out := make([]DepGroup, 0, len(order))
	for _, k := range order {
		out = append(out, *m[k])
	}
	return out
}

func preferDependencyForGroup(a, b db.Dependency) bool {
	aRuntime, bRuntime := db.DependencyVisibleByDefault(a.DependencyType), db.DependencyVisibleByDefault(b.DependencyType)
	if aRuntime != bRuntime {
		return aRuntime
	}
	return a.ManifestKind == "lockfile" && b.ManifestKind != "lockfile"
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
