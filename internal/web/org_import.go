package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// OrgRepo is the slim view of a forge repository the org-import path needs:
// enough to build a clone URL and apply the fork/archived filters.
type OrgRepo struct {
	FullName  string `json:"full_name"`
	CloneURL  string `json:"clone_url"`
	Fork      bool   `json:"fork"`
	Archived  bool   `json:"archived"`
	MirrorURL string `json:"mirror_url"`
}

// githubAPI is the API base. It is a var, not a const, so tests can point the
// fetcher at an httptest.Server.
var githubAPI = "https://api.github.com"

const (
	orgImportUA     = "scrutineer (andrew@ecosyste.ms)"
	orgFetchTimeout = 60 * time.Second
	orgPerPage      = 100
	// orgMaxPages caps pagination so a pathological response (or a forge
	// that never shrinks the page) cannot loop forever. 100 pages * 100
	// per page covers orgs up to 10k repos.
	orgMaxPages = 100
)

// fetchGitHubOrgRepos lists every repository owned by a GitHub org, paging to
// completion. It falls back to the /users endpoint when the login is a user
// account rather than an org (GitHub returns 404 on /orgs for users). An
// optional GITHUB_TOKEN in the environment raises the rate limit from 60 to
// 5000 requests/hour but is not required for public orgs.
func fetchGitHubOrgRepos(ctx context.Context, org string) ([]OrgRepo, error) {
	org = strings.TrimSpace(org)
	if org == "" {
		return nil, fmt.Errorf("organization name is required")
	}
	if strings.ContainsAny(org, "/ \t") {
		return nil, fmt.Errorf("invalid organization name %q", org)
	}

	ctx, cancel := context.WithTimeout(ctx, orgFetchTimeout)
	defer cancel()

	repos, err := fetchGitHubRepos(ctx, "orgs", org)
	if notFound(err) {
		// Not an org — try it as a user account before giving up.
		repos, err = fetchGitHubRepos(ctx, "users", org)
	}
	if notFound(err) {
		return nil, fmt.Errorf("no GitHub organization or user named %q", org)
	}
	return repos, err
}

// errNotFound flags a 404 from GitHub so the caller can retry the /users path.
type errNotFound struct{ owner string }

func (e errNotFound) Error() string { return "GitHub returned 404 for " + e.owner }

func notFound(err error) bool {
	_, ok := err.(errNotFound)
	return ok
}

// fetchGitHubRepos pages through /{kind}/{owner}/repos and returns every repo.
func fetchGitHubRepos(ctx context.Context, kind, owner string) ([]OrgRepo, error) {
	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	var all []OrgRepo
	for page := 1; page <= orgMaxPages; page++ {
		// No type filter: GitHub defaults to "all" for /orgs (every repo the
		// caller can see) and "owner" for /users (repos the user owns, not ones
		// they merely collaborate on), which is what we want on each path.
		q := url.Values{
			"per_page": {fmt.Sprint(orgPerPage)},
			"page":     {fmt.Sprint(page)},
		}
		endpoint := fmt.Sprintf("%s/%s/%s/repos?%s", githubAPI, kind, url.PathEscape(owner), q.Encode())

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", orgImportUA)
		req.Header.Set("Accept", "application/vnd.github+json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxOrgResponseBody))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		switch resp.StatusCode {
		case http.StatusOK:
		case http.StatusNotFound:
			return nil, errNotFound{owner: owner}
		case http.StatusForbidden, http.StatusTooManyRequests:
			// Almost always the unauthenticated 60/hour rate limit.
			return nil, fmt.Errorf("GitHub rate limit hit fetching %s/%s (set GITHUB_TOKEN to raise it)", kind, owner)
		default:
			return nil, fmt.Errorf("GitHub API returned %d for %s/%s", resp.StatusCode, kind, owner)
		}

		var batch []OrgRepo
		if err := json.Unmarshal(body, &batch); err != nil {
			return nil, fmt.Errorf("decode GitHub repos: %w", err)
		}
		all = append(all, batch...)
		// A short page is the last page.
		if len(batch) < orgPerPage {
			break
		}
	}
	return all, nil
}

// maxOrgResponseBody caps a single GitHub repos page. 100 repos of JSON is
// well under this; the limit just guards against a hostile response.
const maxOrgResponseBody = 25 * 1024 * 1024

// OrgImportPreview carries the confirmation-step data: how many repos a given
// org/filters combination would queue, plus the inputs needed to re-submit the
// import once the operator confirms.
type OrgImportPreview struct {
	Org             string
	Count           int // repos that pass the fork/archived filters
	Filtered        int // repos held back by the filters
	IncludeForks    bool
	IncludeArchived bool
}

// repoOrgImport fetches every repository in a GitHub org and queues each one
// for scanning, reusing the single-repo createOrTriageRepo path so dedup and
// default-skill enqueue behave exactly like a manual add. Forks and archived
// repos are skipped unless the corresponding toggle is set.
//
// The first submission previews the count ("this will add N repos") and asks
// the operator to confirm before queueing potentially hundreds of repos. The
// confirm step re-posts with confirm=1; because the import is synchronous and
// keeps no state between requests, that step re-fetches the org listing.
//
// Imports run synchronously within the request, like the bulk-paste path, so a
// very large org (thousands of repos) makes for a slow request; the per-repo
// work is a cheap insert plus a queue enqueue, not the scan itself.
func (s *Server) repoOrgImport(w http.ResponseWriter, r *http.Request) {
	org := strings.TrimSpace(r.FormValue("org"))
	org = strings.TrimPrefix(org, "@")
	if org == "" {
		s.repoFormError(w, r, "org-import-alert-oob", "Import organization", fmt.Errorf("enter a GitHub organization name"), http.StatusUnprocessableEntity)
		return
	}
	includeForks := r.FormValue("include_forks") != ""
	includeArchived := r.FormValue("include_archived") != ""

	repos, err := s.fetchOrgRepos(r.Context(), org)
	if err != nil {
		s.repoFormError(w, r, "org-import-alert-oob", "Couldn't import organization", err, http.StatusBadGateway)
		return
	}

	// Apply the fork/archived filters once so the preview count and the import
	// operate on the same candidate set.
	var toImport []OrgRepo
	var filtered int
	for _, repo := range repos {
		if repo.Fork && !includeForks {
			filtered++
			continue
		}
		if repo.Archived && !includeArchived {
			filtered++
			continue
		}
		// Mirrors track an upstream and are never worth scanning on their own;
		// skip them unconditionally (no opt-in toggle).
		if repo.MirrorURL != "" {
			filtered++
			continue
		}
		toImport = append(toImport, repo)
	}

	if r.FormValue("confirm") == "" {
		s.orgImportConfirm(w, r, OrgImportPreview{
			Org:             org,
			Count:           len(toImport),
			Filtered:        filtered,
			IncludeForks:    includeForks,
			IncludeArchived: includeArchived,
		})
		return
	}

	var created, skipped int
	var invalid []string
	// landingOwner is the canonical owner slug as ParseRepoInput normalizes it
	// (e.g. github.com lower-cases it). The org page matches Owner exactly, so
	// redirecting to the user-typed casing could 404; use the stored casing.
	landingOwner := org
	for _, repo := range toImport {
		input, err := ParseRepoInput(repo.CloneURL)
		if err != nil {
			invalid = append(invalid, repo.FullName)
			continue
		}
		if input.Owner != "" {
			landingOwner = input.Owner
		}
		_, isNew, err := s.createOrTriageRepo(r.Context(), input, r.FormValue("model"))
		if err != nil {
			invalid = append(invalid, repo.FullName)
			continue
		}
		if isNew {
			created++
		} else {
			skipped++
		}
	}

	setFlash(w, Flash{
		Category:    bulkToastCategory(created, invalid),
		Title:       orgImportToastTitle(org, created, skipped, filtered, len(invalid)),
		Description: bulkToastDescription(invalid),
	})
	// Land on the org page when something was imported; otherwise (all
	// filtered/invalid, nothing stored) that page would 404, so go home.
	if created+skipped > 0 {
		s.redirect(w, r, "/orgs/"+url.PathEscape(landingOwner))
	} else {
		s.redirect(w, r, "/")
	}
}

// orgImportConfirm renders the "this will add N repos" confirmation step.
// htmx clients get an OOB swap that replaces the dialog's input form with a
// confirmation panel; plain form posts fall back to the no-JS confirm page.
func (s *Server) orgImportConfirm(w http.ResponseWriter, r *http.Request, p OrgImportPreview) {
	if !isHX(r) {
		s.render(w, r, "repo_new.html", map[string]any{"OrgConfirm": p})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "org-import-confirm-oob", p); err != nil {
		s.Log.Error("render org-import-confirm-oob", "err", err)
	}
}

// orgImportToastTitle summarizes an org import the same way the bulk paste
// path does, plus a count of repos held back by the fork/archived filters.
func orgImportToastTitle(org string, created, skipped, filtered, invalid int) string {
	parts := []string{fmt.Sprintf("%s: %d added", org, created)}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d already present", skipped))
	}
	if filtered > 0 {
		parts = append(parts, fmt.Sprintf("%d forks/archived/mirrors skipped", filtered))
	}
	if invalid > 0 {
		parts = append(parts, fmt.Sprintf("%d invalid", invalid))
	}
	return strings.Join(parts, ", ")
}
