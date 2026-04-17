package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"scrutineer/internal/db"
)

var ecosystemsLookup = "https://repos.ecosyste.ms/api/v1/repositories/lookup"

const (
	userAgent       = "scrutineer (andrew@ecosyste.ms)"
	httpTimeout     = 30 * time.Second
	maxResponseBody = 10 * 1024 * 1024 // 10 MB cap on API responses (T7)
)

// ecoRepo is the subset of the ecosyste.ms repository lookup response we
// promote to Repository columns. The full payload is also stored verbatim in
// Repository.Metadata.
type ecoRepo struct {
	FullName      string     `json:"full_name"`
	Owner         string     `json:"owner"`
	Description   string     `json:"description"`
	DefaultBranch string     `json:"default_branch"`
	Language      string     `json:"language"`
	Stars         int        `json:"stargazers_count"`
	Forks         int        `json:"forks_count"`
	Archived      bool       `json:"archived"`
	License       string     `json:"license"`
	PushedAt      *time.Time `json:"pushed_at"`
	HTMLURL       string     `json:"html_url"`
	IconURL       string     `json:"icon_url"`
}

func fetchEcosystems(ctx context.Context, repoURL string, emit func(Event)) (ecoRepo, []byte, error) {
	q := url.Values{"url": {repoURL}}
	endpoint := ecosystemsLookup + "?" + q.Encode()
	emit(Event{Kind: KindText, Text: "GET " + endpoint})

	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ecoRepo{}, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ecoRepo{}, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return ecoRepo{}, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return ecoRepo{}, body, fmt.Errorf("ecosyste.ms returned %d", resp.StatusCode)
	}

	var er ecoRepo
	if err := json.Unmarshal(body, &er); err != nil {
		return ecoRepo{}, body, fmt.Errorf("decode: %w", err)
	}
	return er, body, nil
}

var packagesLookup = "https://packages.ecosyste.ms/api/v1/packages/lookup"

func fetchPackages(ctx context.Context, repoURL string, emit func(Event)) ([]json.RawMessage, []byte, error) {
	q := url.Values{"repository_url": {repoURL}}
	endpoint := packagesLookup + "?" + q.Encode()
	emit(Event{Kind: KindText, Text: "GET " + endpoint})

	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, body, fmt.Errorf("packages.ecosyste.ms returned %d", resp.StatusCode)
	}

	var pkgs []json.RawMessage
	if err := json.Unmarshal(body, &pkgs); err != nil {
		return nil, body, fmt.Errorf("decode: %w", err)
	}
	return pkgs, body, nil
}

// fetchPackagesByPURL is used by the web handler to resolve a dep's PURL to a
// repository URL. Exported via the function in web/server.go.
func FetchPackagesByPURL(ctx context.Context, purl string) ([]json.RawMessage, []byte, error) {
	q := url.Values{"purl": {purl}}
	endpoint := packagesLookup + "?" + q.Encode()

	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, body, fmt.Errorf("packages.ecosyste.ms returned %d", resp.StatusCode)
	}

	var pkgs []json.RawMessage
	if err := json.Unmarshal(body, &pkgs); err != nil {
		return nil, body, fmt.Errorf("decode: %w", err)
	}
	return pkgs, body, nil
}

// fetchJSON does a GET with the standard user agent and returns the body.
func fetchJSON(ctx context.Context, endpoint string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return body, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return body, nil
}

// fetchJSONFollow is like fetchJSON but follows redirects (issues.ecosyste.ms
// returns 302 for lookups).
func fetchJSONFollow(ctx context.Context, endpoint string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	// http.DefaultClient follows redirects by default
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return body, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return body, nil
}

func safeURL(u string) string {
	if strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://") {
		return u
	}
	return ""
}

func (w *Worker) applyMetadata(repo *db.Repository, er ecoRepo, raw []byte) {
	now := time.Now()
	repo.FullName = er.FullName
	repo.Owner = er.Owner
	repo.Description = er.Description
	repo.DefaultBranch = er.DefaultBranch
	repo.Languages = er.Language
	repo.License = er.License
	repo.Stars = er.Stars
	repo.Forks = er.Forks
	repo.Archived = er.Archived
	repo.PushedAt = er.PushedAt
	repo.HTMLURL = safeURL(er.HTMLURL)
	repo.IconURL = safeURL(er.IconURL)
	repo.Metadata = string(raw)
	repo.FetchedAt = &now
	w.DB.Save(repo)
}
