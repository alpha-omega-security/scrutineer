// Package metadata holds the small residual HTTP helper the web tier uses
// to resolve a dependency PURL back to a repository URL. The rest of the
// ecosyste.ms fetching logic now lives inside skills.
package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

var packagesLookup = "https://packages.ecosyste.ms/api/v1/packages/lookup"

const (
	userAgent       = "scrutineer (andrew@ecosyste.ms)"
	httpTimeout     = 30 * time.Second
	maxResponseBody = 10 * 1024 * 1024 // 10 MB cap on API responses (T7)
)

// FetchPackagesByPURL resolves a dep's PURL to its upstream package records
// via packages.ecosyste.ms. Used by the web handler's "import dependency"
// button to find a repository URL to scan next.
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
