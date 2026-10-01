package akrites

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/git-pkgs/purl"
)

const (
	DefaultBaseURL = "https://intake.tap.akrites.dev"
	MaxBodySize    = 1 << 20
	requestTimeout = 30 * time.Second
	maxVersions    = 64
)

type Config struct {
	BaseURL         string `yaml:"base_url"`
	SubmissionToken string `yaml:"submission_token"`
	AuthHeader      string `yaml:"auth_header"`
	Email           string `yaml:"email"`
}

func (c Config) Enabled() bool { return strings.TrimSpace(c.SubmissionToken) != "" }

func (c Config) Endpoint() (string, error) {
	base := strings.TrimSpace(c.BaseURL)
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("akrites base_url must be an HTTPS origin without credentials, path, query or fragment")
	}
	if c.AuthHeader != "" && c.AuthHeader != "TAP-SUBMISSION-TOKEN" && c.AuthHeader != "Authorization" {
		return "", fmt.Errorf("akrites auth_header must be TAP-SUBMISSION-TOKEN or Authorization")
	}
	u.Path = "/v1/reports"
	return u.String(), nil
}

type Report struct {
	PURL            string   `json:"purl,omitempty"`
	Software        string   `json:"software"`
	Ecosystem       string   `json:"ecosystem,omitempty"`
	Versions        []string `json:"versions,omitempty"`
	CodePath        string   `json:"code_path,omitempty"`
	Exploit         string   `json:"exploit,omitempty"`
	RawFormat       string   `json:"raw_format,omitempty"`
	Raw             string   `json:"raw,omitempty"`
	PackageRepoURL  string   `json:"package_repo_url,omitempty"`
	DiscoveryMethod string   `json:"discovery_method,omitempty"`
	Email           string   `json:"email,omitempty"`
	Notify          string   `json:"notify,omitempty"`
}

func (r Report) JSON() ([]byte, error) {
	if strings.TrimSpace(r.Software) == "" {
		return nil, fmt.Errorf("software is required")
	}
	if r.PURL == "" {
		if !slices.Contains([]string{"Linux", "OSS-Fuzz", "Android", "GitHub Actions", "Hardware"}, r.Ecosystem) {
			return nil, fmt.Errorf("purl is required for this ecosystem")
		}
	} else if _, err := purl.Parse(r.PURL); err != nil {
		return nil, fmt.Errorf("purl must be a valid package URL")
	}
	fields := []struct {
		name, value string
		limit       int
		multiline   bool
	}{
		{"purl", r.PURL, 512, false}, {"software", r.Software, 256, false},
		{"ecosystem", r.Ecosystem, 128, false}, {"code_path", r.CodePath, 1024, false},
		{"exploit", r.Exploit, MaxBodySize, true}, {"raw", r.Raw, MaxBodySize, true},
		{"raw_format", r.RawFormat, 32, false}, {"package_repo_url", r.PackageRepoURL, 512, false},
		{"discovery_method", r.DiscoveryMethod, 32, false}, {"email", r.Email, 256, false},
	}
	for _, f := range fields {
		if !utf8.ValidString(f.value) || len(f.value) > f.limit || strings.ContainsFunc(f.value, func(c rune) bool {
			return unicode.IsControl(c) && (!f.multiline || (c != '\n' && c != '\r' && c != '\t'))
		}) {
			return nil, fmt.Errorf("%s contains invalid characters or exceeds %d bytes", f.name, f.limit)
		}
	}
	if len(r.Versions) > maxVersions {
		return nil, fmt.Errorf("versions must have at most 64 entries")
	}
	for _, v := range r.Versions {
		if len(v) > 64 || !utf8.ValidString(v) || strings.ContainsFunc(v, unicode.IsControl) {
			return nil, fmt.Errorf("versions must be at most 64 bytes each without control characters")
		}
	}
	if r.PackageRepoURL != "" {
		u, err := url.Parse(r.PackageRepoURL)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
			return nil, fmt.Errorf("package_repo_url must be an HTTP or HTTPS URL without credentials")
		}
	}
	if !slices.Contains([]string{"", "manual", "ai-assisted", "ai-discovered", "hybrid", "automated-scan", "upstream-report", "other"}, r.DiscoveryMethod) {
		return nil, fmt.Errorf("invalid discovery_method")
	}
	if !slices.Contains([]string{"", "off", "final", "milestones", "all"}, r.Notify) {
		return nil, fmt.Errorf("invalid notify choice")
	}
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxBodySize {
		return nil, fmt.Errorf("encoded report exceeds 1 MiB")
	}
	return body, nil
}

type ResponseError struct {
	StatusCode int
	Ambiguous  bool
	RetryAfter time.Duration
}

func (e *ResponseError) Error() string {
	if e.Ambiguous {
		return "Akrites may have accepted the report; reconcile with Akrites before submitting again"
	}
	if e.StatusCode == http.StatusBadRequest {
		return "Akrites rejected the report (HTTP 400); check the fields, including whether software and ecosystem match the package URL"
	}
	if e.StatusCode == http.StatusForbidden {
		return "Akrites rejected the configured submission token or blocked the request (HTTP 403)"
	}
	if e.StatusCode == 0 {
		return "could not read Akrites submission status"
	}
	return fmt.Sprintf("Akrites returned HTTP %d", e.StatusCode)
}

type Status struct {
	Receipt string    `json:"receipt"`
	Status  string    `json:"status"`
	At      time.Time `json:"at"`
}

var receiptRE = regexp.MustCompile(`^SUB-[A-Za-z0-9_-]{1,128}$`)

func (c Config) StatusURL(receipt string) (string, error) {
	if !receiptRE.MatchString(receipt) {
		return "", fmt.Errorf("invalid Akrites receipt")
	}
	endpoint, err := c.Endpoint()
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(endpoint, "/reports") + "/submissions/" + receipt, nil
}

type Client struct {
	Config     Config
	HTTPClient *http.Client
}

func (c Client) Submit(ctx context.Context, report Report) (string, error) {
	if !c.Config.Enabled() {
		return "", fmt.Errorf("akrites submission token is not configured")
	}
	body, err := report.JSON()
	if err != nil {
		return "", err
	}
	endpoint, err := c.Config.Endpoint()
	if err != nil {
		return "", err
	}
	raw, err := c.request(ctx, http.MethodPost, endpoint, body, http.StatusAccepted)
	if err != nil {
		return "", err
	}
	var result struct {
		Receipt string `json:"receipt"`
	}
	if json.Unmarshal(raw, &result) != nil || !receiptRE.MatchString(result.Receipt) {
		return "", &ResponseError{StatusCode: http.StatusAccepted, Ambiguous: true}
	}
	return result.Receipt, nil
}

func (c Client) Poll(ctx context.Context, receipt string) (Status, error) {
	endpoint, err := c.Config.StatusURL(receipt)
	if err != nil {
		return Status{}, err
	}
	raw, err := c.request(ctx, http.MethodGet, endpoint, nil, http.StatusOK)
	if err != nil {
		return Status{}, err
	}
	var result Status
	if json.Unmarshal(raw, &result) != nil || result.Receipt != receipt || result.At.IsZero() || !slices.Contains([]string{"queued", "processing", "done"}, result.Status) {
		return Status{}, fmt.Errorf("akrites returned an invalid status response")
	}
	return result, nil
}

func (c Client) request(ctx context.Context, method, endpoint string, body []byte, want int) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		header, token := c.Config.AuthHeader, strings.TrimSpace(c.Config.SubmissionToken)
		if header == "" {
			header = "TAP-SUBMISSION-TOKEN"
		}
		if header == "Authorization" {
			token = "Bearer " + token
		}
		req.Header.Set(header, token)
	}
	client := &http.Client{Timeout: requestTimeout}
	if c.HTTPClient != nil {
		*client = *c.HTTPClient
	}
	if client.Timeout == 0 {
		client.Timeout = requestTimeout
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if custom, ok := client.Transport.(*http.Transport); ok {
		transport = custom.Clone()
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.MinVersion = max(transport.TLSClientConfig.MinVersion, tls.VersionTLS12)
	transport.TLSClientConfig.InsecureSkipVerify = false
	client.Transport = transport
	defer transport.CloseIdleConnections()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, &ResponseError{Ambiguous: method == http.MethodPost}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != want {
		delay := retryAfter(resp.Header.Get("Retry-After"))
		if resp.StatusCode == http.StatusTooManyRequests {
			delay = max(delay, time.Hour)
		}
		return nil, &ResponseError{StatusCode: resp.StatusCode, Ambiguous: method == http.MethodPost && (resp.StatusCode < http.StatusBadRequest || (resp.StatusCode >= http.StatusInternalServerError && resp.StatusCode != http.StatusServiceUnavailable)), RetryAfter: delay}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodySize+1))
	if err != nil || len(raw) > MaxBodySize {
		return nil, &ResponseError{StatusCode: resp.StatusCode, Ambiguous: method == http.MethodPost}
	}
	return raw, nil
}

func retryAfter(value string) time.Duration {
	if seconds, err := strconv.ParseUint(value, 10, 32); err == nil {
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil {
		return max(0, time.Until(at))
	}
	return 0
}
