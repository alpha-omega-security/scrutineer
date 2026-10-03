package akrites

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime"
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
	// MaxBodySize is intake's request body limit; MaxPayloadSize bounds exploit and raw each.
	MaxBodySize        = 3 << 20
	MaxPayloadSize     = 1 << 20
	maxResponseSize    = 64 << 10
	requestTimeout     = 30 * time.Second
	maxVersions        = 64
	maxShownViolations = 10
)

// Intake problem types; any other problem type is about:blank.
const (
	problemMalformed  = "tag:akrites.dev,2026-07:problem/malformed-json"
	problemValidation = "tag:akrites.dev,2026-07:problem/validation"
)

var contentTypes = []string{
	"text/plain", "text/markdown", "application/json", "application/pdf",
	"application/zip", "application/gzip", "application/x-bzip2", "application/octet-stream",
}

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
	if c.AuthHeader != "" && c.AuthHeader != "Authorization" && c.AuthHeader != "TAP-SUBMISSION-TOKEN" {
		return "", fmt.Errorf("akrites auth_header must be Authorization or TAP-SUBMISSION-TOKEN")
	}
	u.Path = "/v1/reports"
	return u.String(), nil
}

type Report struct {
	PURL               string   `json:"purl,omitempty"`
	Software           string   `json:"software"`
	Ecosystem          string   `json:"ecosystem,omitempty"`
	Versions           []string `json:"versions,omitempty"`
	CodePath           string   `json:"code_path,omitempty"`
	Exploit            string   `json:"exploit,omitempty"`
	ExploitContentType string   `json:"exploit_content_type,omitempty"`
	Raw                string   `json:"raw,omitempty"`
	RawContentType     string   `json:"raw_content_type,omitempty"`
	PackageRepoURL     string   `json:"package_repo_url,omitempty"`
	DiscoveryMethod    string   `json:"discovery_method,omitempty"`
	Email              string   `json:"email,omitempty"`
	Notify             string   `json:"notify,omitempty"`
}

func (r Report) JSON() ([]byte, error) {
	if strings.TrimSpace(r.Software) == "" {
		return nil, fmt.Errorf("software is required")
	}
	var purlVersion string
	if r.PURL != "" {
		p, err := purl.Parse(r.PURL)
		if err != nil {
			return nil, fmt.Errorf("purl must be a valid package URL")
		}
		purlVersion = p.Version
	} else if r.Ecosystem == "" {
		return nil, fmt.Errorf("a package URL or an ecosystem is required")
	}
	fields := []struct {
		name, value string
		limit       int
		multiline   bool
	}{
		{"purl", r.PURL, 512, false}, {"software", r.Software, 256, false},
		{"ecosystem", r.Ecosystem, 128, false}, {"code_path", r.CodePath, 1024, false},
		{"exploit", r.Exploit, MaxPayloadSize, true}, {"raw", r.Raw, MaxPayloadSize, true},
		{"package_repo_url", r.PackageRepoURL, 512, false},
		{"discovery_method", r.DiscoveryMethod, 32, false}, {"email", r.Email, 256, false},
	}
	for _, f := range fields {
		if !utf8.ValidString(f.value) || len(f.value) > f.limit || strings.ContainsFunc(f.value, func(c rune) bool {
			return unicode.IsControl(c) && (!f.multiline || (c != '\n' && c != '\r' && c != '\t'))
		}) {
			return nil, fmt.Errorf("%s contains invalid characters or exceeds %d bytes", f.name, f.limit)
		}
	}
	if err := r.checkPayloads(); err != nil {
		return nil, err
	}
	if err := r.checkVersions(purlVersion); err != nil {
		return nil, err
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
	if r.Email == "" && r.Notify != "" && r.Notify != "off" {
		return nil, fmt.Errorf("an email address is required for email notifications")
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	// HTML escaping would grow each <, > and & in the report to six bytes.
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(r); err != nil {
		return nil, err
	}
	if body.Len() > MaxBodySize {
		return nil, fmt.Errorf("encoded report exceeds 3 MiB")
	}
	return body.Bytes(), nil
}

func (r Report) checkPayloads() error {
	for _, p := range []struct{ name, payload, contentType string }{
		{"exploit", r.Exploit, r.ExploitContentType}, {"raw", r.Raw, r.RawContentType},
	} {
		if (p.payload == "") != (p.contentType == "") {
			return fmt.Errorf("%s and %s_content_type must be sent together", p.name, p.name)
		}
		if p.contentType != "" && !slices.Contains(contentTypes, p.contentType) {
			return fmt.Errorf("invalid %s_content_type", p.name)
		}
	}
	return nil
}

// checkVersions counts as intake does: after adding the package URL's version
// and dropping duplicates.
func (r Report) checkVersions(purlVersion string) error {
	versions := map[string]bool{}
	for _, v := range r.Versions {
		if len(v) > 64 || !utf8.ValidString(v) || strings.ContainsFunc(v, unicode.IsControl) {
			return fmt.Errorf("versions must be at most 64 bytes each without control characters")
		}
		if v = strings.TrimSpace(v); v != "" {
			versions[v] = true
		}
	}
	if purlVersion != "" {
		versions[purlVersion] = true
	}
	if len(versions) > maxVersions {
		return fmt.Errorf("versions must have at most 64 entries, including the package URL version")
	}
	return nil
}

type ResponseError struct {
	StatusCode int
	Ambiguous  bool
	RetryAfter time.Duration
	// Problem and Violations keep only the machine-readable parts of an intake
	// problem document, so no response text reaches the page or the database.
	Problem    string
	Violations []Violation
}

type Violation struct {
	Code      string `json:"code"`
	Field     string `json:"field"`
	AlsoField string `json:"also_field"`
}

func (e *ResponseError) Error() string {
	switch {
	case e.Ambiguous:
		return "Akrites may have accepted the report; reconcile with Akrites before submitting again"
	case e.Problem == problemMalformed:
		return "Akrites could not parse the report (HTTP 400); Scrutineer does not match the intake API, so update Scrutineer before submitting again"
	case len(e.Violations) > 0:
		return fmt.Sprintf("Akrites rejected the report (HTTP %d): %s", e.StatusCode, e.violationSummary())
	case e.StatusCode == http.StatusBadRequest:
		return "Akrites rejected the report (HTTP 400)"
	case e.StatusCode == http.StatusUnauthorized:
		return "Akrites did not accept the configured submission token (HTTP 401); it may be missing, expired or revoked, so ask Akrites for a new one"
	case e.StatusCode == http.StatusForbidden:
		return "the Akrites web firewall blocked the request (HTTP 403)"
	case e.StatusCode == 0:
		return "could not read Akrites submission status"
	}
	return fmt.Sprintf("Akrites returned HTTP %d", e.StatusCode)
}

func (e *ResponseError) violationSummary() string {
	shown := e.Violations[:min(len(e.Violations), maxShownViolations)]
	parts := make([]string, 0, len(shown)+1)
	for _, v := range shown {
		field := v.Field
		if v.AlsoField != "" {
			field += " and " + v.AlsoField
		}
		parts = append(parts, field+" ("+v.Code+")")
	}
	if more := len(e.Violations) - len(shown); more > 0 {
		parts = append(parts, fmt.Sprintf("%d more", more))
	}
	return strings.Join(parts, ", ")
}

var (
	problemCodeRE  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	problemFieldRE = regexp.MustCompile(`^[a-z][a-z0-9_.\[\]]{0,127}$`)
)

// readProblem drops each violation's reason: intake writes it as prose, and
// the code and field are enough to correct the report.
func readProblem(resp *http.Response) (string, []Violation) {
	if mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mediaType != "application/problem+json" {
		return "", nil
	}
	var doc struct {
		Type   string      `json:"type"`
		Errors []Violation `json:"errors"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&doc) != nil || (doc.Type != problemMalformed && doc.Type != problemValidation) {
		return "", nil
	}
	var violations []Violation
	for _, v := range doc.Errors {
		if problemCodeRE.MatchString(v.Code) && problemFieldRE.MatchString(v.Field) && (v.AlsoField == "" || problemFieldRE.MatchString(v.AlsoField)) {
			violations = append(violations, v)
		}
	}
	return doc.Type, violations
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
			header = "Authorization"
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
		responseErr := &ResponseError{StatusCode: resp.StatusCode, Ambiguous: method == http.MethodPost && (resp.StatusCode < http.StatusBadRequest || (resp.StatusCode >= http.StatusInternalServerError && resp.StatusCode != http.StatusServiceUnavailable)), RetryAfter: delay}
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusRequestEntityTooLarge {
			responseErr.Problem, responseErr.Violations = readProblem(resp)
		}
		return nil, responseErr
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil || len(raw) > maxResponseSize {
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
