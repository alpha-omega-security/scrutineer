package akrites

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
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
	// MaxBodySize is intake's request body limit; MaxPayloadSize bounds each attachment's data.
	MaxBodySize        = 3 << 20
	MaxPayloadSize     = 1 << 20
	maxAttachments     = 16
	maxFilename        = 255
	maxDescription     = 1024
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

// contentTypes maps each accepted content type to the extension intake adds
// to an attachment's download name.
var contentTypes = map[string]string{
	"text/plain": ".txt", "text/markdown": ".md", "application/json": ".json", "application/pdf": ".pdf",
	"application/zip": ".zip", "application/gzip": ".tar.gz", "application/x-bzip2": ".tar.bz2", "application/octet-stream": ".bin",
}

var attachmentTypes = []string{"", "patch", "exploit-proof-of-concept", "reproducer", "threat-model", "other"}

type Config struct {
	BaseURL         string `yaml:"base_url"`
	SubmissionToken string `yaml:"submission_token"`
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
	u.Path = "/v1/reports"
	return u.String(), nil
}

type Symbol struct {
	File     string `json:"file,omitempty"`
	Function string `json:"function,omitempty"`
	Line     int    `json:"line,omitempty"`
}

type Attachment struct {
	Filename    string `json:"filename"`
	Data        string `json:"data"`
	ContentType string `json:"content_type"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type,omitempty"`
}

type Report struct {
	PURL            string       `json:"purl,omitempty"`
	Software        string       `json:"software,omitempty"`
	Ecosystem       string       `json:"ecosystem,omitempty"`
	Versions        []string     `json:"versions,omitempty"`
	AffectedSymbol  *Symbol      `json:"affected_symbol,omitempty"`
	Attachments     []Attachment `json:"attachments,omitempty"`
	PackageRepoURL  string       `json:"package_repo_url,omitempty"`
	DiscoveryMethod string       `json:"discovery_method,omitempty"`
	Email           string       `json:"email,omitempty"`
	Notify          string       `json:"notify,omitempty"`
}

func checkMetadata(name, value string, limit int) error {
	if !utf8.ValidString(value) || len(value) > limit || strings.ContainsFunc(value, unicode.IsControl) {
		return fmt.Errorf("%s contains invalid characters or exceeds %d bytes", name, limit)
	}
	return nil
}

func (r Report) JSON() ([]byte, error) {
	var purlVersion string
	if r.PURL != "" {
		p, err := purl.Parse(r.PURL)
		if err != nil {
			return nil, fmt.Errorf("purl must be a valid package URL")
		}
		purlVersion = p.Version
	} else if r.Software == "" || r.Ecosystem == "" {
		return nil, fmt.Errorf("a package URL, or both software and an ecosystem, is required")
	}
	symbol := r.AffectedSymbol
	if symbol == nil {
		symbol = &Symbol{}
	}
	for _, f := range []struct {
		name, value string
		limit       int
	}{
		{"purl", r.PURL, 512}, {"software", r.Software, 256}, {"ecosystem", r.Ecosystem, 128},
		{"affected_symbol.file", symbol.File, 512}, {"affected_symbol.function", symbol.Function, 256},
		{"package_repo_url", r.PackageRepoURL, 512}, {"discovery_method", r.DiscoveryMethod, 32}, {"email", r.Email, 256},
	} {
		if err := checkMetadata(f.name, f.value, f.limit); err != nil {
			return nil, err
		}
	}
	if symbol.Line < 0 {
		return nil, fmt.Errorf("affected_symbol.line must not be negative")
	}
	if err := r.checkAttachments(); err != nil {
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

func (r Report) checkAttachments() error {
	if len(r.Attachments) > maxAttachments {
		return fmt.Errorf("at most %d attachments can be sent", maxAttachments)
	}
	downloads := map[string]bool{}
	for i, a := range r.Attachments {
		field := fmt.Sprintf("attachments[%d]", i)
		extension, ok := contentTypes[a.ContentType]
		if !ok {
			return fmt.Errorf("%s.content_type is not an accepted content type", field)
		}
		if a.Filename == "" || a.Filename == "." || a.Filename == ".." || strings.ContainsAny(a.Filename, `/\`) {
			return fmt.Errorf("%s.filename must be a file name, not a path", field)
		}
		if err := checkMetadata(field+".filename", a.Filename, maxFilename); err != nil {
			return err
		}
		if err := checkMetadata(field+".description", a.Description, maxDescription); err != nil {
			return err
		}
		if !slices.Contains(attachmentTypes, a.Type) {
			return fmt.Errorf("%s.type is not an accepted attachment type", field)
		}
		if a.Data == "" || len(a.Data) > MaxPayloadSize {
			return fmt.Errorf("%s.data must be 1 byte to 1 MiB", field)
		}
		if strings.HasPrefix(a.ContentType, "text/") || a.ContentType == "application/json" {
			if !utf8.ValidString(a.Data) {
				return fmt.Errorf("%s.data must be valid UTF-8", field)
			}
		} else if decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(a.Data, "\n", "")); err != nil || len(decoded) == 0 {
			return fmt.Errorf("%s.data must be padded standard base64", field)
		}
		// Intake keeps attachments apart by the name each downloads under.
		download := strings.ToLower(a.Filename)
		if !strings.HasSuffix(download, extension) {
			download += extension
		}
		if downloads[download] {
			return fmt.Errorf("%s.filename downloads under the same name as another attachment", field)
		}
		downloads[download] = true
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
	case e.StatusCode == http.StatusNotFound:
		return "Akrites has no submission with this receipt (HTTP 404)"
	case e.StatusCode == 0:
		return "could not read Akrites submission status"
	}
	return fmt.Sprintf("Akrites returned HTTP %d", e.StatusCode)
}

// Validation reports whether intake refused the report's contents, so the
// analyst can correct it and submit again.
func (e *ResponseError) Validation() bool {
	return e.StatusCode == http.StatusBadRequest || e.StatusCode == http.StatusRequestEntityTooLarge
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
	raw, header, err := c.request(ctx, http.MethodPost, endpoint, body, http.StatusAccepted)
	if err != nil {
		return "", err
	}
	var result struct {
		Receipt string `json:"receipt"`
	}
	if json.Unmarshal(raw, &result) != nil || !receiptRE.MatchString(result.Receipt) {
		result.Receipt = ""
	}
	linked := monitorReceipt(header.Values("Link"), endpoint)
	switch {
	case result.Receipt != "" && linked != "" && result.Receipt != linked:
		return "", &ResponseError{StatusCode: http.StatusAccepted, Ambiguous: true}
	case result.Receipt != "":
		return result.Receipt, nil
	case linked != "":
		return linked, nil
	}
	return "", &ResponseError{StatusCode: http.StatusAccepted, Ambiguous: true}
}

var linkRE = regexp.MustCompile(`<([^>]*)>((?:\s*;\s*[^;,]*)*)`)

// monitorReceipt returns the receipt in a rel="monitor" Link, resolved against
// the submission endpoint, or "" when there is no usable one.
func monitorReceipt(values []string, endpoint string) string {
	base, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	for _, value := range values {
		for _, m := range linkRE.FindAllStringSubmatch(value, -1) {
			if !hasMonitorRel(m[2]) {
				continue
			}
			ref, err := base.Parse(m[1])
			if err != nil || ref.Scheme != base.Scheme || ref.Host != base.Host || ref.RawQuery != "" {
				continue
			}
			if receipt, ok := strings.CutPrefix(ref.Path, "/v1/submissions/"); ok && receiptRE.MatchString(receipt) {
				return receipt
			}
		}
	}
	return ""
}

func hasMonitorRel(params string) bool {
	for param := range strings.SplitSeq(params, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(param), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "rel") {
			continue
		}
		if slices.Contains(strings.Fields(strings.ToLower(strings.Trim(strings.TrimSpace(value), `"`))), "monitor") {
			return true
		}
	}
	return false
}

func (c Client) Poll(ctx context.Context, receipt string) (Status, error) {
	endpoint, err := c.Config.StatusURL(receipt)
	if err != nil {
		return Status{}, err
	}
	raw, _, err := c.request(ctx, http.MethodGet, endpoint, nil, http.StatusOK)
	if err != nil {
		return Status{}, err
	}
	var result Status
	if json.Unmarshal(raw, &result) != nil || result.Receipt != receipt || result.At.IsZero() || !slices.Contains([]string{"queued", "processing", "done"}, result.Status) {
		return Status{}, fmt.Errorf("akrites returned an invalid status response")
	}
	return result, nil
}

func (c Client) request(ctx context.Context, method, endpoint string, body []byte, want int) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.Config.SubmissionToken))
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
		return nil, nil, &ResponseError{Ambiguous: method == http.MethodPost}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != want {
		delay := retryAfter(resp.Header.Get("Retry-After"))
		if resp.StatusCode == http.StatusTooManyRequests {
			delay = max(delay, time.Hour)
		}
		responseErr := &ResponseError{StatusCode: resp.StatusCode, Ambiguous: method == http.MethodPost && (resp.StatusCode < http.StatusBadRequest || (resp.StatusCode >= http.StatusInternalServerError && resp.StatusCode != http.StatusServiceUnavailable)), RetryAfter: delay}
		if responseErr.Validation() {
			responseErr.Problem, responseErr.Violations = readProblem(resp)
		}
		return nil, nil, responseErr
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil || len(raw) > maxResponseSize {
		return nil, nil, &ResponseError{StatusCode: resp.StatusCode, Ambiguous: method == http.MethodPost}
	}
	return raw, resp.Header, nil
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
