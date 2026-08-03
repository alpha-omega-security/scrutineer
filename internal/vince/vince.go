// Package vince submits vulnerability reports to CERT/CC VINCE.
package vince

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/mail"
	"net/textproto"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	DefaultBaseURL    = "https://kb.cert.org"
	MaxAttachmentSize = 10 * 1024 * 1024
	defaultTimeout    = 30 * time.Second
	maxResponseSize   = 1 << 20
)

// Config is the credential-bearing VINCE configuration. APIKey must remain
// in process memory and must not be copied into persisted or rendered data.
type Config struct {
	BaseURL  string   `yaml:"base_url"`
	APIKey   string   `yaml:"api_key"`
	Reporter Reporter `yaml:"reporter"`
}

type Reporter struct {
	Name         string `yaml:"name"`
	Organization string `yaml:"organization"`
	Email        string `yaml:"email"`
	Phone        string `yaml:"phone"`
	PGPKey       string `yaml:"pgp_key"`
}

func (c Config) Enabled() bool {
	return strings.TrimSpace(c.APIKey) != ""
}

func (c Config) baseURL() string {
	if strings.TrimSpace(c.BaseURL) == "" {
		return DefaultBaseURL
	}
	return strings.TrimSpace(c.BaseURL)
}

func (c Config) Endpoint() (string, error) {
	return c.resolvedURL("/vince/comm/api/vulreport/")
}

func (c Config) ReportsURL() (string, error) {
	return c.resolvedURL("/vince/comm/reports/")
}

func (c Config) resolvedURL(path string) (string, error) {
	u, err := url.Parse(c.baseURL())
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("vince base_url must be an absolute HTTP or HTTPS URL")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	loopback := strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
	if u.Scheme != "https" && !loopback {
		return "", fmt.Errorf("vince base_url must use HTTPS unless it points to loopback")
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String(), nil
}

const (
	AnswerUnknown = ""
	AnswerYes     = "True"
	AnswerNo      = "False"
)

// Report mirrors CERTCC/VINCE 3.0.43's vinny.forms.CaseRequestForm at
// fcbfbc732a248972a634e3831ead0108c0494efe. Answers use Django's
// "True"/"False" values so the multipart body matches the form rendered by
// VINCE itself.
type Report struct {
	ContactName              string
	ContactOrganization      string
	ContactEmail             string
	ReporterPGP              string
	ContactPhone             string
	ShareRelease             string
	CreditRelease            string
	CoordinationStatus       []string
	CommunicationAttempt     string
	WhyNoAttempt             string
	PleaseExplain            string
	VendorName               string
	MultipleVendors          string
	OtherVendors             string
	FirstContact             string
	VendorCommunication      string
	ProductName              string
	ProductVersion           string
	ICSImpact                string
	AIMLSystem               string
	VulnerabilityDescription string
	VulnerabilityExploit     string
	VulnerabilityImpact      string
	VulnerabilityDiscovery   string
	VulnerabilityPublic      string
	PublicReferences         string
	VulnerabilityExploited   string
	ExploitReferences        string
	VulnerabilityDisclose    string
	DisclosurePlans          string
	Tracking                 string
	Comments                 string
	CISACoordination         string
}

type Attachment struct {
	Name        string
	ContentType string
	Data        []byte
}

// ValidationErrors is keyed by VINCE form field name so the web preview can
// render failures beside the exact value that needs attention.
type ValidationErrors map[string][]string

func (e ValidationErrors) Error() string {
	return "VINCE report has invalid or unresolved fields"
}

func (e ValidationErrors) add(field, message string) {
	e[field] = append(e[field], message)
}

var phoneRE = regexp.MustCompile(`^[0-9()+.,\- ]*$`)

func (r Report) Validate() error {
	errs := ValidationErrors{}
	requiredText(errs, "product_name", r.ProductName)
	requiredText(errs, "product_version", r.ProductVersion)
	requiredText(errs, "vul_description", r.VulnerabilityDescription)
	requiredText(errs, "vul_exploit", r.VulnerabilityExploit)
	requiredText(errs, "vul_impact", r.VulnerabilityImpact)
	requiredText(errs, "vul_discovery", r.VulnerabilityDiscovery)

	for field, value := range map[string]string{
		"share_release":   r.ShareRelease,
		"credit_release":  r.CreditRelease,
		"comm_attempt":    r.CommunicationAttempt,
		"multiplevendors": r.MultipleVendors,
		"ics_impact":      r.ICSImpact,
		"ai_ml_system":    r.AIMLSystem,
		"vul_public":      r.VulnerabilityPublic,
		"vul_exploited":   r.VulnerabilityExploited,
		"vul_disclose":    r.VulnerabilityDisclose,
		"cisa_please":     r.CISACoordination,
	} {
		validateAnswer(errs, field, value)
	}

	// CaseRequestForm declares wider contact_phone and exploit_references
	// limits than VTCaseRequest's PostgreSQL columns can store.
	lengths := map[string]struct {
		value string
		max   int
	}{
		"contact_name":         {r.ContactName, 100},
		"contact_org":          {r.ContactOrganization, 100},
		"contact_email":        {r.ContactEmail, 254},
		"reporter_pgp":         {r.ReporterPGP, 100000000},
		"contact_phone":        {r.ContactPhone, 20},
		"please_explain":       {r.PleaseExplain, 20000},
		"vendor_name":          {r.VendorName, 100},
		"other_vendors":        {r.OtherVendors, 1000},
		"vendor_communication": {r.VendorCommunication, 20000},
		"product_name":         {r.ProductName, 200},
		"product_version":      {r.ProductVersion, 100},
		"vul_description":      {r.VulnerabilityDescription, 20000},
		"vul_exploit":          {r.VulnerabilityExploit, 20000},
		"vul_impact":           {r.VulnerabilityImpact, 20000},
		"vul_discovery":        {r.VulnerabilityDiscovery, 20000},
		"public_references":    {r.PublicReferences, 1000},
		"exploit_references":   {r.ExploitReferences, 1000},
		"disclosure_plans":     {r.DisclosurePlans, 1000},
		"tracking":             {r.Tracking, 100},
		"comments":             {r.Comments, 1000},
	}
	for field, item := range lengths {
		if len([]rune(item.value)) > item.max {
			errs.add(field, fmt.Sprintf("must be at most %d characters", item.max))
		}
	}

	if r.ContactEmail != "" {
		address, err := mail.ParseAddress(r.ContactEmail)
		if err != nil || address.Address != r.ContactEmail {
			errs.add("contact_email", "must be a valid email address")
		}
	}
	if !phoneRE.MatchString(r.ContactPhone) {
		errs.add("contact_phone", "contains non-telephone characters")
	}
	if r.FirstContact != "" {
		d, err := time.Parse("2006-01-02", r.FirstContact)
		if err != nil {
			errs.add("first_contact", "must use YYYY-MM-DD")
		} else {
			now := time.Now()
			today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
			if d.After(today) {
				errs.add("first_contact", "must not be in the future")
			}
		}
	}
	for _, choice := range r.CoordinationStatus {
		if !slices.Contains([]string{"1", "2", "3", "4", "5"}, choice) {
			errs.add("coord_status", "contains an unknown choice")
			break
		}
	}
	if r.WhyNoAttempt != "" && !slices.Contains([]string{"1", "2", "3"}, r.WhyNoAttempt) {
		errs.add("why_no_attempt", "contains an unknown choice")
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

func requiredText(errs ValidationErrors, field, value string) {
	if strings.TrimSpace(value) == "" {
		errs.add(field, "is required")
	}
}

func validateAnswer(errs ValidationErrors, field, value string) {
	if value != AnswerYes && value != AnswerNo {
		errs.add(field, "choose Yes or No")
	}
}

func (r Report) fields() map[string][]string {
	return map[string][]string{
		"contact_name":         {r.ContactName},
		"contact_org":          {r.ContactOrganization},
		"contact_email":        {r.ContactEmail},
		"reporter_pgp":         {r.ReporterPGP},
		"contact_phone":        {r.ContactPhone},
		"share_release":        {r.ShareRelease},
		"credit_release":       {r.CreditRelease},
		"coord_status":         r.CoordinationStatus,
		"comm_attempt":         {r.CommunicationAttempt},
		"why_no_attempt":       {r.WhyNoAttempt},
		"please_explain":       {r.PleaseExplain},
		"vendor_name":          {r.VendorName},
		"multiplevendors":      {r.MultipleVendors},
		"other_vendors":        {r.OtherVendors},
		"first_contact":        {r.FirstContact},
		"vendor_communication": {r.VendorCommunication},
		"product_name":         {r.ProductName},
		"product_version":      {r.ProductVersion},
		"ics_impact":           {r.ICSImpact},
		"ai_ml_system":         {r.AIMLSystem},
		"vul_description":      {r.VulnerabilityDescription},
		"vul_exploit":          {r.VulnerabilityExploit},
		"vul_impact":           {r.VulnerabilityImpact},
		"vul_discovery":        {r.VulnerabilityDiscovery},
		"vul_public":           {r.VulnerabilityPublic},
		"public_references":    {r.PublicReferences},
		"vul_exploited":        {r.VulnerabilityExploited},
		"exploit_references":   {r.ExploitReferences},
		"vul_disclose":         {r.VulnerabilityDisclose},
		"disclosure_plans":     {r.DisclosurePlans},
		"tracking":             {r.Tracking},
		"comments":             {r.Comments},
		"cisa_please":          {r.CISACoordination},
	}
}

type ErrorKind string

const (
	ErrorValidation ErrorKind = "validation"
	ErrorAuth       ErrorKind = "auth"
	ErrorRateLimit  ErrorKind = "rate_limit"
	ErrorAmbiguous  ErrorKind = "ambiguous"
	ErrorResponse   ErrorKind = "response"
)

type SubmitError struct {
	Kind        ErrorKind
	StatusCode  int
	FieldErrors ValidationErrors
	Message     string
}

func (e *SubmitError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "VINCE submission failed"
}

func (e *SubmitError) Unwrap() error {
	if len(e.FieldErrors) > 0 {
		return e.FieldErrors
	}
	return nil
}

type Client struct {
	Config     Config
	HTTPClient *http.Client
}

// Submit sends exactly one request. It deliberately has no retry path because
// VINCE does not expose an idempotency key or a pending-report lookup.
func (c Client) Submit(ctx context.Context, report Report, attachment *Attachment) (string, error) {
	if err := report.Validate(); err != nil {
		return "", &SubmitError{Kind: ErrorValidation, FieldErrors: err.(ValidationErrors), Message: err.Error()}
	}
	if attachment != nil && len(attachment.Data) > MaxAttachmentSize {
		errs := ValidationErrors{"user_file": {
			fmt.Sprintf("must be at most %d bytes", MaxAttachmentSize),
		}}
		return "", &SubmitError{Kind: ErrorValidation, FieldErrors: errs, Message: errs.Error()}
	}
	if !c.Config.Enabled() {
		return "", &SubmitError{Kind: ErrorAuth, Message: "VINCE API key is not configured"}
	}
	endpoint, err := c.Config.Endpoint()
	if err != nil {
		return "", &SubmitError{Kind: ErrorValidation, Message: err.Error()}
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for field, values := range report.fields() {
		for _, value := range values {
			if err := writer.WriteField(field, value); err != nil {
				return "", fmt.Errorf("write VINCE field %s: %w", field, err)
			}
		}
	}
	if attachment != nil {
		header := textproto.MIMEHeader{}
		header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="user_file"; filename="%s"`,
			escapeQuotes(attachment.Name)))
		contentType := attachment.ContentType
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		header.Set("Content-Type", contentType)
		part, err := writer.CreatePart(header)
		if err != nil {
			return "", fmt.Errorf("create VINCE attachment: %w", err)
		}
		if _, err := part.Write(attachment.Data); err != nil {
			return "", fmt.Errorf("write VINCE attachment: %w", err)
		}
	}
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("finish VINCE request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &body)
	if err != nil {
		return "", fmt.Errorf("create VINCE request: %w", err)
	}
	req.Header.Set("Authorization", "Token "+strings.TrimSpace(c.Config.APIKey))
	req.Header.Set("Content-Type", writer.FormDataContentType())

	httpClient := &http.Client{}
	if c.HTTPClient != nil {
		*httpClient = *c.HTTPClient
	}
	if httpClient.Timeout == 0 {
		httpClient.Timeout = defaultTimeout
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", &SubmitError{
			Kind:    ErrorAmbiguous,
			Message: "VINCE did not return a response; the report may have been accepted",
		}
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if readErr != nil {
		return "", &SubmitError{
			Kind:       ErrorAmbiguous,
			StatusCode: resp.StatusCode,
			Message:    "VINCE returned an unreadable response; the report may have been accepted",
		}
	}

	switch resp.StatusCode {
	case http.StatusCreated:
		var result struct {
			VRFID string `json:"vrf_id"`
		}
		if err := json.Unmarshal(raw, &result); err != nil || strings.TrimSpace(result.VRFID) == "" {
			return "", &SubmitError{
				Kind:       ErrorAmbiguous,
				StatusCode: resp.StatusCode,
				Message:    "VINCE accepted the request but did not return a VRF ID",
			}
		}
		return strings.TrimSpace(result.VRFID), nil
	case http.StatusBadRequest:
		var result struct {
			Errors ValidationErrors `json:"errors"`
		}
		_ = json.Unmarshal(raw, &result)
		return "", &SubmitError{
			Kind:        ErrorValidation,
			StatusCode:  resp.StatusCode,
			FieldErrors: result.Errors,
			Message:     "VINCE rejected one or more report fields",
		}
	case http.StatusUnauthorized, http.StatusForbidden:
		return "", &SubmitError{
			Kind:       ErrorAuth,
			StatusCode: resp.StatusCode,
			Message:    "VINCE rejected the configured API key",
		}
	case http.StatusTooManyRequests:
		return "", &SubmitError{
			Kind:       ErrorRateLimit,
			StatusCode: resp.StatusCode,
			Message:    "VINCE rate limited the submission",
		}
	default:
		if resp.StatusCode >= http.StatusInternalServerError {
			return "", &SubmitError{
				Kind:       ErrorAmbiguous,
				StatusCode: resp.StatusCode,
				Message:    "VINCE returned a server error; the report may have been accepted",
			}
		}
		return "", &SubmitError{
			Kind:       ErrorResponse,
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("VINCE returned HTTP %d", resp.StatusCode),
		}
	}
}

func escapeQuotes(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\r", "", "\n", "").Replace(s)
}

func AsSubmitError(err error) (*SubmitError, bool) {
	var target *SubmitError
	ok := errors.As(err, &target)
	return target, ok
}
